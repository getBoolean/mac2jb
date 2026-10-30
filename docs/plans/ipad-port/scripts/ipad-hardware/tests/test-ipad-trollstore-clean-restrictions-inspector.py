#!/usr/bin/env python3
"""Hermetic transport/parser tests for the cleanRestrictions inspector."""

from __future__ import annotations

from io import BytesIO
import hashlib
import os
from pathlib import Path
import plistlib
import re
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
INSPECTOR = ROOT / "scripts/ipad-hardware/inspect-trollstore-clean-restrictions-over-ssh.py"
PAYLOAD = b"#!/bin/sh\nexit 0\n"
IDENTITY = b"fixture-identity\n"
KNOWN_HOSTS = b"fixture-known-hosts\n"
MEMBER = "private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes, mode: int = 0o400) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def archive_bytes(plist: bytes, *, duplicate: bool = False, symlink: bool = False) -> bytes:
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        count = 2 if duplicate else 1
        for _index in range(count):
            member = tarfile.TarInfo(MEMBER)
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "/private/etc/passwd"
                member.size = 0
                archive.addfile(member)
            else:
                member.size = len(plist)
                archive.addfile(member, BytesIO(plist))
    return stream.getvalue()


def plist_for(scenario: str) -> bytes:
    if scenario == "missing-field":
        document: object = {}
    else:
        if scenario == "nonempty":
            values: object = ["private.example", "private.other"]
        elif scenario == "null-value":
            values = None
        else:
            values = []
        document = {
            "com.apple.lsd.appremoval": {
                "clientRestrictions": {
                    "union": {"removedSystemAppBundleIDs": {"values": values}}
                }
            }
        }
    return plistlib.dumps(document, fmt=plistlib.FMT_BINARY, sort_keys=True)


def malformed_bplist(scenario: str) -> bytes:
    if scenario == "bplist-unreachable":
        objects = b"\xd0\xd0"
        return b"bplist00" + objects + b"\x08\x09" + struct.pack(
            ">6xBBQQQ", 1, 1, 2, 0, 10
        )
    if scenario == "bplist-overlap":
        objects = b"\x52ab"
        return b"bplist00" + objects + b"\x08\x09" + struct.pack(
            ">6xBBQQQ", 1, 1, 2, 0, 11
        )
    if scenario == "bplist-cycle":
        return b"bplist00\xa1\x00\x08" + struct.pack(
            ">6xBBQQQ", 1, 1, 1, 0, 10
        )
    raise AssertionError(scenario)


def fake_ssh_source(scenario: str, contacts: Path, payload_sha: str, child_pid: Path) -> str:
    if scenario == "absent":
        output = b"ABSENT\n"
    elif scenario == "malformed-plist":
        output = b"ARCHIVE\n" + archive_bytes(b"not a plist")
    elif scenario == "duplicate-member":
        output = b"ARCHIVE\n" + archive_bytes(plist_for("empty"), duplicate=True)
    elif scenario == "symlink-member":
        output = b"ARCHIVE\n" + archive_bytes(plist_for("empty"), symlink=True)
    elif scenario == "oversize":
        output = b"x" * (2 * 1024 * 1024 + 1)
    elif scenario.startswith("bplist-"):
        output = b"ARCHIVE\n" + archive_bytes(malformed_bplist(scenario))
    else:
        output = b"ARCHIVE\n" + archive_bytes(plist_for(scenario))
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import hashlib
        import os
        import pathlib
        import subprocess
        import sys
        import time

        scenario = {scenario!r}
        contacts = pathlib.Path({str(contacts)!r})
        required_options = {{
            "GlobalKnownHostsFile=/dev/null",
            "KnownHostsCommand=none",
            "UpdateHostKeys=no",
        }}
        observed_options = {{
            sys.argv[index + 1]
            for index, argument in enumerate(sys.argv[:-1])
            if argument == "-o"
        }}
        if not required_options.issubset(observed_options):
            raise SystemExit(96)
        data = sys.stdin.buffer.read()
        with contacts.open("a", encoding="ascii") as stream:
            stream.write("contact\\n")
        if hashlib.sha256(data).hexdigest() != {payload_sha!r}:
            raise SystemExit(97)
        if scenario in ("hang", "signal"):
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding="ascii")
            time.sleep(60)
        if scenario == "ssh-fail":
            raise SystemExit(255)
        if scenario == "payload-inaccessible":
            raise SystemExit(66)
        sys.stdout.buffer.write({output!r})
        """
    )


def replace_constant(source: str, name: str, value: str) -> str:
    updated, count = re.subn(
        rf"^{name} = .+$",
        f"{name} = {value}",
        source,
        flags=re.MULTILINE,
    )
    assert count == 1, name
    return updated


def prepare(root: Path, scenario: str) -> dict[str, Path]:
    repo = root / "repo"
    inspector = repo / "scripts/ipad-hardware/inspect-trollstore-clean-restrictions-over-ssh.py"
    payload = repo / "scripts/ipad-hardware/device/u1-readonly-trollstore-clean-restrictions-input.sh"
    identity = root / "identity"
    known_hosts = root / "known-hosts"
    contacts = root / "contacts"
    child_pid = root / "child-pid"
    fake_ssh = root / "ssh"
    write(payload, PAYLOAD, 0o444)
    write(identity, IDENTITY, 0o600)
    write(known_hosts, KNOWN_HOSTS, 0o600)
    write(
        fake_ssh,
        fake_ssh_source(scenario, contacts, digest(PAYLOAD), child_pid).encode(),
        0o555,
    )
    source = INSPECTOR.read_text(encoding="utf-8")
    source = replace_constant(source, "SSH", f"Path({str(fake_ssh)!r})")
    source = replace_constant(source, "IDENTITY_FILE", f"Path({str(identity)!r})")
    source = replace_constant(source, "KNOWN_HOSTS_FILE", f"Path({str(known_hosts)!r})")
    source = replace_constant(source, "EXPECTED_PAYLOAD_SHA", repr(digest(PAYLOAD)))
    source = replace_constant(source, "EXPECTED_IDENTITY_SHA", repr(digest(IDENTITY)))
    source = replace_constant(source, "EXPECTED_KNOWN_HOSTS_SHA", repr(digest(KNOWN_HOSTS)))
    source = replace_constant(source, "SSH_TIMEOUT", "0.4")
    source = replace_constant(source, "TERMINATE_GRACE", "0.2")
    write(inspector, source.encode(), 0o555)
    return {
        "inspector": inspector,
        "payload": payload,
        "contacts": contacts,
        "child_pid": child_pid,
    }


def run_once(paths: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(paths["inspector"])],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=4,
        check=False,
    )


def contacts(path: Path) -> int:
    if not path.exists():
        return 0
    return len(path.read_text(encoding="ascii").splitlines())


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_noop_states_pass_without_values() -> None:
    for scenario in ("absent", "missing-field", "empty"):
        with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
            paths = prepare(Path(directory), scenario)
            result = run_once(paths)
            assert result.returncode == 0, (scenario, result.stderr)
            assert result.stdout.startswith("PASS cleanRestrictions snapshot is no-op:")
            assert "not install authorization" in result.stdout
            assert "private." not in result.stdout + result.stderr
            assert contacts(paths["contacts"]) == 1


def test_nonempty_state_blocks_without_leaking_values() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
        paths = prepare(Path(directory), "nonempty")
        result = run_once(paths)
        assert result.returncode == 78
        assert result.stdout == ""
        assert "2 entries" in result.stderr
        assert "private.example" not in result.stderr


def test_hostile_archives_and_transport_reject() -> None:
    for scenario in (
        "malformed-plist",
        "duplicate-member",
        "symlink-member",
        "null-value",
        "bplist-unreachable",
        "bplist-overlap",
        "bplist-cycle",
        "oversize",
        "ssh-fail",
        "payload-inaccessible",
    ):
        with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
            paths = prepare(Path(directory), scenario)
            result = run_once(paths)
            assert result.returncode not in (0, 78), scenario
            assert result.stdout == "", scenario
            if scenario == "ssh-fail":
                assert "capture-category=ssh-transport-failed" in result.stderr
            if scenario == "payload-inaccessible":
                assert "capture-category=device-input-inaccessible" in result.stderr


def test_payload_drift_stops_before_contact() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
        paths = prepare(Path(directory), "empty")
        paths["payload"].chmod(0o600)
        paths["payload"].write_bytes(b"drift")
        paths["payload"].chmod(0o400)
        result = run_once(paths)
        assert result.returncode != 0
        assert contacts(paths["contacts"]) == 0


def test_timeout_and_signal_kill_descendants() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
        paths = prepare(Path(directory), "hang")
        result = run_once(paths)
        assert result.returncode != 0
        pid = int(paths["child_pid"].read_text(encoding="ascii"))
        time.sleep(0.05)
        assert not process_exists(pid)

    for handled in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
            paths = prepare(Path(directory), "signal")
            process = subprocess.Popen(
                [sys.executable, str(paths["inspector"])],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = time.monotonic() + 2
            while not paths["child_pid"].exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert paths["child_pid"].exists()
            pid = int(paths["child_pid"].read_text(encoding="ascii"))
            os.kill(process.pid, handled)
            process.wait(timeout=3)
            assert process.returncode == 128 + handled
            time.sleep(0.05)
            assert not process_exists(pid)


def test_post_transport_signal_cannot_pass() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-inspector-test-") as directory:
        paths = prepare(Path(directory), "absent")
        source = paths["inspector"].read_text(encoding="utf-8")
        original = "captured = capture(staged_payload, staged_identity, staged_known_hosts)\n        check_signal()"
        replacement = (
            "captured = capture(staged_payload, staged_identity, staged_known_hosts)\n"
            "        signal_handler(signal.SIGTERM, None)\n"
            "        check_signal()"
        )
        assert source.count(original) == 1
        paths["inspector"].chmod(0o600)
        paths["inspector"].write_text(source.replace(original, replacement), encoding="utf-8")
        paths["inspector"].chmod(0o555)
        result = run_once(paths)
        assert result.returncode == 128 + signal.SIGTERM
        assert result.stdout == ""


def main() -> None:
    test_noop_states_pass_without_values()
    test_nonempty_state_blocks_without_leaking_values()
    test_hostile_archives_and_transport_reject()
    test_payload_drift_stops_before_contact()
    test_timeout_and_signal_kill_descendants()
    test_post_transport_signal_cannot_pass()
    print("PASS TrollStore cleanRestrictions inspector tests (6 groups / 20 scenarios)")


if __name__ == "__main__":
    main()
