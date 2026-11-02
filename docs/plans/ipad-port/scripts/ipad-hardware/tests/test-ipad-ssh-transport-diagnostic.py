#!/usr/bin/env python3
"""Hermetic tests for the no-session SSH transport diagnostic."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
DIAGNOSTIC = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/diagnose-ipad-ssh-transport.py"
IDENTITY = b"fixture-identity\n"
KNOWN_HOSTS = b"fixture-known-hosts\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def replace_constant(source: str, name: str, value: str) -> str:
    updated, count = re.subn(
        rf"^{name} = .+$", f"{name} = {value}", source, flags=re.MULTILINE
    )
    assert count == 1, name
    return updated


def fake_ssh_source(scenario: str, contacts: Path, child_pid: Path) -> str:
    messages = {
        "authenticated": b'debug1: Authenticated to 127.0.0.1 using "publickey".\n',
        "permission": b"mobile@127.0.0.1: Permission denied (publickey).\n",
        "host-key": b"Host key verification failed.\n",
        "reset": b"kex_exchange_identification: read: Connection reset by peer\n",
        "banner-spoof": b'debug1: Authenticated to 127.0.0.1 using "publickey".\nPermission denied (publickey).\n',
        "unknown": b"some unrecognized diagnostic\n",
    }
    message = messages.get(scenario, b"")
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import pathlib
        import socket
        import subprocess
        import sys
        import time

        scenario = {scenario!r}
        arguments = sys.argv[1:]
        required = {{"SessionType=none", "ControlMaster=yes", "ControlPersist=no", "ClearAllForwardings=yes", "GlobalKnownHostsFile=/dev/null", "KnownHostsCommand=none", "UpdateHostKeys=no"}}
        options = {{arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == "-o"}}
        if "-N" not in arguments or "-T" not in arguments or "-M" not in arguments or "-S" not in arguments or not required.issubset(options):
            raise SystemExit(96)
        with pathlib.Path({str(contacts)!r}).open("a", encoding="ascii") as stream:
            stream.write("contact\\n")
        if scenario in ("hang", "signal"):
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding="ascii")
            time.sleep(60)
        sys.stderr.buffer.write({message!r})
        sys.stderr.buffer.flush()
        if scenario == "authenticated":
            control_path = arguments[arguments.index("-S") + 1]
            control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            control.bind(control_path)
            control.listen(1)
            time.sleep(60)
        raise SystemExit(255)
        """
    )


def prepare(root: Path, scenario: str) -> dict[str, Path]:
    repo = root / "repo"
    diagnostic = repo / "docs/plans/ipad-port/scripts/ipad-hardware/diagnose-ipad-ssh-transport.py"
    identity = root / "identity"
    known_hosts = root / "known-hosts"
    fake_ssh = root / "ssh"
    contacts = root / "contacts"
    child_pid = root / "child-pid"
    write(identity, IDENTITY, 0o600)
    write(known_hosts, KNOWN_HOSTS, 0o600)
    write(fake_ssh, fake_ssh_source(scenario, contacts, child_pid).encode(), 0o555)
    source = DIAGNOSTIC.read_text(encoding="utf-8")
    source = replace_constant(source, "SSH", f"Path({str(fake_ssh)!r})")
    source = replace_constant(source, "IDENTITY_FILE", f"Path({str(identity)!r})")
    source = replace_constant(source, "KNOWN_HOSTS_FILE", f"Path({str(known_hosts)!r})")
    source = replace_constant(source, "EXPECTED_IDENTITY_SHA", repr(digest(IDENTITY)))
    source = replace_constant(source, "EXPECTED_KNOWN_HOSTS_SHA", repr(digest(KNOWN_HOSTS)))
    source = replace_constant(source, "DEADLINE_SECONDS", "0.4")
    source = replace_constant(source, "TERMINATE_GRACE", "0.2")
    write(diagnostic, source.encode(), 0o555)
    return {
        "diagnostic": diagnostic,
        "identity": identity,
        "contacts": contacts,
        "child_pid": child_pid,
    }


def run_once(paths: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(paths["diagnostic"])],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=4,
        check=False,
    )


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_authenticated_and_fixed_failures() -> None:
    expected = {
        "authenticated": (0, "authenticated-no-session-method-unverified"),
        "permission": (65, "public-key-rejected"),
        "host-key": (65, "host-key-rejected"),
        "reset": (65, "connection-reset"),
        "banner-spoof": (65, "public-key-rejected"),
        "unknown": (65, "unclassified-failure"),
    }
    for scenario, (status, category) in expected.items():
        with tempfile.TemporaryDirectory(prefix="mac2jb-ssh-diagnostic-test-") as directory:
            paths = prepare(Path(directory), scenario)
            result = run_once(paths)
            assert result.returncode == status, (scenario, result.stderr)
            assert result.stdout == f"SSH_TRANSPORT {category}\n"
            assert "fixture" not in result.stdout + result.stderr


def test_digest_drift_stops_before_contact() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-ssh-diagnostic-test-") as directory:
        paths = prepare(Path(directory), "authenticated")
        paths["identity"].write_bytes(b"drift")
        paths["identity"].chmod(0o600)
        result = run_once(paths)
        assert result.returncode == 65
        assert not paths["contacts"].exists()


def test_timeout_kills_descendant() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-ssh-diagnostic-test-") as directory:
        paths = prepare(Path(directory), "hang")
        result = run_once(paths)
        assert result.returncode == 65
        pid = int(paths["child_pid"].read_text(encoding="ascii"))
        time.sleep(0.05)
        assert not process_exists(pid)


def test_signals_kill_descendants() -> None:
    for handled in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        with tempfile.TemporaryDirectory(prefix="mac2jb-ssh-diagnostic-test-") as directory:
            paths = prepare(Path(directory), "signal")
            process = subprocess.Popen(
                [sys.executable, str(paths["diagnostic"])],
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


def main() -> None:
    test_authenticated_and_fixed_failures()
    test_digest_drift_stops_before_contact()
    test_timeout_kills_descendant()
    test_signals_kill_descendants()
    print("PASS iPad SSH no-session diagnostic tests (4 groups / 11 scenarios)")


if __name__ == "__main__":
    main()
