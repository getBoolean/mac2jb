#!/usr/bin/env python3
"""Hermetic tests for the read-only plist archive payload and SSH collector."""

from __future__ import annotations

import base64
from io import BytesIO
import hashlib
import os
from pathlib import Path
import plistlib
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-app-plist-archive.sh"
RUNNER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/collect-app-versions-over-ssh.sh"
EXPECTED = (
    "dopamine-app: version=2.4.5 build=1 bundle-family=standard\n"
    "trollstore-app: version=2.1.0 build=210 bundle-family=stealth\n"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def add_plist(path: Path, bundle: str, version: object = "2.4.5", build: object = "1") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": bundle,
                "CFBundleShortVersionString": version,
                "CFBundleVersion": build,
            },
            fmt=plistlib.FMT_BINARY,
        )
    )


def test_missing_sentinel_distinguishes_explicit_null() -> None:
    missing = object()
    absent = plistlib.loads(plistlib.dumps({}, fmt=plistlib.FMT_BINARY))
    explicit_null = plistlib.loads(
        b"bplist00\xd1\x01\x02_\x10\x1aCFBundleShortVersionString\x00"
        b"\x08\x0b(\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)"
    )
    expect(absent.get("CFBundleShortVersionString", missing) is missing, "absent key lost sentinel")
    expect(
        "CFBundleShortVersionString" in explicit_null
        and explicit_null.get("CFBundleShortVersionString", missing) is None,
        "explicit null was not preserved",
    )


def prepare_payload(root: Path, scenario: str) -> tuple[Path, list[Path]]:
    containers = root / "containers"
    applications = root / "applications"
    jb_applications = root / "jb-applications"
    for path in (containers, applications, jb_applications):
        path.mkdir()
    if scenario not in ("absent", "scan-cap", "symlink", "zero"):
        add_plist(
            containers / "UUID" / "Dopamine.app" / "Info.plist",
            "com.opa334.Dopamine",
        )
        add_plist(
            applications / "TrollStore.app" / "Info.plist",
            "com.opa334.TrollStore.TS_0123456789ABCDEF",
            "2.1.0",
            "210",
        )
    if scenario != "zero":
        add_plist(jb_applications / "TrollStoreHelper.app" / "Info.plist", "example.unrelated")
    if scenario == "scan-cap":
        for index in range(65):
            add_plist(applications / f"TrollStoreExtra{index:03d}.app" / "Info.plist", f"example.{index}")
    if scenario == "symlink":
        target = root / "external.plist"
        add_plist(target, "com.opa334.Dopamine")
        app = applications / "TrollStoreSymlink.app"
        app.mkdir()
        (app / "Info.plist").symlink_to(target)

    fake_timeout = root / "timeout"
    write_executable(
        fake_timeout,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            import sys

            scenario = {scenario!r}
            arguments = sys.argv[1:]
            if len(arguments) < 4 or arguments[:2] != ["-k", "1"]:
                raise SystemExit(98)
            command = arguments[3]
            if command.endswith("/sleep"):
                raise SystemExit(0 if scenario == "timeout-canary-fail" else 124)
            if scenario == "timeout-tar-124":
                raise SystemExit(124)
            if scenario == "timeout-tar-137":
                raise SystemExit(137)
            os.execv(command, arguments[3:])
            """
        ),
    )

    source = PAYLOAD.read_text(encoding="utf-8")
    old_candidates = (
        "for candidate in \\\n"
        "  /var/jb/usr/bin/bsdtar \\\n"
        "  /var/jb/usr/bin/tar \\\n"
        "  /var/jb/bin/tar \\\n"
        "  /usr/bin/tar \\\n"
        "  /bin/tar\n"
        "do"
    )
    source = source.replace(old_candidates, "for candidate in /usr/bin/bsdtar\ndo")
    old_timeout_candidates = (
        "for candidate in \\\n"
        "  /var/jb/usr/bin/timeout \\\n"
        "  /var/jb/bin/timeout \\\n"
        "  /usr/bin/timeout \\\n"
        "  /bin/timeout \\\n"
        "  /var/jb/usr/bin/gtimeout \\\n"
        "  /var/jb/bin/gtimeout \\\n"
        "  /usr/bin/gtimeout \\\n"
        "  /bin/gtimeout\n"
        "do"
    )
    source = source.replace(old_timeout_candidates, f"for candidate in '{fake_timeout}'\ndo")
    old_roots = (
        "  /var/containers/Bundle/Application \\\n"
        "  /Applications \\\n"
        "  /var/jb/Applications"
    )
    new_roots = f"  '{containers}' \\\n  '{applications}' \\\n  '{jb_applications}'"
    old_globs = (
        "  /var/containers/Bundle/Application/*/Dopamine*.app/Info.plist \\\n"
        "  /var/containers/Bundle/Application/*/TrollStore*.app/Info.plist \\\n"
        "  /Applications/Dopamine*.app/Info.plist \\\n"
        "  /Applications/TrollStore*.app/Info.plist \\\n"
        "  /var/jb/Applications/Dopamine*.app/Info.plist \\\n"
        "  /var/jb/Applications/TrollStore*.app/Info.plist"
    )
    new_globs = (
        f"  '{containers}'/*/Dopamine*.app/Info.plist \\\n"
        f"  '{containers}'/*/TrollStore*.app/Info.plist \\\n"
        f"  '{applications}'/Dopamine*.app/Info.plist \\\n"
        f"  '{applications}'/TrollStore*.app/Info.plist \\\n"
        f"  '{jb_applications}'/Dopamine*.app/Info.plist \\\n"
        f"  '{jb_applications}'/TrollStore*.app/Info.plist"
    )
    source = source.replace(old_roots, new_roots).replace(old_globs, new_globs)
    payload = root / "payload.sh"
    write_executable(payload, source)
    evidence = sorted(containers.rglob("Info.plist")) + sorted(applications.rglob("Info.plist"))
    evidence += sorted(jb_applications.rglob("Info.plist"))
    return payload, evidence


def execute_payload(scenario: str) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-plist-payload-test.") as temporary:
        root = Path(temporary)
        payload, evidence = prepare_payload(root, scenario)
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in evidence}
        result = subprocess.run(
            ["/bin/sh", str(payload)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        after = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in evidence}
        if after != before:
            raise AssertionError(f"{scenario} changed fixture contents or mtimes")
        return result


def binary_string(value: str) -> bytes:
    encoded = value.encode("ascii")
    if len(encoded) < 15:
        return bytes([0x50 | len(encoded)]) + encoded
    if len(encoded) > 255:
        raise ValueError("fixture string is too long")
    return b"\x5f\x10" + bytes([len(encoded)]) + encoded


def duplicate_binary_plist() -> bytes:
    objects = [
        b"\xd4" + bytes([1, 1, 2, 3, 4, 5, 6, 7]),
        binary_string("CFBundleIdentifier"),
        binary_string("CFBundleShortVersionString"),
        binary_string("CFBundleVersion"),
        binary_string("com.opa334.Dopamine"),
        binary_string("com.opa334.TrollStore"),
        binary_string("2.4.5"),
        binary_string("1"),
    ]
    data = bytearray(b"bplist00")
    offsets = []
    for item in objects:
        offsets.append(len(data))
        data.extend(item)
    table_offset = len(data)
    data.extend(bytes(offsets))
    data.extend(struct.pack(">6xBBQQQ", 1, 1, len(objects), 0, table_offset))
    return bytes(data)


def overlapping_binary_plist() -> bytes:
    objects = [
        b"\xd4" + bytes([1, 2, 3, 4, 5, 6, 7, 8]),
        binary_string("CFBundleIdentifier"),
        binary_string("CFBundleShortVersionString"),
        binary_string("CFBundleVersion"),
        binary_string("Bomb"),
        binary_string("com.opa334.Dopamine"),
        binary_string("2.4.5"),
        binary_string("1"),
        b"\xa2" + bytes([9, 10]),
        b"\x4f\x10\x14" + (b"A" * 20),
    ]
    data = bytearray(b"bplist00")
    offsets = []
    for item in objects:
        offsets.append(len(data))
        data.extend(item)
    offsets.append(offsets[9] + 1)
    table_offset = len(data)
    data.extend(bytes(offsets))
    data.extend(struct.pack(">6xBBQQQ", 1, 1, len(offsets), 0, table_offset))
    return bytes(data)


def duplicate_xml_plist() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.opa334.TrollStore</string>
<key>CFBundleIdentifier</key><string>com.opa334.Dopamine</string>
<key>CFBundleShortVersionString</key><string>2.4.5</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>"""


def make_archive(scenario: str) -> bytes:
    entries: list[tuple[str, bytes, bytes | None]] = []
    if scenario != "absent":
        dopamine_values = {
            "CFBundleIdentifier": "com.opa334.Dopamine",
            "CFBundleShortVersionString": 245 if scenario == "non-string" else "2.4.5",
            "CFBundleVersion": "1",
        }
        if scenario == "dopamine-missing-version":
            dopamine_values.pop("CFBundleShortVersionString")
        dopamine = plistlib.dumps(dopamine_values, fmt=plistlib.FMT_BINARY)
        if scenario == "duplicate-binary-key":
            dopamine = duplicate_binary_plist()
        if scenario == "duplicate-xml-key":
            dopamine = duplicate_xml_plist()
        if scenario == "huge-binary-object-count":
            dopamine = b"bplist00" + struct.pack(">6xBBQQQ", 1, 1, 2**63, 0, 8)
        if scenario == "overlapping-binary-objects":
            dopamine = overlapping_binary_plist()
        trollstore_values = {
            "CFBundleIdentifier": "com.opa334.TrollStore.TS_0123456789ABCDEF",
            "CFBundleShortVersionString": "2.1.0",
            "CFBundleVersion": "210",
        }
        if scenario == "trollstore-missing-version":
            trollstore_values.pop("CFBundleShortVersionString")
        if scenario == "trollstore-null-version":
            trollstore_values["CFBundleShortVersionString"] = None
        trollstore = plistlib.dumps(
            trollstore_values,
            fmt=plistlib.FMT_BINARY if scenario == "trollstore-null-version" else plistlib.FMT_XML,
        )
        entries.extend(
            [
                ("var/containers/Bundle/Application/UUID/Dopamine.app/Info.plist", dopamine, None),
                ("Applications/TrollStore.app/Info.plist", trollstore, None),
            ]
        )
    if scenario == "duplicate":
        entries.append(
            (
                "var/jb/Applications/DopamineOther.app/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.opa334.Dopamine",
                        "CFBundleShortVersionString": "9.9.9",
                        "CFBundleVersion": "2",
                    }
                ),
                None,
            )
        )
    if scenario == "invalid-path":
        entries = [("etc/passwd", b"not a plist", None)]
    if scenario == "malformed":
        entries = [("Applications/DopamineBad.app/Info.plist", b"not a plist", None)]
    if scenario == "symlink-member":
        entries = [("Applications/TrollStoreBad.app/Info.plist", b"", b"/private/target")]
    if scenario == "gnu-longname":
        entries = [
            (
                "Applications/TrollStore" + ("A" * 100) + ".app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": "example.longname"}),
                None,
            )
        ]

    stream = BytesIO()
    archive_format = tarfile.GNU_FORMAT if scenario == "gnu-longname" else tarfile.USTAR_FORMAT
    with tarfile.open(fileobj=stream, mode="w", format=archive_format) as archive:
        for name, content, link_target in entries:
            member = tarfile.TarInfo(name)
            member.uid = member.gid = 0
            member.mtime = 0
            if link_target is not None:
                member.type = tarfile.SYMTYPE
                member.linkname = link_target.decode("ascii")
                member.size = 0
                archive.addfile(member)
            else:
                member.mode = 0o444
                member.size = len(content)
                archive.addfile(member, BytesIO(content))
    data = stream.getvalue()
    if scenario == "trailing-junk":
        data += b"x"
    if scenario in ("aligned-junk", "zero-then-junk"):
        if scenario == "zero-then-junk":
            data = make_archive("absent")
        mutable = bytearray(data)
        for offset in range(0, len(mutable) - 1024, 512):
            if mutable[offset:offset + 1024] == bytes(1024):
                mutable[offset + 1024:offset + 1536] = b"J" * 512
                break
        else:
            raise AssertionError("fixture archive had no end marker")
        data = bytes(mutable)
    return data


def prepare_runner(root: Path, scenario: str) -> Path:
    payload_directory = root / "device"
    payload_directory.mkdir()
    staged_payload = payload_directory / PAYLOAD.name
    staged_payload.write_bytes(PAYLOAD.read_bytes())
    staged_payload.chmod(0o555)
    identity = root / "identity"
    known_hosts = root / "known-hosts"
    identity.write_text("fixture identity\n", encoding="ascii")
    known_hosts.write_text("fixture host\n", encoding="ascii")
    identity.chmod(0o600)
    known_hosts.chmod(0o600)

    archive = b"" if scenario in ("hang", "oversized") else make_archive(scenario)
    encoded = base64.b64encode(archive).decode("ascii")
    fake_ssh = root / "ssh"
    write_executable(
        fake_ssh,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import base64
            import os
            import pathlib
            import sys
            import time

            scenario = {scenario!r}
            root = pathlib.Path({str(root)!r})
            arguments = sys.argv[1:]
            for required in ("ServerAliveInterval=5", "ServerAliveCountMax=2"):
                if required not in arguments:
                    raise SystemExit(64)
            remote = sys.argv[-1]
            for required in ('[ ! -L "$candidate" ]', '[ ! -w "$candidate" ]', '[ ! -L "$shell_candidate" ]'):
                if required not in remote:
                    raise SystemExit(64)
            sys.stdin.buffer.read()
            if scenario == "hang":
                (root / "child-pid").write_text(str(os.getpid()), encoding="ascii")
                time.sleep(30)
            if scenario == "oversized":
                sys.stdout.buffer.write(bytes(9 * 1024 * 1024))
            else:
                sys.stdout.buffer.write(base64.b64decode({encoded!r}))
            """
        ),
    )

    source = RUNNER.read_text(encoding="utf-8")
    if scenario == "parser-hang":
        source = source.replace(
            '/usr/bin/python3 -I -S -c "$process_runner_code" 10 /usr/bin/python3',
            '/usr/bin/python3 -I -S -c "$process_runner_code" 1 /usr/bin/python3',
        )
        source = source.replace(
            "/usr/bin/python3 -I -S -c 'import atexit\nimport os\nfrom pathlib",
            "/usr/bin/python3 -I -S -c 'import atexit\nimport os\nimport time\ntime.sleep(30)\nfrom pathlib",
        )
    source = source.replace(
        "readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'",
        f"readonly identity_file='{identity}'",
    )
    source = source.replace(
        "readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'",
        f"readonly known_hosts_file='{known_hosts}'",
    )
    source = source.replace(
        "readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'",
        f"readonly expected_identity_sha='{digest(identity)}'",
    )
    source = source.replace(
        "readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'",
        f"readonly expected_known_hosts_sha='{digest(known_hosts)}'",
    )
    ssh_line = '    /usr/bin/python3 -I -S -c "$process_runner_code" 60 /usr/bin/ssh \\\n'
    fake_line = f'    /usr/bin/python3 -I -S -c "$process_runner_code" 1 \'{fake_ssh}\' \\\n'
    source = source.replace(ssh_line, fake_line)
    source = source.replace("/tmp/mac2jb-app-plists.", f"{root}/app-plists.")
    runner = root / "runner.sh"
    write_executable(runner, source)
    return runner


def execute_runner(scenario: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-plist-runner-test.") as temporary:
        root = Path(temporary)
        runner = prepare_runner(root, scenario)
        result = subprocess.run(
            ["/bin/sh", str(runner)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        pid_file = root / "child-pid"
        if pid_file.exists() and process_exists(int(pid_file.read_text(encoding="ascii"))):
            raise AssertionError(f"{scenario} left child alive")
        if list(root.glob("app-plists.*")):
            raise AssertionError(f"{scenario} left private temporary evidence")
        return result


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_payload_streams_only_regular_plists() -> None:
    for scenario, expected_count in (("standard", 3), ("absent", 1), ("symlink", 1), ("zero", 0)):
        result = execute_payload(scenario)
        expect(result.returncode == 0, result.stderr.decode("utf-8", "replace"))
        with tarfile.open(fileobj=BytesIO(result.stdout), mode="r:") as archive:
            members = archive.getmembers()
        expect(len(members) == expected_count, f"{scenario} member count {len(members)}")
        expect(all(member.isfile() for member in members), f"{scenario} emitted non-file member")
    result = execute_payload("scan-cap")
    expect(result.returncode != 0, "over-cap payload falsely passed")
    expect(result.stdout == b"", "over-cap payload emitted a partial archive")


def test_payload_timeout_failures_emit_no_archive() -> None:
    for scenario in ("timeout-canary-fail", "timeout-tar-124", "timeout-tar-137"):
        result = execute_payload(scenario)
        expect(result.returncode != 0, f"{scenario} falsely passed")
        expect(result.stdout == b"", f"{scenario} emitted a partial archive")


def test_runner_accepts_versions_and_absence() -> None:
    result = execute_runner("standard")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == EXPECTED, result.stdout)
    result = execute_runner("absent")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == "dopamine-app: not-observed\ntrollstore-app: not-observed\n", result.stdout)
    result = execute_runner("trollstore-missing-version")
    expect(result.returncode == 0, result.stderr)
    expect(
        result.stdout
        == "dopamine-app: version=2.4.5 build=1 bundle-family=standard\n"
        "trollstore-app: version=not-present build=210 bundle-family=stealth\n",
        result.stdout,
    )


def test_runner_rejects_unsafe_archives() -> None:
    for scenario in (
        "duplicate",
        "non-string",
        "invalid-path",
        "malformed",
        "symlink-member",
        "trailing-junk",
        "aligned-junk",
        "zero-then-junk",
        "gnu-longname",
        "duplicate-xml-key",
        "duplicate-binary-key",
        "dopamine-missing-version",
        "trollstore-null-version",
        "huge-binary-object-count",
        "overlapping-binary-objects",
        "oversized",
    ):
        result = execute_runner(scenario)
        expect(result.returncode != 0, f"{scenario} falsely passed")
        expect(result.stdout == "", f"{scenario} released output")


def test_runner_hang_is_bounded_and_reaped() -> None:
    for scenario in ("hang", "parser-hang"):
        started = time.monotonic()
        result = execute_runner(scenario)
        expect(result.returncode != 0, f"{scenario} falsely passed")
        expect(result.stdout == "", f"{scenario} released output")
        expect(time.monotonic() - started < 5, f"{scenario} was not bounded")


def test_runner_signals_reap_and_cleanup() -> None:
    for sent_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        with tempfile.TemporaryDirectory(prefix="mac2jb-plist-runner-test.") as temporary:
            root = Path(temporary)
            runner = prepare_runner(root, "hang")
            process = subprocess.Popen(
                ["/bin/sh", str(runner)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            pid_file = root / "child-pid"
            deadline = time.monotonic() + 4
            while not pid_file.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            expect(pid_file.exists(), f"{sent_signal.name} child did not start")
            child_pid = int(pid_file.read_text(encoding="ascii"))
            os.killpg(process.pid, sent_signal)
            stdout, stderr = process.communicate(timeout=4)
            expect(process.returncode == 128 + sent_signal, f"{sent_signal.name}: {process.returncode} {stderr}")
            expect(stdout == "", f"{sent_signal.name} released output")
            expect(not process_exists(child_pid), f"{sent_signal.name} left child alive")
            expect(not list(root.glob("app-plists.*")), f"{sent_signal.name} left temp evidence")


def main() -> None:
    tests = [
        test_missing_sentinel_distinguishes_explicit_null,
        test_payload_streams_only_regular_plists,
        test_payload_timeout_failures_emit_no_archive,
        test_runner_accepts_versions_and_absence,
        test_runner_rejects_unsafe_archives,
        test_runner_hang_is_bounded_and_reaped,
        test_runner_signals_reap_and_cleanup,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS {len(tests)} app-version archive scenarios")


if __name__ == "__main__":
    main()
