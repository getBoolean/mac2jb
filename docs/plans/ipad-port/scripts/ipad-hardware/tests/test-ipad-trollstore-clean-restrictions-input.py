#!/usr/bin/env python3
"""Hermetic tests for the cleanRestrictions input payload."""

from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-trollstore-clean-restrictions-input.sh"
MEMBER = "private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"


def write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o555)


def prepare(root: Path, scenario: str) -> tuple[Path, Path, Path]:
    parent = root / "ConfigurationProfiles"
    parent.mkdir()
    target = parent / "ClientTruth.plist"
    if scenario not in {"absent", "symlink"}:
        target.write_bytes(b"bplist fixture")
        target.chmod(0o444 if scenario != "writable" else 0o600)
    if scenario == "symlink":
        outside = root / "outside.plist"
        outside.write_bytes(b"outside")
        target.symlink_to(outside)
    parent.chmod(0o555 if scenario != "inaccessible-parent" else 0o000)

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
            os.execv(command, arguments[3:])
            """
        ),
    )

    source = PAYLOAD.read_text(encoding="utf-8")
    source = source.replace(
        "parent_directory='/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles'",
        f"parent_directory={str(parent)!r}",
    )
    tar_loop = """for candidate in \\
  /var/jb/usr/bin/bsdtar \\
  /var/jb/usr/bin/tar \\
  /var/jb/bin/tar \\
  /usr/bin/tar \\
  /bin/tar
do"""
    source = source.replace(tar_loop, "for candidate in /usr/bin/bsdtar\ndo")
    timeout_loop = """for candidate in \\
  /var/jb/usr/bin/timeout \\
  /var/jb/bin/timeout \\
  /usr/bin/timeout \\
  /bin/timeout \\
  /var/jb/usr/bin/gtimeout \\
  /var/jb/bin/gtimeout \\
  /usr/bin/gtimeout \\
  /bin/gtimeout
do"""
    source = source.replace(timeout_loop, f"for candidate in {str(fake_timeout)!r}\ndo")
    member_assignment = "member='private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist'"
    source = source.replace(member_assignment, f"member={str(target).lstrip('/')!r}")
    if str(parent) not in source or str(fake_timeout) not in source:
        raise AssertionError("fixture rewrite failed")
    payload = root / "payload.sh"
    write_executable(payload, source)
    return payload, parent, target


def execute(scenario: str, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-payload-test-") as directory:
        root = Path(directory)
        payload, parent, target = prepare(root, scenario)
        before = target.read_bytes() if target.is_file() and not target.is_symlink() else None
        result = subprocess.run(
            ["/bin/sh", str(payload), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        if before is not None:
            assert target.read_bytes() == before
        parent.chmod(0o755)
        return result


def test_absent_is_explicit() -> None:
    result = execute("absent")
    assert result.returncode == 0
    assert result.stdout == b"ABSENT\n"
    assert result.stderr == b""


def test_exact_regular_file_is_archived() -> None:
    result = execute("present")
    assert result.returncode == 0
    assert result.stdout.startswith(b"ARCHIVE\n")
    with tarfile.open(fileobj=BytesIO(result.stdout.removeprefix(b"ARCHIVE\n")), mode="r:") as archive:
        members = archive.getmembers()
        assert len(members) == 1
        assert members[0].isfile()
        assert members[0].name.endswith("/ClientTruth.plist")
        extracted = archive.extractfile(members[0])
        assert extracted is not None and extracted.read() == b"bplist fixture"


def test_unsafe_or_unobservable_state_rejects() -> None:
    for scenario in ("symlink", "writable", "inaccessible-parent"):
        result = execute(scenario)
        assert result.returncode != 0, scenario
        assert result.stdout == b"", scenario


def test_arguments_and_timeout_canary_reject() -> None:
    assert execute("present", "unexpected").returncode == 64
    result = execute("timeout-canary-fail")
    assert result.returncode != 0
    assert result.stdout == b""


def main() -> None:
    test_absent_is_explicit()
    test_exact_regular_file_is_archived()
    test_unsafe_or_unobservable_state_rejects()
    test_arguments_and_timeout_canary_reject()
    print("PASS TrollStore cleanRestrictions input payload tests (4 groups / 7 scenarios)")


if __name__ == "__main__":
    main()
