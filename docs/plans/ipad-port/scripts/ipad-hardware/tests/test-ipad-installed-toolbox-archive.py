#!/usr/bin/env python3
"""Hermetic tests for the read-only installed-toolbox archive payload."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import os
import subprocess
import sys
import tarfile
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-installed-toolbox-archive.sh"
EXPECTED_FILES = {
    "Info.plist": b"plist",
    "mac2jb-u1-baseline": b"baseline",
    "Probes/mac2jb-u1-setdescription": b"setdescription",
    "Probes/mac2jb-u1-controller-client": b"controller",
    "Probes/mac2jb-u1-interface-client": b"interface",
    "_CodeSignature/CodeResources": b"resources",
}


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def make_bundle(root: Path, container: str = "UUID") -> Path:
    app = root / container / "Mac2JBU1-Toolbox.app"
    for relative, content in EXPECTED_FILES.items():
        path = app / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o555 if "mac2jb-u1-" in path.name else 0o444)
    return app


def snapshot(root: Path) -> dict[Path, tuple[bytes, int]]:
    return {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def prepare_payload(root: Path, scenario: str) -> tuple[Path, Path]:
    containers = root / "containers"
    applications = root / "applications"
    jb_applications = root / "jb-applications"
    for directory in (containers, applications, jb_applications):
        directory.mkdir()

    if scenario not in ("absent", "symlink-app"):
        make_bundle(containers)
    if scenario == "duplicate":
        make_bundle(applications, container="")
    if scenario == "symlink-app":
        real_app = make_bundle(root / "outside")
        (containers / "UUID").mkdir()
        (containers / "UUID" / "Mac2JBU1-Toolbox.app").symlink_to(real_app)
    if scenario == "nested-symlink":
        outside = root / "outside-secret"
        outside.write_bytes(b"do-not-follow")
        app = containers / "UUID" / "Mac2JBU1-Toolbox.app"
        (app / "unexpected-link").symlink_to(outside)

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
            os.execv(command, arguments[3:])
            """
        ),
    )

    source = PAYLOAD.read_text(encoding="utf-8")
    tar_block = """for candidate in \\
  /var/jb/usr/bin/bsdtar \\
  /var/jb/usr/bin/tar \\
  /var/jb/bin/tar \\
  /usr/bin/tar \\
  /bin/tar
do"""
    source = source.replace(tar_block, "for candidate in /usr/bin/bsdtar\ndo")
    timeout_block = """for candidate in \\
  /var/jb/usr/bin/timeout \\
  /var/jb/bin/timeout \\
  /usr/bin/timeout \\
  /bin/timeout \\
  /var/jb/usr/bin/gtimeout \\
  /var/jb/bin/gtimeout \\
  /usr/bin/gtimeout \\
  /bin/gtimeout
do"""
    source = source.replace(timeout_block, f"for candidate in '{fake_timeout}'\ndo")
    roots = """  /var/containers/Bundle/Application \\
  /Applications \\
  /var/jb/Applications"""
    fixture_roots = f"  '{containers}' \\\n+  '{applications}' \\\n+  '{jb_applications}'"
    source = source.replace(roots, fixture_roots)
    globs = """  /var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app \\
  /Applications/Mac2JBU1-Toolbox.app \\
  /var/jb/Applications/Mac2JBU1-Toolbox.app"""
    fixture_globs = f"""  '{containers}'/*/Mac2JBU1-Toolbox.app \\
  '{applications}'/Mac2JBU1-Toolbox.app \\
  '{jb_applications}'/Mac2JBU1-Toolbox.app"""
    source = source.replace(globs, fixture_globs)
    if source == PAYLOAD.read_text(encoding="utf-8"):
        raise AssertionError("payload fixture rewrite did not apply")
    payload = root / "payload.sh"
    write_executable(payload, source)
    return payload, containers


def execute(scenario: str, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-payload-test-") as directory:
        root = Path(directory)
        payload, fixture_root = prepare_payload(root, scenario)
        before = snapshot(root)
        result = subprocess.run(
            ["/bin/sh", str(payload), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        after = snapshot(root)
        # Ignore the generated payload itself and fake timeout; fixture files must not change.
        for path, state in before.items():
            if path.is_relative_to(fixture_root):
                assert after[path] == state
        return result


def test_success() -> None:
    result = execute("success")
    assert result.returncode == 0
    assert result.stderr == b""
    with tarfile.open(fileobj=BytesIO(result.stdout), mode="r:*") as archive:
        names = [member.name for member in archive.getmembers()]
        assert any(name.endswith("/Info.plist") for name in names)
        assert any(name.endswith("/Probes/mac2jb-u1-controller-client") for name in names)


def test_absent_and_duplicates_fail_closed() -> None:
    assert execute("absent").returncode == 68
    assert execute("absent").stdout == b""
    duplicate = execute("duplicate")
    assert duplicate.returncode == 65
    assert duplicate.stdout == b""


def test_symlink_app_is_not_followed() -> None:
    result = execute("symlink-app")
    assert result.returncode == 68
    assert result.stdout == b""


def test_nested_symlink_is_archived_not_followed() -> None:
    result = execute("nested-symlink")
    assert result.returncode == 0
    with tarfile.open(fileobj=BytesIO(result.stdout), mode="r:*") as archive:
        member = next(item for item in archive.getmembers() if item.name.endswith("unexpected-link"))
        assert member.issym()
        assert member.size == 0


def test_timeout_and_arguments_fail_closed() -> None:
    assert execute("timeout-canary-fail").returncode == 67
    assert execute("timeout-tar-124").returncode == 124
    assert execute("success", "unexpected").returncode == 64


def main() -> None:
    test_success()
    test_absent_and_duplicates_fail_closed()
    test_symlink_app_is_not_followed()
    test_nested_symlink_is_archived_not_followed()
    test_timeout_and_arguments_fail_closed()
    print("PASS installed-toolbox archive payload tests (5 groups)")


if __name__ == "__main__":
    main()
