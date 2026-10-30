#!/usr/bin/env python3
"""Hermetic tests for the on-device read-only app-version payload."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-app-versions.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def add_app(root: Path, directory: str, metadata: dict[str, object], *, containerized: bool) -> Path:
    app = root / directory / "Fixture.app" if containerized else root / f"{directory}.app"
    app.mkdir(parents=True)
    plist = app / "Info.plist"
    plist.write_text(json.dumps(metadata), encoding="utf-8")
    return plist


def prepare(root: Path, scenario: str) -> tuple[Path, list[Path]]:
    containers = root / "containers"
    applications = root / "applications"
    jb_applications = root / "jb-applications"
    for path in (containers, applications, jb_applications):
        path.mkdir()

    fake_plutil = root / "plutil"
    if scenario == "scan-cap":
        write_executable(fake_plutil, "#!/bin/sh\nexit 1\n")
    else:
        write_executable(
            fake_plutil,
            textwrap.dedent(
                f"""\
            #!{sys.executable}
            import json
            import pathlib
            import sys

            arguments = sys.argv[1:]
            expected = ["raw", "-expect", "string", "-n", "-o", "-", "--"]
            if len(arguments) != 10 or arguments[0] != "-extract" or arguments[2:9] != expected:
                raise SystemExit(64)
            metadata = json.loads(pathlib.Path(arguments[9]).read_text(encoding="utf-8"))
            value = metadata.get(arguments[1])
            if not isinstance(value, str):
                raise SystemExit(1)
            sys.stdout.write(value)
            """
            ),
        )

    if scenario not in ("absent", "scan-cap", "symlink-plist"):
        dopamine_version: object = "bad/value" if scenario == "invalid" else "2.4.5"
        if scenario == "long":
            dopamine_version = "v" * 65
        if scenario == "non-string":
            dopamine_version = 245
        if scenario == "trailing-newline":
            dopamine_version = "2.4.5\n"
        add_app(
            containers,
            "A",
            {
                "CFBundleIdentifier": "com.opa334.Dopamine",
                "CFBundleShortVersionString": dopamine_version,
                "CFBundleVersion": "1",
            },
            containerized=True,
        )
        add_app(
            applications,
            "TrollStore",
            {
                "CFBundleIdentifier": (
                    "com.opa334.TrollStore.TS_0123456789ABCDEF"
                    if scenario == "stealth"
                    else "com.opa334.TrollStore"
                ),
                "CFBundleShortVersionString": "2.1.0",
                "CFBundleVersion": "210",
            },
            containerized=False,
        )
    if scenario == "duplicate":
        add_app(
            jb_applications,
            "DuplicateDopamine",
            {
                "CFBundleIdentifier": "com.opa334.Dopamine",
                "CFBundleShortVersionString": "9.9.9",
                "CFBundleVersion": "2",
            },
            containerized=False,
        )
    add_app(
        jb_applications,
        "Unrelated",
        {
            "CFBundleIdentifier": "example.unrelated",
            "CFBundleShortVersionString": "unsafe/value/is/ignored",
            "CFBundleVersion": "ignored",
        },
        containerized=False,
    )
    if scenario == "scan-cap":
        for index in range(513):
            add_app(
                applications,
                f"Unrelated{index:03d}",
                {"CFBundleIdentifier": f"example.unrelated.{index}"},
                containerized=False,
            )
    if scenario == "symlink-plist":
        target = root / "external.plist"
        target.write_text(
            json.dumps(
                {
                    "CFBundleIdentifier": "com.opa334.Dopamine",
                    "CFBundleShortVersionString": "9.9.9",
                    "CFBundleVersion": "9",
                }
            ),
            encoding="utf-8",
        )
        symlink_app = applications / "Symlink.app"
        symlink_app.mkdir()
        (symlink_app / "Info.plist").symlink_to(target)
    if scenario == "writable-tool":
        fake_plutil.chmod(0o755)
    if scenario == "symlink-tool":
        real_tool = root / "plutil-real"
        fake_plutil.rename(real_tool)
        fake_plutil.symlink_to(real_tool)

    source = PAYLOAD.read_text(encoding="utf-8")
    source = source.replace(
        "for candidate in /usr/bin/plutil /var/jb/usr/bin/plutil; do",
        f"for candidate in '{fake_plutil}'; do",
    )
    old_roots = (
        "  /var/containers/Bundle/Application \\\n"
        "  /Applications \\\n"
        "  /var/jb/Applications"
    )
    new_roots = f"  '{containers}' \\\n  '{applications}' \\\n  '{jb_applications}'"
    old_globs = (
        "  /var/containers/Bundle/Application/*/*.app/Info.plist \\\n"
        "  /Applications/*.app/Info.plist \\\n"
        "  /var/jb/Applications/*.app/Info.plist"
    )
    new_globs = (
        f"  '{containers}'/*/*.app/Info.plist \\\n"
        f"  '{applications}'/*.app/Info.plist \\\n"
        f"  '{jb_applications}'/*.app/Info.plist"
    )
    source = source.replace(old_roots, new_roots).replace(old_globs, new_globs)
    runner = root / "payload.sh"
    write_executable(runner, source)
    evidence = sorted(containers.rglob("Info.plist")) + sorted(applications.rglob("Info.plist")) + sorted(
        jb_applications.rglob("Info.plist")
    )
    return runner, evidence


def execute(scenario: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-app-payload-test.") as temporary:
        root = Path(temporary)
        runner, evidence = prepare(root, scenario)
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in evidence}
        result = subprocess.run(
            ["/bin/sh", str(runner)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        after = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in evidence}
        if after != before:
            raise AssertionError(f"{scenario} changed fixture contents or mtimes")
        return result


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_standard() -> None:
    result = execute("standard")
    expect(result.returncode == 0, str(result.returncode))
    expect(
        result.stdout
        == "dopamine-app: version=2.4.5 build=1 bundle-family=standard\n"
        "trollstore-app: version=2.1.0 build=210 bundle-family=standard\n",
        result.stdout,
    )
    expect(result.stderr == "", "payload emitted diagnostics")


def test_stealth_redacts_identifier() -> None:
    result = execute("stealth")
    expect(result.returncode == 0, str(result.returncode))
    expect("bundle-family=stealth" in result.stdout, result.stdout)
    expect("TS_" not in result.stdout, "stealth identifier suffix leaked")


def test_absent_is_fixed_output() -> None:
    result = execute("absent")
    expect(result.returncode == 0, str(result.returncode))
    expect(result.stdout == "dopamine-app: not-observed\ntrollstore-app: not-observed\n", result.stdout)


def test_duplicate_stops_without_output() -> None:
    result = execute("duplicate")
    expect(result.returncode != 0, "duplicate app falsely passed")
    expect(result.stdout == "", "duplicate app leaked partial output")


def test_invalid_values_stop_without_output() -> None:
    for scenario in ("invalid", "long", "non-string", "trailing-newline"):
        result = execute(scenario)
        expect(result.returncode != 0, f"{scenario} value falsely passed")
        expect(result.stdout == "", f"{scenario} value leaked partial output")


def test_untrusted_tool_stops_without_output() -> None:
    for scenario in ("writable-tool", "symlink-tool"):
        result = execute(scenario)
        expect(result.returncode != 0, f"{scenario} falsely passed")
        expect(result.stdout == "", f"{scenario} leaked output")


def test_symlink_plist_is_not_followed() -> None:
    result = execute("symlink-plist")
    expect(result.returncode == 0, str(result.returncode))
    expect(result.stdout == "dopamine-app: not-observed\ntrollstore-app: not-observed\n", result.stdout)


def test_scan_cap_stops_without_output() -> None:
    result = execute("scan-cap")
    expect(result.returncode != 0, "oversized scan falsely passed")
    expect(result.stdout == "", "oversized scan leaked output")


def main() -> None:
    tests = [
        test_standard,
        test_stealth_redacts_identifier,
        test_absent_is_fixed_output,
        test_duplicate_stops_without_output,
        test_invalid_values_stop_without_output,
        test_untrusted_tool_stops_without_output,
        test_symlink_plist_is_not_followed,
        test_scan_cap_stops_without_output,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS {len(tests)} on-device app-version payload scenarios")


if __name__ == "__main__":
    main()
