#!/usr/bin/env python3
"""Hermetic tests for the CoreDevice installed-app version collector."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
RUNNER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/collect-installed-app-versions.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o700)


def prepare(root: Path, scenario: str) -> Path:
    fake_xcrun = root / "xcrun"
    write_executable(
        fake_xcrun,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import os
            import pathlib
            import sys
            import time

            scenario = {scenario!r}
            arguments = sys.argv[1:]
            root = pathlib.Path({str(root)!r})
            if scenario in ("hang", "signal-hang"):
                if scenario == "signal-hang":
                    (root / "child-pid").write_text(str(os.getpid()))
                time.sleep(30)
            if "--json-output" not in arguments:
                raise SystemExit(64)
            output = pathlib.Path(arguments[arguments.index("--json-output") + 1])
            if arguments[:3] == ["devicectl", "list", "devices"]:
                expected = [
                    "devicectl", "list", "devices", "--filter",
                    "State = 'available'", "--timeout", "10",
                    "--json-output", str(output),
                ]
                if arguments != expected:
                    raise SystemExit(64)
                if scenario == "device-command-failure":
                    raise SystemExit(69)
                if scenario == "oversized":
                    with output.open("wb") as handle:
                        handle.write(b"x" * (32 * 1024 * 1024))
                    raise SystemExit(0)
                if scenario == "cross-level-device":
                    output.write_text(json.dumps({{
                        "result": {{"devices": [{{
                            "identifier": "fixture-device",
                            "nested": {{
                                "hardwareProperties": {{"productType": "iPad14,5"}},
                            }},
                        }}]}},
                    }}))
                    raise SystemExit(0)
                devices = [
                    {{
                        "identifier": "fixture-device",
                        "hardwareProperties": {{"productType": "iPad14,5"}},
                    }}
                ]
                if scenario == "no-target":
                    devices[0]["hardwareProperties"]["productType"] = "iPad13,4"
                if scenario == "ambiguous-device":
                    devices.append({{
                        "identifier": "fixture-device-2",
                        "hardwareProperties": {{"productType": "iPad14,5"}},
                    }})
                if scenario == "malformed-second-target":
                    devices.append({{
                        "identifier": "invalid device id",
                        "hardwareProperties": {{"productType": "iPad14,5"}},
                    }})
                if scenario == "duplicate-same-id":
                    devices.append({{
                        "identifier": "fixture-device",
                        "hardwareProperties": {{"productType": "iPad14,5"}},
                    }})
                output.write_text(json.dumps({{"result": {{"devices": devices}}}}))
                raise SystemExit(0)
            if arguments[:4] == ["devicectl", "device", "info", "apps"]:
                if "--bundle-id" in arguments:
                    expected = [
                        "devicectl", "device", "info", "apps", "--device",
                        "fixture-device", "--include-default-apps",
                        "--include-removable-apps", "--no-include-app-clips",
                        "--bundle-id", "com.opa334.Dopamine", "--timeout", "15",
                        "--json-output", str(output),
                    ]
                    query = "dopamine"
                elif "--search" in arguments:
                    expected = [
                        "devicectl", "device", "info", "apps", "--device",
                        "fixture-device", "--include-default-apps",
                        "--include-removable-apps", "--no-include-app-clips",
                        "--search", "com.opa334.TrollStore", "--timeout", "15",
                        "--json-output", str(output),
                    ]
                    query = "trollstore"
                else:
                    raise SystemExit(64)
                if arguments != expected:
                    raise SystemExit(64)
                if scenario == f"{{query}}-command-failure":
                    raise SystemExit(69)
                if scenario == "duplicate-key" and query == "dopamine":
                    output.write_text(
                        '{{"result":{{"apps":[{{"bundleIdentifier":'
                        '"com.opa334.Dopamine","version":"2.4.5",'
                        '"version":"9.9.9"}}]}}}}'
                    )
                    raise SystemExit(0)
                apps = []
                if scenario != "absent":
                    candidates = [
                        {{
                            "bundleIdentifier": "com.opa334.Dopamine",
                            "version": "2.4.5",
                            "buildVersion": "1",
                        }},
                        {{
                            "bundleIdentifier": (
                                "com.opa334.TrollStore.TS_0123456789ABCDEF"
                                if scenario == "stealth" else "com.opa334.TrollStore"
                            ),
                            "version": "2.1.0",
                            "buildVersion": "210",
                        }},
                    ]
                    apps.append(candidates[0] if query == "dopamine" else candidates[1])
                if scenario == "invalid-version" and query == "dopamine":
                    apps[0]["version"] = "bad\\nvalue"
                if scenario == "ambiguous-app" and query == "dopamine":
                    apps.append({{
                        "bundleIdentifier": "com.opa334.Dopamine",
                        "version": "9.9.9",
                        "buildVersion": "2",
                    }})
                if scenario == "conflicting-alias" and query == "dopamine":
                    apps[0]["shortVersion"] = "9.9.9"
                output.write_text(json.dumps({{"result": {{"apps": apps}}}}))
                raise SystemExit(0)
            raise SystemExit(64)
            """
        ),
    )

    source = RUNNER.read_text(encoding="utf-8")
    source = source.replace("readonly xcrun_path='/usr/bin/xcrun'", f"readonly xcrun_path='{fake_xcrun}'")
    source = source.replace("timeout=25", "timeout=1")
    source = source.replace("/tmp/mac2jb-app-versions.", f"{root}/app-versions.")
    runner = root / "runner.sh"
    write_executable(runner, source)
    return runner


def execute(scenario: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-app-version-test.") as temporary:
        root = Path(temporary)
        runner = prepare(root, scenario)
        result = subprocess.run(
            ["/bin/sh", str(runner)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        leftovers = list(root.glob("app-versions.*"))
        expect(not leftovers, f"{scenario} left temporary evidence: {leftovers}")
        return result


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_standard() -> None:
    result = execute("standard")
    expect(result.returncode == 0, result.stderr)
    expect(
        result.stdout
        == "dopamine-app: version=2.4.5 build=1 bundle-family=standard\n"
        "trollstore-app: version=2.1.0 build=210 bundle-family=standard\n",
        result.stdout,
    )


def test_stealth_redacts_identifier() -> None:
    result = execute("stealth")
    expect(result.returncode == 0, result.stderr)
    expect("bundle-family=stealth" in result.stdout, result.stdout)
    expect("TS_" not in result.stdout, "stealth suffix leaked")


def test_absent_is_fixed_output() -> None:
    result = execute("absent")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == "dopamine-app: not-observed\ntrollstore-app: not-observed\n", result.stdout)


def test_ambiguous_device_stops() -> None:
    result = execute("ambiguous-device")
    expect(result.returncode != 0, "ambiguous device falsely passed")
    expect(result.stdout == "", "ambiguous device leaked output")
    expect(
        "target-selection: records=multiple valid-identifiers=multiple "
        "unique-identifiers=multiple all-valid=yes all-same=no records-identical=no\n"
        in result.stderr,
        result.stderr,
    )


def test_malformed_second_target_stops() -> None:
    result = execute("malformed-second-target")
    expect(result.returncode != 0, "malformed second target falsely passed")
    expect(result.stdout == "", "malformed second target leaked output")
    expect(
        "target-selection: records=multiple valid-identifiers=one "
        "unique-identifiers=one all-valid=no all-same=no records-identical=no\n"
        in result.stderr,
        result.stderr,
    )


def test_duplicate_same_id_stops() -> None:
    result = execute("duplicate-same-id")
    expect(result.returncode != 0, "duplicate same-ID target falsely passed")
    expect(result.stdout == "", "duplicate same-ID target leaked output")
    expect(
        "target-selection: records=multiple valid-identifiers=multiple "
        "unique-identifiers=one all-valid=yes all-same=yes records-identical=yes\n"
        in result.stderr,
        result.stderr,
    )


def test_no_target_reports_only_redacted_counts() -> None:
    result = execute("no-target")
    expect(result.returncode != 0, "missing target falsely passed")
    expect(result.stdout == "", "missing target leaked output")
    expect(
        "target-selection: records=zero valid-identifiers=zero "
        "unique-identifiers=zero all-valid=yes all-same=no records-identical=no\n"
        in result.stderr,
        result.stderr,
    )


def test_ambiguous_app_stops() -> None:
    result = execute("ambiguous-app")
    expect(result.returncode != 0, "ambiguous app falsely passed")
    expect(result.stdout == "", "ambiguous app leaked output")


def test_invalid_version_stops() -> None:
    result = execute("invalid-version")
    expect(result.returncode != 0, "invalid version falsely passed")
    expect(result.stdout == "", "invalid version leaked output")


def test_command_failures_stop() -> None:
    for scenario in (
        "device-command-failure",
        "dopamine-command-failure",
        "trollstore-command-failure",
    ):
        result = execute(scenario)
        expect(result.returncode != 0, f"{scenario} falsely passed")
        expect(result.stdout == "", f"{scenario} leaked output")


def test_hang_is_bounded() -> None:
    result = execute("hang")
    expect(result.returncode != 0, "hang falsely passed")
    expect(result.stdout == "", "hang leaked output")


def test_oversized_writer_is_bounded() -> None:
    result = execute("oversized")
    expect(result.returncode != 0, "oversized writer falsely passed")
    expect(result.stdout == "", "oversized writer leaked output")


def test_cross_level_device_join_is_rejected() -> None:
    result = execute("cross-level-device")
    expect(result.returncode != 0, "cross-level device join falsely passed")
    expect(result.stdout == "", "cross-level device join leaked output")


def test_conflicting_alias_is_rejected() -> None:
    result = execute("conflicting-alias")
    expect(result.returncode != 0, "conflicting metadata aliases falsely passed")
    expect(result.stdout == "", "conflicting aliases leaked output")


def test_duplicate_json_key_is_rejected() -> None:
    result = execute("duplicate-key")
    expect(result.returncode != 0, "duplicate JSON key falsely passed")
    expect(result.stdout == "", "duplicate JSON key leaked output")


def test_signal_reaps_child_and_cleans_up() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-app-version-test.") as temporary:
        root = Path(temporary)
        runner = prepare(root, "signal-hang")
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
        expect(pid_file.exists(), "signal fixture child did not start")
        child_pid = int(pid_file.read_text(encoding="ascii"))
        os.killpg(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=4)
        expect(process.returncode == 143, f"signal exit was {process.returncode}: {stderr}")
        expect(stdout == "", "signal path leaked output")
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(f"signal path left child {child_pid} alive")
        leftovers = list(root.glob("app-versions.*"))
        expect(not leftovers, f"signal path left temporary evidence: {leftovers}")


def main() -> None:
    tests = [
        test_standard,
        test_stealth_redacts_identifier,
        test_absent_is_fixed_output,
        test_ambiguous_device_stops,
        test_malformed_second_target_stops,
        test_duplicate_same_id_stops,
        test_no_target_reports_only_redacted_counts,
        test_ambiguous_app_stops,
        test_invalid_version_stops,
        test_command_failures_stop,
        test_hang_is_bounded,
        test_oversized_writer_is_bounded,
        test_cross_level_device_join_is_rejected,
        test_conflicting_alias_is_rejected,
        test_duplicate_json_key_is_rejected,
        test_signal_reaps_child_and_cleans_up,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS {len(tests)} installed-app version scenarios")


if __name__ == "__main__":
    main()
