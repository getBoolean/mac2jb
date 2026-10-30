#!/usr/bin/env python3
"""Bind four new attested SpringBoard R2 reports to a Mac A USB window.

This Mac-only wrapper checks the fixed monitor and Go runner sources, compiles
them privately, and waits for the monitor's exact target-ready record before
any iPad action. Over pinned Wi-Fi SSH it clears only each app's previously
captured round-4 receipt by full digest, runs rounds 5 and 6 for baseline and
set-description, and validates all twelve retained reports. The Go runner
checks installed code, the backed-up profile, and pinned SSH for each action.
The app performs read-only IOKit calls and writes only its own bounded report;
the clear helper removes only that exact captured report between rounds.
After a complete event-free 90-second Mac window, this wrapper publishes only
private ignored evidence. It does not change USB, SSH, trust, or system files.
Physical orientation and power remain unattributed in these app reports.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
BUILD = ROOT / "build/ipad-hardware"
MONITOR = ROOT / "scripts/ipad-hardware/host/u1-usb-event-monitor.swift"
WINDOW = ROOT / "scripts/ipad-hardware/run-capture-host-authorization-window.py"
RUNNER = ROOT / "scripts/ipad-hardware/host/run-springboard-r2-report-wifi.go"
VALIDATOR = ROOT / "scripts/ipad-hardware/validate-springboard-r2-report.py"
PINS = {
    MONITOR: "da900b13b41435fc13f7e596f1ed76c88079ad04edd8733440d2a75406079199",
    WINDOW: "365d18f7bc29fbab827537e3cbdde7a69e6501e679b738c26cd84c97b848d456",
    RUNNER: "1f3842654cef7a6e092c2dff47fe6c8ad5fb592a69ae2cf7705b1fc384304e64",
    VALIDATOR: "00a6ca00cde30be22d3a6257fafdeb4e11c9f3e3e8d6a65e17dc51cd3d25cc3d",
}
OUTPUT = BUILD / "host-lifecycle-springboard-r2-authorization-wifi-a"
STAGING = BUILD / ".host-lifecycle-springboard-r2-authorization-wifi-a.staging"
FINGERPRINT = re.compile(rb"^SPRINGBOARD_R2_REPORT_VALID profile=(baseline|setdescription) round=([1-6]) controllers=1 functions=16 operations=42 topology=([0-9a-f]{64})\n$")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def stop(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def command(args, timeout, environment=None):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, env=environment)
    require(result.returncode == 0 and len(result.stdout) <= 4096, "bounded local command failed")
    return result.stdout


def validate_report(label, number):
    output = command(["/opt/homebrew/bin/python3", "-I", "-S", "-B", str(VALIDATOR), label, str(number)], 15)
    match = FINGERPRINT.fullmatch(output)
    require(match is not None and match.group(1).decode() == label and int(match.group(2)) == number,
            "R2 report validator rejected")
    path = BUILD / f"springboard-r2-{label}-round-{number}.json"
    data = path.read_bytes()
    require(0 < len(data) <= 1_048_576, "private report extent")
    return match.group(3).decode(), hashlib.sha256(data).hexdigest()


def main():
    require(len(sys.argv) == 1, "no arguments accepted")
    require(not OUTPUT.exists() and not OUTPUT.is_symlink() and not STAGING.exists() and not STAGING.is_symlink(),
            "USB lifecycle evidence path already exists")
    for path, expected in PINS.items():
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "pinned source changed")
    previous = {label: [validate_report(label, number) for number in (1, 2, 3, 4)]
                for label in ("baseline", "setdescription")}
    require(all(len({row[0] for row in rows}) == 1 for rows in previous.values()), "prior R2 rounds disagree")
    window = runpy.run_path(str(WINDOW))
    window["safe_host_tool"](Path("/usr/bin/xcrun"))
    with tempfile.TemporaryDirectory(prefix="mac2jb-r2-window-", dir=BUILD) as directory:
        temporary = Path(directory)
        cache = temporary / "module-cache"
        cache.mkdir(mode=0o700)
        monitor_binary = temporary / "usb-monitor"
        go_binary = temporary / "r2-runner"
        environment = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "LC_ALL": "C",
                       "SWIFT_MODULECACHE_PATH": str(cache), "CLANG_MODULE_CACHE_PATH": str(cache),
                       "TMPDIR": str(temporary)}
        command(["/usr/bin/xcrun", "--sdk", "macosx", "swiftc", str(MONITOR),
                 "-framework", "IOKit", "-framework", "CryptoKit", "-o", str(monitor_binary)],
                30, environment)
        go_env = os.environ.copy()
        go_env["GOCACHE"] = str(BUILD / "go-cache")
        command(["/opt/homebrew/bin/go", "vet", str(RUNNER)], 30, go_env)
        command(["/opt/homebrew/bin/go", "build", "-o", str(go_binary), str(RUNNER)], 30, go_env)
        require(hashlib.sha256(RUNNER.read_bytes()).hexdigest() == PINS[RUNNER], "runner source changed during build")
        monitor = None
        monitor_fd = None
        try:
            monitor, monitor_fd = window["start_monitor"](monitor_binary, temporary / "monitor.ndjson")
            ready_data = window["wait_ready"](monitor, monitor_fd)
            ready = window["validate_ready"](ready_data)
            ready_time = time.monotonic_ns()
            start = time.monotonic_ns()
            for label in ("baseline", "setdescription"):
                for action in ("clear4", "round5", "clear5", "round6"):
                    output = command([str(go_binary), label, action], 20)
                    if action.startswith("clear"):
                        require(output == f"SPRINGBOARD_R2_CLEAR profile={label} verified\n".encode(),
                                "R2 clear receipt invalid")
                    else:
                        require(output.startswith(f"SPRINGBOARD_R2_LAUNCH profile={label} status=accepted\nSPRINGBOARD_R2_CAPTURE profile={label} bytes=".encode()) and
                                len(output.splitlines()) == 2, "R2 capture receipt invalid")
                    require(monitor.poll() is None, "USB monitor ended during R2 action")
            finish = time.monotonic_ns()
            reports = {}
            for label in ("baseline", "setdescription"):
                rows = [validate_report(label, number) for number in (1, 2, 3, 4, 5, 6)]
                require(len({row[0] for row in rows}) == 1, "R2 topology changed across rounds")
                reports[label] = {"topologyFingerprint": rows[0][0],
                                  "reportSha256ByRound": {str(number): row[1]
                                                          for number, row in enumerate(rows, 1)}}
            require(os.pread(monitor_fd, 131073, 0) == ready_data,
                    "unexpected monitor output before window completed")
            monitor.wait(timeout=100)
            monitor_finished = time.monotonic_ns()
            require(monitor.returncode == 0, "USB lifecycle monitor failed")
            data = os.pread(monitor_fd, 131073, 0)
            summary = window["validate_monitor_output"](data, ready)
            require(ready_time <= start <= finish <= monitor_finished,
                    "R2 actions not bound to monitor window")
            for path, expected in PINS.items():
                require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                        "pinned source changed during window")
            manifest = {"schemaVersion": 1, "peer": "capture-host",
                        "controlTransport": "pinned-wifi-ssh", "physicalOrientation": "a-operator-confirmed",
                        "powerState": "operator-observed-vbus-charging", "profileSet": "ordinary-springboard-baseline-setdescription",
                        "monitorSourceSha256": PINS[MONITOR], "runnerSourceSha256": PINS[RUNNER],
                        "validatorSourceSha256": PINS[VALIDATOR],
                        "monitorOutputSha256": hashlib.sha256(data).hexdigest(),
                        "probeStartedAfterReadyMilliseconds": (start-ready_time)//1_000_000,
                        "probeDurationMilliseconds": (finish-start)//1_000_000,
                        "monitorFinishedAfterProbeMilliseconds": (monitor_finished-finish)//1_000_000,
                        "reports": reports, "summary": summary}
            window["publish"](OUTPUT, STAGING, data, manifest)
            print("SPRINGBOARD_R2_WINDOW accepted lifecycle=event-free profiles=two rounds=two-each")
        finally:
            if monitor_fd is not None:
                os.close(monitor_fd)
            stop(monitor)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print("SPRINGBOARD_R2_WINDOW rejected: " + str(error) +
              "; inspect app reports before retry", file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print("SPRINGBOARD_R2_WINDOW rejected; inspect app reports before retry", file=sys.stderr)
        raise SystemExit(1)
