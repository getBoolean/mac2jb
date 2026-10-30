#!/usr/bin/env python3
"""Run the two admitted U1 profiles inside a host USB lifecycle window.

What this code does: verify the pinned monitor and auxiliary-runner sources,
build the passive Mac IOUSB monitor, wait for monitor readiness, and run
the attested read-only controller/interface probes twice each. It requires an
event-free completed monitor window before publishing a private binding record.
The only iPad commands are those in the pinned auxiliary runner. USB control
requires one usbmux device and a fresh repo SSH tunnel; `--wifi` instead uses
the separately pinned target SSH service while keeping the USB cable attached
to the Mac. It creates no iPad file or USB configuration change.

The operator must mark and physically observe the cable's A or B orientation.
With final `--admission`, it binds the separately attested platform-only and
platform-plus-setdescription read-only reports to the same passive window.
It never installs an app or changes USB description. A Mac capture host does
not establish electronic Switch peer identity.
"""

import hashlib
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
HERE = Path(__file__).resolve().parent
BUILD = ROOT / "build/ipad-hardware"
RUNNER = HERE / "run-attested-auxiliary-probes.py"
MONITOR = HERE / "u1-usb-event-monitor.swift"
TUNNEL = HERE / "start-usb-ssh-tunnel.sh"
WINDOW = ROOT / "scripts/ipad-hardware/run-capture-host-authorization-window.py"
RUNNER_SHA = "195cc9644cfcdcb95e817731422d7bf4341a3af8c8eea2cd6085a38cb3f1e9f4"
MONITOR_SHA = "da900b13b41435fc13f7e596f1ed76c88079ad04edd8733440d2a75406079199"
POWERS = ("operator-observed-vbus-charging", "operator-observed-vbus-not-charging",
          "operator-observed-no-vbus", "operator-not-observed")
LABEL = re.compile(r"observed-[ab]-[a-z0-9][a-z0-9-]{0,31}\Z")


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def checked_sha(path, expected):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    require(digest == expected, "pinned source changed")


def one_usb_device():
    result = subprocess.run(["/opt/homebrew/bin/idevice_id", "-l"],
                            capture_output=True, timeout=8)
    return result.returncode == 0 and len(
        [line for line in result.stdout.splitlines() if line.strip()]) == 1


def stop_child(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def main():
    require(len(sys.argv) in (4, 5, 6) and
            (len(sys.argv) < 5 or sys.argv[4] == "--wifi") and
            (len(sys.argv) < 6 or sys.argv[5] == "--admission"),
            "Usage: run-auxiliary-with-usb-window.py a|b POWER_STATE observed-a|b-LABEL [--wifi [--admission]]")
    orientation, power, label = sys.argv[1:4]
    wireless = len(sys.argv) >= 5
    admission = len(sys.argv) == 6
    require(orientation in ("a", "b") and power in POWERS and
            LABEL.fullmatch(label) is not None and label.startswith("observed-" + orientation + "-"),
            "invalid observed capture arguments")
    report_name = (("admission-probe-" if admission else "auxiliary-probe-") +
                   "capture-host-" + orientation + "-" + power +
                   "-" + label + ("-wifi-control" if wireless else ""))
    report_dir = BUILD / report_name
    window_name = "host-lifecycle-" + report_name
    window_dir = BUILD / window_name
    staging = BUILD / ("." + window_name + ".staging")
    require(not any(path.exists() or path.is_symlink()
                    for path in (report_dir, window_dir, staging)), "capture output already exists")
    checked_sha(RUNNER, RUNNER_SHA)
    checked_sha(MONITOR, MONITOR_SHA)
    if not wireless:
        require(one_usb_device(), "one USB device required")
    window = runpy.run_path(str(WINDOW))
    window["safe_host_tool"](Path("/usr/bin/xcrun"))
    window["safe_host_tool"](Path("/usr/bin/python3"))
    if not wireless:
        require(not subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP:2222",
                                    "-sTCP:LISTEN"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=5).returncode == 0,
                "port 2222 already occupied")
    with tempfile.TemporaryDirectory(prefix="mac2jb-u1-partial-window-", dir=BUILD) as temporary:
        temporary = Path(temporary)
        binary = temporary / "usb-monitor"
        module_cache = temporary / "module-cache"
        module_cache.mkdir(mode=0o700)
        build = subprocess.run(["/usr/bin/xcrun", "--sdk", "macosx", "swiftc",
                                str(MONITOR), "-framework", "IOKit", "-framework",
                                "CryptoKit", "-o", str(binary)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                    "SWIFT_MODULECACHE_PATH": str(module_cache),
                                    "CLANG_MODULE_CACHE_PATH": str(module_cache),
                                    "TMPDIR": str(temporary)}, timeout=30)
        require(build.returncode == 0 and binary.is_file(), "host monitor compilation failed")
        tunnel = monitor = None
        monitor_fd = None
        try:
            if not wireless:
                tunnel = subprocess.Popen(["/bin/sh", str(TUNNEL)],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, start_new_session=True)
                for _ in range(40):
                    listener = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP:2222",
                                               "-sTCP:LISTEN"], stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL, timeout=5)
                    if listener.returncode == 0 or tunnel.poll() is not None:
                        break
                    time.sleep(0.125)
                require(listener.returncode == 0 and tunnel.poll() is None,
                        "checked USB SSH tunnel failed")
            monitor, monitor_fd = window["start_monitor"](binary, temporary / "monitor.ndjson")
            ready_data = window["wait_ready"](monitor, monitor_fd)
            ready = window["validate_ready"](ready_data)
            ready_observed = time.monotonic_ns()
            start = time.monotonic_ns()
            result = subprocess.run(["/usr/bin/python3", "-I", "-S", str(RUNNER)] +
                                    (["--admission"] if admission else []) +
                                    [orientation, power, label] +
                                    (["--wifi"] if wireless else []),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=75)
            finish = time.monotonic_ns()
            require(result.returncode == 0 and len(result.stdout) <= 4096,
                    "auxiliary runner failed")
            receipt_prefix = b"ADMISSION_PROBE " if admission else b"AUX_PROBE "
            require(result.stdout.count(receipt_prefix) == 5 and
                    receipt_prefix + b"accepted " in result.stdout and report_dir.is_dir(),
                    "auxiliary runner receipt invalid")
            checked_sha(RUNNER, RUNNER_SHA)
            checked_sha(MONITOR, MONITOR_SHA)
            require(monitor.poll() is None and os.pread(monitor_fd, 131073, 0) == ready_data,
                    "USB lifecycle event during probe")
            print("U1_PARTIAL_WINDOW probes=validated monitor=waiting-for-90-second-window",
                  flush=True)
            monitor.wait(timeout=100)
            monitor_finished = time.monotonic_ns()
            require(monitor.returncode == 0, "host monitor failed")
            data = os.pread(monitor_fd, 131073, 0)
            summary = window["validate_monitor_output"](data, ready)
            require(ready_observed <= start <= finish <= monitor_finished,
                    "observation interval not bound")
            manifest = report_dir / "partial-manifest.json"
            manifest_data = window["read_regular"](manifest, 2 * 1024 * 1024)
            manifest_sha = hashlib.sha256(manifest_data).hexdigest()
            binding = {"schemaVersion": 1, "peer": "capture-host",
                       "controlTransport": "pinned-wifi-ssh" if wireless else "pinned-usb-ssh",
                       "orientation": orientation, "powerState": power,
                       "captureLabel": label, "reportDirectory": report_name,
                       "reportManifestSha256": manifest_sha,
                       "runnerSha256": RUNNER_SHA, "monitorSourceSha256": MONITOR_SHA,
                       "monitorBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                       "monitorOutputSha256": hashlib.sha256(data).hexdigest(),
                       "probeStartedAfterReadyMilliseconds": (start-ready_observed)//1_000_000,
                       "probeDurationMilliseconds": (finish-start)//1_000_000,
                       "monitorFinishedAfterProbeMilliseconds": (monitor_finished-finish)//1_000_000,
                       "summary": summary}
            if admission:
                binding["profileSet"] = "admission-platform-pair"
            window["publish"](window_dir, staging, data, binding)
            print("U1_PARTIAL_WINDOW accepted " + window_name)
        finally:
            if monitor_fd is not None:
                os.close(monitor_fd)
            stop_child(monitor)
            stop_child(tunnel)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("U1_PARTIAL_WINDOW interrupted monitor-incomplete; preserve any probe reports",
              file=sys.stderr)
        raise SystemExit(130)
    except RuntimeError as error:
        print("U1_PARTIAL_WINDOW rejected " + str(error), file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:
        print("U1_PARTIAL_WINDOW rejected " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
