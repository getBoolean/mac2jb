"""Shared helpers for the current U2 host tools (no device writes here).

Effect: pinned root SSH command construction, owner-only evidence writes, the
passive Mac USB lifecycle monitor (compiled from u2-usb-lifecycle-monitor.swift),
and read-only checks for Mac USB presence and the broker journal phase.
"""

import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys

HOST = Path(__file__).resolve().parent
MONITOR = HOST / "u2-usb-lifecycle-monitor.swift"
# The short window, for a probe batch that does not take the device off bus.
WINDOW_SECONDS = 20
# The window a description-changing trial needs. The device is measured at
# 29-72 s to come back on bus after a description change, so a 20 s window
# always closed before the earliest return and reported `terminated` then
# `missing-at-window-end` - the absence, never the reattach. A trial can cycle
# the bus twice (the publication's own cycle and the explicit re-enumeration
# cycle), so the window has to outlast 2 x 72 s of reattach plus the 30 s lease
# ceiling, the report deadline and the registry read: about 264 s. 300 s covers
# that with margin and stays inside the monitor's own 1...600 s limit. The
# monitor buffers its events and emits them when the window ends, so it is left
# to run the window out rather than being cut short.
TRIAL_WINDOW_SECONDS = 300
PACKET_OK = (b"U2_NCM_PACKET peer=one-linklocal echo=reply "
             b"link=active usbmux=one ssh=healthy\n")
POWER_OK = {
    b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
    b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
    b"POWER_SOURCE query=ok external=yes charging=no full=yes\n",
}


def ssh():
    return runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private evidence write")
        os.fsync(fd)
    finally:
        os.close(fd)


def usb_present():
    """One USBMux device on the Mac (device-agnostic)."""
    result = subprocess.run([sys.executable, str(HOST / "diagnose-usb-recognition.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    return result.returncode == 0 and b"USBMUX query=ok count=1\n" in result.stdout


def journal_absent():
    result = subprocess.run([sys.executable, str(HOST / "read-u2-journal-state-wifi.py"),
                             "--native-journal"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or result.stdout != b"U2_NATIVE_JOURNAL phase=absent sha256=none\n":
        raise ValueError("active journal or journal status unavailable")


def monitor_binary(temporary):
    binary = Path(temporary) / "u2-usb-observer"
    result = subprocess.run(
        ["/usr/bin/xcrun", "swiftc", str(MONITOR), "-o", str(binary)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
        env=dict(os.environ, CLANG_MODULE_CACHE_PATH=str(Path(temporary) / "clang"),
                 SWIFT_MODULE_CACHE_PATH=str(Path(temporary) / "swift")))
    if result.returncode != 0 or not binary.is_file():
        raise ValueError("passive monitor compile failed")
    return binary


def arm_monitor(binary, vendor, product, window=WINDOW_SECONDS):
    """Arm the passive monitor for `window` seconds and check the ready record.

    The window is a parameter because a trial that changes the description has
    to outlast the device's reattach, while a probe batch that never leaves the
    bus does not; the ready record is checked against the window that was
    asked for, so a monitor armed for the wrong one is refused rather than
    silently measuring a shorter period than the caller believes.
    """
    process = subprocess.Popen(
        [str(binary), f"0x{vendor:04x}", f"0x{product:04x}", str(window)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        available, _, _ = select.select([process.stdout], [], [], 8)
        ready = process.stdout.readline() if available else b""
        record = json.loads(ready)
        if (record.get("type") != "ready" or record.get("windowSeconds") != window or
                record.get("target", {}).get("vendorID") != f"0x{vendor:04x}" or
                record.get("target", {}).get("productID") != f"0x{product:04x}"):
            raise ValueError("monitor target not ready")
        return process, ready
    except BaseException:
        process.kill()
        process.communicate(timeout=3)
        raise
