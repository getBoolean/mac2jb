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
WINDOW_SECONDS = 20
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


def arm_monitor(binary, vendor, product):
    process = subprocess.Popen(
        [str(binary), f"0x{vendor:04x}", f"0x{product:04x}", str(WINDOW_SECONDS)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        available, _, _ = select.select([process.stdout], [], [], 8)
        ready = process.stdout.readline() if available else b""
        record = json.loads(ready)
        if (record.get("type") != "ready" or record.get("windowSeconds") != WINDOW_SECONDS or
                record.get("target", {}).get("vendorID") != f"0x{vendor:04x}" or
                record.get("target", {}).get("productID") != f"0x{product:04x}"):
            raise ValueError("monitor target not ready")
        return process, ready
    except BaseException:
        process.kill()
        process.communicate(timeout=3)
        raise
