#!/usr/bin/env python3
"""Capture private Mac IOUSB device scalars for the U2 before/after comparison.

This host-only program reads the one connected iPad's IORegistry properties,
selects fixed USB descriptor scalar fields, and saves them mode 0600 under
the ignored U2 baseline directory. It does not open a USB user client,
request a descriptor, run an iPad command, or modify the USB connection.
Interface/function descriptors are not exposed by this view and remain a
separate U2 gate.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
DIAGNOSTIC = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/diagnose-usb-recognition.py"
DESTINATION = ROOT / "build/ipad-hardware/u2-baseline"
TARGET = DESTINATION / "host-usb-scalars.json"
FIELDS = (
    "idVendor", "idProduct", "bcdUSB", "bcdDevice", "bDeviceClass",
    "bDeviceSubClass", "bDeviceProtocol", "bMaxPacketSize0",
    "bNumConfigurations", "kUSBCurrentConfiguration",
)


def capture():
    diagnostic = runpy.run_path(str(DIAGNOSTIC))
    result = subprocess.run(["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("IOUSB query failed")
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    if sum("+-o iPad@" in line for line in lines) != 1:
        raise ValueError("ambiguous iPad")
    subtree = diagnostic["first_ipad_subtree"](lines)
    if not subtree:
        raise ValueError("iPad absent")
    fields = {}
    for name in FIELDS:
        pattern = re.compile(r'"'+re.escape(name)+r'"\s*=\s*(\d+)')
        values = [match.group(1) for line in subtree
                  if (match := pattern.search(line))]
        if len(values) != 1:
            raise ValueError("missing or duplicate host field")
        fields[name] = int(values[0])
    if fields["kUSBCurrentConfiguration"] != 5 or fields["bNumConfigurations"] != 5:
        raise ValueError("unexpected host configuration")
    return {"version": 1, "fields": fields}


def main():
    report = capture()
    if not DESTINATION.is_dir() or stat.S_IMODE(DESTINATION.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    data = json.dumps(report,
                      sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short host capture")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print("U2_HOST_SCALARS fields=10 configuration=5")
    print("U2_HOST_SCALARS evidence-sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_HOST_SCALARS rejected")
        raise SystemExit(1)
