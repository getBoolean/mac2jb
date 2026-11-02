#!/usr/bin/env python3
"""Capture the Mac-visible iPad USB interface descriptor tree privately.

This host-only read reads IOService properties already published by macOS
after enumeration. It records ordered interface names, class/subclass,
protocol, alternate setting, configuration, interface number, and endpoint
count for the active configuration. The ignored mode-0600 capture can be
compared before and after a future restore without opening an exclusive USB
user client or sending a USB request. It is still not a raw endpoint-byte
or packet-level capture, and the gate must retain that limit.
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
BASE = ROOT / "build/ipad-hardware/u2-baseline"
TARGET = BASE / "host-interfaces.json"
FIELDS = (
    "iInterface", "bInterfaceProtocol", "bAlternateSetting",
    "bInterfaceClass", "bInterfaceSubClass", "bInterfaceNumber",
    "bConfigurationValue", "bNumEndpoints",
)


def capture():
    diagnostic = runpy.run_path(str(DIAGNOSTIC))
    result = subprocess.run(["/usr/sbin/ioreg", "-p", "IOService", "-l", "-w0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("IOService query failed")
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    if sum("+-o iPad@" in line for line in lines) != 1:
        raise ValueError("ambiguous iPad")
    subtree = diagnostic["first_ipad_subtree"](lines)
    interfaces = []
    for index, line in enumerate(subtree):
        marker = re.search(r"\+-o (.+)@(\d+)  <class IOUSBHostInterface,", line)
        if not marker:
            continue
        depth = len(line.split("+-o ", 1)[0])
        properties = {}
        for child in subtree[index + 1:]:
            if "+-o " in child and len(child.split("+-o ", 1)[0]) <= depth:
                break
            if "+-o " in child:
                break
            for field in FIELDS:
                match = re.search(r'"' + re.escape(field) + r'"\s*=\s*(\d+)', child)
                if match:
                    if field in properties:
                        raise ValueError("duplicate interface field")
                    properties[field] = int(match.group(1))
        if set(properties) != set(FIELDS):
            raise ValueError("missing interface field")
        interfaces.append({
            "name": marker.group(1), "ordinal": int(marker.group(2)),
            **properties,
        })
    if len(interfaces) != 6 or [item["ordinal"] for item in interfaces] != list(range(6)):
        raise ValueError("unexpected interface topology")
    if any(item["bConfigurationValue"] != 5 or
           item["bInterfaceNumber"] != index for index, item in enumerate(interfaces)):
        raise ValueError("unexpected active configuration")
    return {"version": 1, "interfaces": interfaces}


def main():
    report = capture()
    if not BASE.is_dir() or stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    data = json.dumps(report,
                      sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short host interface capture")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print("U2_HOST_INTERFACES count=6 configuration=5")
    print("U2_HOST_INTERFACES evidence-sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_HOST_INTERFACES rejected")
        raise SystemExit(1)
