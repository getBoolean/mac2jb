#!/usr/bin/env python3
"""Check the private U1 restore candidate against stock source and Mac USB state.

This Mac-only verifier reads the two captured controller description plists,
the stock configuration copy, and the current IOUSB registry. It requires the
default fields to match live, one exact stock configuration-list match, and
nine live USB fields to match the independently attached Mac host. It prints
only a fixed categorical result; private strings and IDs remain in memory.
It makes no iPad request or file change. This does not test publication.
"""

import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess


BUILD = Path(__file__).resolve().parents[6] / "build/ipad-hardware"
DESC_DIR = BUILD / "controller-descriptions"
STOCK_DIR = BUILD / "stock-configuration"
LIMIT = 16 * 1024 * 1024


def private_file(path, limit):
    parent = path.parent.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or
            stat.S_IMODE(parent.st_mode) != 0o700 or
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
            not 8 <= info.st_size <= limit):
        raise ValueError("unsafe private input")
    data = path.read_bytes()
    if len(data) != info.st_size:
        raise ValueError("private input changed")
    value = plistlib.loads(data)
    if not isinstance(value, dict):
        raise ValueError("unexpected plist root")
    return value


def host_properties():
    result = subprocess.run(["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w0"],
                            capture_output=True, timeout=15)
    if result.returncode != 0 or len(result.stdout) > LIMIT:
        raise ValueError("host registry unavailable")
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    candidates = []
    for index, line in enumerate(lines):
        if "+-o " in line and "iPad" in line.split("+-o ", 1)[1].split("  <", 1)[0]:
            end = index + 1
            while end < len(lines) and "+-o " not in lines[end]:
                end += 1
            candidates.append(lines[index + 1:end])
    if len(candidates) != 1:
        raise ValueError("ambiguous host target")
    return candidates[0]


def property_value(lines, key, quoted):
    pattern = re.compile(r'"' + re.escape(key) + r'"\s*=\s*' +
                         (r'"([^"\n]*)"' if quoted else r'(\d+)'))
    values = [match.group(1) for line in lines if (match := pattern.search(line))]
    if len(values) != 1:
        raise ValueError("missing or ambiguous host field")
    return values[0] if quoted else int(values[0])


def main():
    default = private_file(DESC_DIR / "default.bplist", 512 * 1024)
    live = private_file(DESC_DIR / "live.bplist", 512 * 1024)
    stock = private_file(STOCK_DIR / "USBDeviceConfiguration.plist", 2 * 1024 * 1024)
    if len(default) != 11 or len(live) != 16 or any(live.get(k) != v for k, v in default.items()):
        raise ValueError("default/live relationship changed")
    if len(stock) != 1:
        raise ValueError("unexpected stock root")
    groups = next(iter(stock.values()))
    configs = live.get("ConfigurationDescriptors")
    if not isinstance(groups, dict) or not isinstance(configs, list) or len(configs) != 9:
        raise ValueError("unexpected configuration structure")
    if sum(configs == group for group in groups.values()) != 1:
        raise ValueError("stock configuration not unique")
    lines = host_properties()
    numeric = (
        ("vendorID", "idVendor"), ("productID", "idProduct"),
        ("deviceClass", "bDeviceClass"), ("deviceSubClass", "bDeviceSubClass"),
        ("deviceProtocol", "bDeviceProtocol"), ("MPS0", "bMaxPacketSize0"),
        ("BcdUSBVersion", "bcdUSB"),
    )
    strings = (("productString", "USB Product Name"),
               ("manufacturerString", "USB Vendor Name"))
    if any(live.get(a) != property_value(lines, b, False) for a, b in numeric):
        raise ValueError("host numeric mismatch")
    if any(live.get(a) != property_value(lines, b, True) for a, b in strings):
        raise ValueError("host string mismatch")
    print("DESCRIPTION_CANDIDATE default-subset=yes stock-list=unique host-fields=9-of-9")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("DESCRIPTION_CANDIDATE rejected")
        raise SystemExit(1)
