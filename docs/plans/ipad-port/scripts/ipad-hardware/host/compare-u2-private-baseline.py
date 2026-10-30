#!/usr/bin/env python3
"""Compare the private U2 iPad live description with Mac USB device scalars.

This host-only tool reads two ignored owner-only captures and prints only a
redacted verdict. It verifies eight directly comparable scalar fields, the
current Mac configuration number, and the saved trust categories. It does
not claim host-side interface/function descriptor equivalence, and it makes
no iPad or Mac USB request or file write.
"""

import base64
import hashlib
import json
from pathlib import Path
import plistlib
import stat


ROOT = Path(__file__).resolve().parents[6]
BASE = ROOT / "build/ipad-hardware/u2-baseline"
MAPPING = (
    ("idVendor", "vendorID"), ("idProduct", "productID"),
    ("bcdUSB", "BcdUSBVersion"), ("bcdDevice", "deviceID"),
    ("bDeviceClass", "deviceClass"), ("bDeviceSubClass", "deviceSubClass"),
    ("bDeviceProtocol", "deviceProtocol"), ("bMaxPacketSize0", "MPS0"),
)


def private_json(name):
    path = BASE / name
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024):
        raise ValueError("unsafe private capture")
    data = path.read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def main():
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    baseline, baseline_hash = private_json("current.json")
    host, host_hash = private_json("host-usb-scalars.json")
    live = plistlib.loads(base64.b64decode(
        baseline["snapshot"]["live_b64"], validate=True))
    fields = host["fields"]
    mac = baseline["mac"]
    if (baseline["version"] != 1 or host["version"] != 1 or
            set(mac) != {"usbmux_count", "network_count", "same_device",
                         "usb_pair_valid", "network_pair_valid"} or
            mac["usbmux_count"] != 1 or
            type(mac["network_count"]) is not int or mac["network_count"] < 1 or
            mac["same_device"] is not True or
            mac["usb_pair_valid"] is not True or
            mac["network_pair_valid"] is not True or
            fields["kUSBCurrentConfiguration"] != 5 or
            fields["bNumConfigurations"] != 5 or
            not isinstance(live, dict) or len(live) != 16):
        raise ValueError("baseline shape")
    equal = all(fields[host_key] == live[ipad_key] for host_key, ipad_key in MAPPING)
    print("U2_BASELINE_COMPARE scalars=" + ("8-of-8" if equal else "mismatch") +
          " usbmux=one trust=valid functions=not-captured")
    print("U2_BASELINE_COMPARE private-hashes=" + baseline_hash[:12] + "," +
          host_hash[:12])
    if not equal:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, plistlib.InvalidFileException):
        print("U2_BASELINE_COMPARE rejected")
        raise SystemExit(1)
