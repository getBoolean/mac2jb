#!/usr/bin/env python3
"""Compare private raw Mac USB descriptors with the iPad and IORegistry baseline.

This host-only check reads three ignored owner-only captures. It validates the
entire raw configuration framing, active interface/alternate/endpoint counts,
and the six active alternate-zero interfaces against the independent Mac
IOService tree. It also compares device scalars to the iPad's saved live
description. It sends no USB request, runs no iPad command, and changes no file.
The result is an external baseline for later byte-for-byte restoration checks;
it is not evidence that a controller publication or restore has worked.
"""

import base64
import json
from pathlib import Path
import plistlib
import stat


ROOT = Path(__file__).resolve().parents[6]
BASE = ROOT / "build/ipad-hardware/u2-baseline"
SCALARS = (
    ("idVendor", "vendorID"), ("idProduct", "productID"),
    ("bcdUSB", "BcdUSBVersion"), ("bcdDevice", "deviceID"),
    ("bDeviceClass", "deviceClass"),
    ("bDeviceSubClass", "deviceSubClass"),
    ("bDeviceProtocol", "deviceProtocol"),
    ("bMaxPacketSize0", "MPS0"),
)
INTERFACE_FIELDS = (
    ("bInterfaceNumber", 2), ("bAlternateSetting", 3),
    ("bNumEndpoints", 4), ("bInterfaceClass", 5),
    ("bInterfaceSubClass", 6), ("bInterfaceProtocol", 7),
)


def private(name, maximum):
    path = BASE / name
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= maximum):
        raise ValueError("unsafe private capture")
    return path.read_bytes()


def configurations(envelope):
    if not envelope.startswith(b"U2CFGD1\0") or len(envelope) < 12:
        raise ValueError("raw descriptor envelope")
    count = envelope[8]
    if count != 5:
        raise ValueError("unexpected configuration count")
    offset = 9
    parsed = []
    for number in range(1, count + 1):
        if offset + 2 > len(envelope):
            raise ValueError("truncated length")
        length = int.from_bytes(envelope[offset:offset + 2], "little")
        offset += 2
        if not 9 <= length <= 16384 or offset + length > len(envelope):
            raise ValueError("truncated configuration")
        raw = envelope[offset:offset + length]
        offset += length
        if (raw[0] != 9 or raw[1] != 2 or
                int.from_bytes(raw[2:4], "little") != length or raw[5] != number):
            raise ValueError("invalid configuration header")
        interfaces = []
        endpoints = []
        position = 0
        while position < length:
            size = raw[position]
            if size < 2 or position + size > length:
                raise ValueError("invalid descriptor length")
            item = raw[position:position + size]
            if item[1] == 4:
                if size < 9:
                    raise ValueError("short interface")
                interfaces.append(item)
            elif item[1] == 5:
                if size < 7:
                    raise ValueError("short endpoint")
                endpoints.append(item)
            position += size
        if len({item[2] for item in interfaces}) != raw[4]:
            raise ValueError("interface count mismatch")
        if sum(item[4] for item in interfaces) != len(endpoints):
            raise ValueError("endpoint count mismatch")
        parsed.append((raw, interfaces, endpoints))
    if offset != len(envelope):
        raise ValueError("trailing descriptor bytes")
    return parsed


def main():
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    raw = configurations(private("raw-configs.bin", 128 * 1024))
    baseline = json.loads(private("current.json", 1024 * 1024))
    host = json.loads(private("host-usb-scalars.json", 1024 * 1024))
    tree = json.loads(private("host-interfaces.json", 1024 * 1024))
    live = plistlib.loads(base64.b64decode(
        baseline["snapshot"]["live_b64"], validate=True))
    if (baseline["version"] != 1 or host["version"] != 1 or
            tree["version"] != 1 or
            len(live["ConfigurationDescriptors"]) < 5 or
            any(raw[index][0][4] != len(item["Interfaces"])
                for index, item in enumerate(live["ConfigurationDescriptors"][:5])) or
            host["fields"]["kUSBCurrentConfiguration"] != 5 or
            host["fields"]["bNumConfigurations"] != 5 or
            any(host["fields"][mac] != live[device] for mac, device in SCALARS)):
        raise ValueError("device baseline mismatch")
    active = raw[4]
    if len(active[1]) != 8 or len(active[2]) != 10:
        raise ValueError("active descriptor topology")
    primary = [item for item in active[1] if item[3] == 0]
    host_interfaces = tree["interfaces"]
    if len(primary) != 6 or len(host_interfaces) != 6:
        raise ValueError("active interface count")
    for number, (descriptor, observed) in enumerate(zip(primary, host_interfaces)):
        if (descriptor[2] != number or observed["ordinal"] != number or
                observed["bConfigurationValue"] != 5 or
                any(observed[key] != descriptor[index]
                    for key, index in INTERFACE_FIELDS)):
            raise ValueError("active interface mismatch")
    print("U2_EXTERNAL_BASELINE configurations=5 active-interfaces=6 "
          "active-alternates=8 active-endpoints=10")
    print("U2_EXTERNAL_BASELINE scalars=8-of-8 mac-interfaces=6-of-6 "
          "stock-function-counts=5-of-5")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, json.JSONDecodeError):
        print("U2_EXTERNAL_BASELINE rejected")
        raise SystemExit(1)
