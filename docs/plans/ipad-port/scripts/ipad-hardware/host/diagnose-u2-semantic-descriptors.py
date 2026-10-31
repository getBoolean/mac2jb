#!/usr/bin/env python3
"""Compare U2 Mac USB observations without sending a USB request.

The existing pinned IOUSBLib helper reads configuration descriptors without
USBDeviceOpen. IORegistry supplies active-interface properties. This program
reads the private pre-trial baseline and prints only categorical differences.
String-index changes are reported separately because equal descriptor bytes
outside an index do not prove the referenced string values are equal.
It does not write a file, call the iPad, or confirm/clear the restore journal.
"""

import hashlib
import json
from pathlib import Path
import runpy
import stat


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
RAW_SHA256 = "bffeea0b79d6c571b0164b2a2b84f8939148e45b51a63591cb0ad2bec15a599f"
INTERFACES_SHA256 = "226d9551f3f65a28213b1b0c1888414b9760fea7da9ed6d25942731ff4c0b8c5"


def private(name, expected, maximum):
    directory = BASE.lstat()
    info = (BASE / name).lstat()
    if (not stat.S_ISDIR(directory.st_mode) or
            stat.S_IMODE(directory.st_mode) != 0o700 or
            not stat.S_ISREG(info.st_mode) or
            stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_size > maximum):
        raise ValueError("unsafe private baseline")
    data = (BASE / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("baseline digest changed")
    return data


def configurations(data):
    if not data.startswith(b"U2CFGD1\0") or len(data) < 10:
        raise ValueError("invalid raw envelope")
    count = data[8]
    position = 9
    result = []
    for _ in range(count):
        if position + 2 > len(data):
            raise ValueError("short configuration length")
        size = int.from_bytes(data[position:position + 2], "little")
        position += 2
        raw = data[position:position + size]
        if len(raw) != size or size < 9 or raw[1] != 2 or raw[2:4] != size.to_bytes(2, "little"):
            raise ValueError("invalid configuration")
        result.append(raw)
        position += size
    if position != len(data) or count != 5:
        raise ValueError("configuration count/framing changed")
    return result


def descriptors(raw):
    result = []
    position = 0
    while position < len(raw):
        size = raw[position]
        if size < 2 or position + size > len(raw):
            raise ValueError("invalid descriptor framing")
        result.append(raw[position:position + size])
        position += size
    return result


def difference(before, after):
    if len(before) != len(after):
        return "framing-changed", 0, 0
    indexes = nonindexes = 0
    for old, new in zip(before, after):
        if len(old) != len(new) or old[1] != new[1]:
            return "framing-changed", indexes, nonindexes
        permitted = {8} if old[1] == 4 and len(old) >= 9 else set()
        if old[1] == 0x24 and len(old) >= 4 and old[2] == new[2] == 0x0F:
            permitted = {3}
        for offset, (left, right) in enumerate(zip(old, new)):
            if left == right:
                continue
            if offset in permitted and left and right:
                indexes += 1
            else:
                nonindexes += 1
    return "same-framing", indexes, nonindexes


def main():
    raw_capture = runpy.run_path(str(HOST / "capture-u2-raw-configs.py"))["capture"]
    interface_capture = runpy.run_path(str(HOST / "capture-u2-host-interfaces.py"))["capture"]
    previous = configurations(private("raw-configs.bin", RAW_SHA256, 128 * 1024))
    current = configurations(raw_capture()[0])
    changed_configs = indexes = nonindexes = 0
    framing = "same-framing"
    for old, new in zip(previous, current):
        state, index_count, other_count = difference(descriptors(old), descriptors(new))
        changed_configs += old != new
        indexes += index_count
        nonindexes += other_count
        if state != "same-framing":
            framing = state
    before_interfaces = json.loads(private("host-interfaces.json", INTERFACES_SHA256, 1024 * 1024))
    after_interfaces = interface_capture()
    old_rows = before_interfaces["interfaces"]
    new_rows = after_interfaces["interfaces"]
    if len(old_rows) != len(new_rows) or len(old_rows) != 6:
        raise ValueError("active interface count changed")
    name_changes = index_changes = alternate_changes = other_changes = 0
    other_fields = {}
    for old, new in zip(old_rows, new_rows):
        name_changes += old["name"] != new["name"]
        index_changes += old["iInterface"] != new["iInterface"]
        alternate_changes += old["bAlternateSetting"] != new["bAlternateSetting"]
        changed = [key for key in old if key not in
                   ("name", "iInterface", "bAlternateSetting") and old[key] != new[key]]
        other_changes += bool(changed)
        for key in changed:
            other_fields[key] = other_fields.get(key, 0) + 1
    print(f"U2_SEMANTIC raw-framing={framing} changed-configs={changed_configs} "
          f"string-index-bytes={indexes} other-bytes={nonindexes}")
    print(f"U2_SEMANTIC host-name-changes={name_changes} "
          f"host-index-changes={index_changes} "
          f"host-alternate-changes={alternate_changes} "
          f"host-other-changes={other_changes}")
    print("U2_SEMANTIC host-other-fields=" +
          (",".join(f"{key}:{count}" for key, count in sorted(other_fields.items()))
           if other_fields else "none"))
    print("U2_SEMANTIC string-values=unverified journal=unchanged")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("U2_SEMANTIC unavailable")
        raise SystemExit(1)
