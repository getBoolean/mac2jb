#!/usr/bin/env python3
"""Exercise the fail-closed live and Mac interface rules of the U2 checker.

These are Mac-only fixtures. They do not contact the iPad or send USB requests.
The full checker is separately run against the real current-boot reference.
"""

import json
from pathlib import Path
import plistlib
import runpy


ROOT = Path(__file__).resolve().parents[6]
CHECK = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/check-u2-recovered-current.py"))


def rejected(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("unsafe U2 comparison accepted")


def main():
    original = {f"field{i}": i for i in range(16)}
    saved = plistlib.dumps(original, fmt=plistlib.FMT_BINARY)
    assert CHECK["live_equals"](saved, saved) == "original"
    with_flag = dict(original, AllowMultipleCreates=True)
    assert CHECK["live_equals"](
        saved, plistlib.dumps(with_flag, fmt=plistlib.FMT_BINARY)) == "original-plus-flag"
    rejected(lambda: CHECK["live_equals"](
        saved, plistlib.dumps(dict(original, AllowMultipleCreates=False),
                              fmt=plistlib.FMT_BINARY)))
    rejected(lambda: CHECK["live_equals"](
        saved, plistlib.dumps(dict(original, unexpected=True),
                              fmt=plistlib.FMT_BINARY)))
    changed = dict(original)
    changed["field7"] = -1
    rejected(lambda: CHECK["live_equals"](
        saved, plistlib.dumps(changed, fmt=plistlib.FMT_BINARY)))

    rows = [{"name": f"interface{i}", "iInterface": i + 1,
             "bAlternateSetting": 0, "bNumEndpoints": 1} for i in range(6)]
    saved_rows = json.dumps({"interfaces": rows}).encode()
    current = {"interfaces": [dict(row) for row in rows]}
    CHECK["host_interfaces"](saved_rows, current)
    current["interfaces"][2]["iInterface"] = 42
    CHECK["host_interfaces"](saved_rows, current)
    current["interfaces"][2]["bAlternateSetting"] = 1
    rejected(lambda: CHECK["host_interfaces"](saved_rows, current))
    current["interfaces"][2]["bAlternateSetting"] = 0
    current["interfaces"][2]["bNumEndpoints"] = 2
    rejected(lambda: CHECK["host_interfaces"](saved_rows, current))
    current["interfaces"][2]["bNumEndpoints"] = 1
    current["interfaces"][2]["name"] = "wrong"
    rejected(lambda: CHECK["host_interfaces"](saved_rows, current))
    print("PASS U2 recovered-current live/interface guards")


if __name__ == "__main__":
    main()
