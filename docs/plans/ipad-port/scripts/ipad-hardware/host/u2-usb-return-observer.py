#!/usr/bin/env python3
"""Passively observe a target iPad's Mac USB return from an absent state.

The first line confirms that the target is absent before a recovery request.
For 20 seconds, `ioreg` snapshots the Mac IOUSB plane. It emits an arrival
when the exact vendor/product first appears. It never opens the iPad, changes
USB state, or contacts the iPad. A later full checker proves function health.
"""

import json
import re
import subprocess
import sys
import time


def sample(vendor, product):
    result = subprocess.run(["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("IORegistry unavailable")
    text = result.stdout.decode("utf-8", "replace")
    devices = text.split("+-o ")
    for device in devices[1:]:
        v = re.search(r'"idVendor"\s*=\s*(\d+)', device)
        p = re.search(r'"idProduct"\s*=\s*(\d+)', device)
        if v and p and int(v[1]) == vendor and int(p[1]) == product:
            return True
    return False


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def main():
    if len(sys.argv) != 4:
        raise ValueError("fixed target and window required")
    vendor, product, seconds = (int(value, 0) for value in sys.argv[1:])
    if not (0 < vendor <= 65535 and 0 < product <= 65535 and seconds == 20):
        raise ValueError("invalid observer input")
    if sample(vendor, product):
        raise ValueError("target already present")
    emit({"type": "ready", "target": {"vendorID": f"0x{vendor:04x}",
                                      "productID": f"0x{product:04x}"},
          "windowSeconds": seconds, "initial": "absent"})
    start = time.monotonic()
    previous = False
    events = 0
    while time.monotonic() - start < seconds:
        present = sample(vendor, product)
        if present != previous:
            emit({"type": "event", "kind": "arrived" if present else "terminated",
                  "elapsedMilliseconds": int((time.monotonic() - start) * 1000)})
            events += 1
        previous = present
        time.sleep(0.25)
    emit({"type": "summary", "windowCompleted": True, "eventCount": events,
          "targetPresent": previous})


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        emit({"type": "error", "reason": "observer-unavailable"})
        raise SystemExit(1)
