#!/usr/bin/env python3
"""Read-only categorical diagnosis after a guarded U2 no-op trial.

Re-captures each private baseline component independently and reports only
equal/changed/unavailable. This sends no USB request and writes no file. It
does not clear or modify a restore journal. Raw descriptors, identifiers,
network addresses, and controller bytes remain private/in memory.
"""

import json
from pathlib import Path
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
CAPTURES = (
    ("ipad-live-trust", "current.json", "capture-u2-private-baseline.py"),
    ("mac-scalars", "host-usb-scalars.json", "capture-u2-host-usb-scalars.py"),
    ("mac-interfaces", "host-interfaces.json", "capture-u2-host-interfaces.py"),
    ("raw-configs", "raw-configs.bin", "capture-u2-raw-configs.py"),
)


def main():
    for label, name, source in CAPTURES:
        try:
            module = runpy.run_path(str(HOST / source))
            observed = module["capture"]()
            if name == "raw-configs.bin":
                data = observed[0]
            else:
                data = (json.dumps(observed, sort_keys=True,
                                   separators=(",", ":")).encode("ascii") + b"\n")
            state = "equal" if data == (BASE / name).read_bytes() else "changed"
        except (OSError, ValueError, TypeError, KeyError, IndexError,
                subprocess.TimeoutExpired):
            state = "unavailable"
        print("U2_POSTTRIAL " + label + "=" + state)
    try:
        power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
        state = "external" if b"external=yes" in power else "other"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        state = "unavailable"
    print("U2_POSTTRIAL power=" + state)
    try:
        network = runpy.run_path(str(HOST / "check-u2-host-network-function.py"))[
            "capture"]()
        state = "baseline" if network == (0, 0) else "changed"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        state = "unavailable"
    print("U2_POSTTRIAL usb-network-driver=" + state)


if __name__ == "__main__":
    main()
