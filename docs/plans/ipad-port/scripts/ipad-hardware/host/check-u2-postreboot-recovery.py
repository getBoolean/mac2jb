#!/usr/bin/env python3
"""Read-only stock-state check after an owner-assisted iPad reboot.

Requires a *new* boot session, the pinned original U2 baseline, an equal live
16-field description, equal Mac raw descriptors/interfaces/scalars, USBMux and
network pairing, external power, and the pre-existing unresolved journal.
It never writes a receipt, clears a journal, starts a service, or sends a USB
request. A pass is evidence for recovery analysis, not authorization to
delete the old-boot journal or resume descriptor publication.
"""

import base64
import json
from pathlib import Path
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
CHECK = runpy.run_path(str(HOST / "check-u2-external-current.py"))
EXPECTED_JOURNAL = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"


def main():
    previous = json.loads(CHECK["private"]("current.json"))
    current = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))["capture"]()
    old = previous["snapshot"]
    new = current["snapshot"]
    old_identity = old["identity"]
    new_identity = new["identity"]
    if (current["version"] != previous["version"] or
            current["mac"] != previous["mac"] or
            current["live_sha256"] != previous["live_sha256"] or
            base64.b64decode(new["live_b64"], validate=True) !=
            base64.b64decode(old["live_b64"], validate=True) or
            any(new_identity[key] != old_identity[key] for key in
                ("product_type", "os_build", "source_sha256")) or
            new_identity["boot_session"] == old_identity["boot_session"]):
        raise ValueError("new boot stock description/trust mismatch")
    for name, source in CHECK["CAPTURES"].items():
        if name == "current.json":
            continue
        result = runpy.run_path(str(HOST / source))["capture"]()
        data = result[0] if name == "raw-configs.bin" else CHECK["canonical"](result)
        if data != CHECK["private"](name):
            raise ValueError("Mac external descriptors differ")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in (
            b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
            b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=yes\n"):
        raise ValueError("external power unavailable")
    if runpy.run_path(str(HOST / "check-u2-host-network-function.py"))["capture"]() != (0, 0):
        raise ValueError("host network binding differs")
    journal = subprocess.run(
        ["/usr/bin/python3", str(HOST / "run-u2-readonly-default-description-wifi.py"),
         "--native-journal"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20)
    if (journal.returncode != 0 or
            journal.stdout != ("U2_NATIVE_JOURNAL phase=restoring sha256=" +
                               EXPECTED_JOURNAL + "\n").encode("ascii")):
        raise ValueError("old-boot journal changed")
    print("U2_POSTREBOOT new-boot=yes live=original raw-configs=byte-equal "
          "host-interfaces=equal usb-scalars=equal usbmux=one trust=valid "
          "power=external usb-network-driver=absent old-journal=retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_POSTREBOOT rejected")
        raise SystemExit(1)
