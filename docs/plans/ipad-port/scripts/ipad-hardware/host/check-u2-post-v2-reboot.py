#!/usr/bin/env python3
"""Read-only cross-boot recovery comparison after the failed v2 U2 trial.

The retained pretrial reference is verified but its boot token must differ.
This compares the current original live description, all five raw USB
configurations by resolved string value, Mac interfaces/scalars/NCM binding,
one bounded NCM packet reply, USB/network pairing, charging, and the exact
retained v2 journal. It makes no iPad file or controller change. A pass proves
postreboot function recovery, not successful restoration by the failed trial.
"""

import json
from pathlib import Path
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
C = runpy.run_path(str(HOST / "check-u2-recovered-current.py"))
JOURNAL_SHA256 = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"


def main():
    data = C["reference"]()
    old_boot = json.loads(data["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    if C["RECOVERY"]["read_boot_token"]() == old_boot:
        raise ValueError("same boot")
    C["PROBE"]["pinned"](C["PROBE"]["SOURCE"], C["PROBE"]["SOURCE_SHA256"], 32 * 1024)
    C["PROBE"]["pinned"](C["PROBE"]["BINARY"], C["PROBE"]["BINARY_SHA256"], 1024 * 1024)
    C["PROBE"]["connection"]()
    C["PROBE"]["host_usb_ready"]()
    if C["journal"]("awaitingVerification") != JOURNAL_SHA256:
        raise ValueError("v2 journal changed")
    _, live = C["LIVE"]["capture"]()
    import base64
    old_live = base64.b64decode(json.loads(data["snapshot.json"])["snapshot"]["live_b64"],
                                validate=True)
    shape = C["live_equals"](old_live, live)
    if shape != "original":
        raise ValueError("original live description not recovered")
    C["trust"]()
    raw, strings, interfaces, scalars, drivers = C["capture_external"]()
    comparison = C["SEMANTIC"]["compare"](data["raw-configs.bin"],
                                             data["strings.bin"], raw, strings)
    C["host_interfaces"](data["host-interfaces.json"], interfaces)
    if C["CHECK"]["canonical"](scalars) != data["host-usb-scalars.json"]:
        raise ValueError("USB scalars differ")
    saved = json.loads(data["host-network.json"])
    if drivers != (saved["ethernet"], saved["ncm_driver"]):
        raise ValueError("NCM binding differs")
    if drivers != (0, 0):
        packet = subprocess.run(["/usr/bin/python3", str(HOST / "probe-u2-ncm-packet-flow.py")],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
        if packet.returncode or packet.stdout != (
                b"U2_NCM_PACKET peer=one-linklocal echo=reply "
                b"link=active usbmux=one ssh=healthy\n"):
            raise ValueError("NCM packet flow unavailable")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in (
            b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
            b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=yes\n"):
        raise ValueError("charging or full battery unavailable")
    _, second_live = C["LIVE"]["capture"]()
    if second_live != live or C["RECOVERY"]["read_boot_token"]() == old_boot or \
            C["journal"]("awaitingVerification") != JOURNAL_SHA256:
        raise ValueError("recovery state unstable")
    C["PROBE"]["host_usb_ready"]()
    print("U2_POST_V2_REBOOT boot=new live=original configs=" +
          str(comparison["configurations"]) + " resolved-strings=" +
          str(comparison["resolved_references"]) + " renumbered=" +
          str(comparison["renumbered_references"]) +
          " interfaces=equal scalars=equal network-binding=equal "
          "network-packet=reply usbmux=one pairing=valid power=charging-or-full "
          "journal=retained-exact")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_POST_V2_REBOOT rejected; journal retained")
        raise SystemExit(1)
