#!/usr/bin/env python3
"""Capture a stable private current-boot baseline for U2 v5 fault trials.

The read-only capture requires the exact idle v5 stage, absent active journal,
the observed 17-field live description with only the known replacement flag,
all five configurations semantically equal to the v4 pretrial reference,
stable host interfaces/scalars/NCM packet flow, pairing, and power. It
captures twice and writes only eight ignored owner-only Mac files. This is a
reference, not proof that a v5 controller trial will restore the iPad.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
DEST = ROOT / "build/ipad-hardware/u2-v5-baseline"
C = runpy.run_path(str(HOST / "check-u2-v4-current.py"))


def command(args, limit=512, timeout=20):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout)
    if result.returncode or len(result.stdout) > limit:
        raise ValueError("baseline precondition unavailable")
    return result.stdout


def preconditions():
    if DEST.exists() or DEST.is_symlink():
        raise ValueError("v5 baseline already exists")
    if C["journal"]("absent") != "none":
        raise ValueError("active journal present")
    if command(["/usr/bin/python3", str(
            HOST / "check-u2-v5-service-wifi.py")]) != (
            b"U2_TRIAL_V5 job=loaded running=yes binary=exact plist=exact "
            b"socket=responding phase=absent publication=enabled archives=retained\n"):
        raise ValueError("v5 trial service changed")
    if command(["/usr/bin/python3", str(
            HOST / "check-u2-three-archives-wifi.py")]) != (
            b"U2_ARCHIVES_THREE first=exact v2=exact v3=exact active=absent\n"):
        raise ValueError("old trial archives changed")
    if command(["/usr/bin/python3", str(
            HOST / "check-u2-v5-service-wifi.py"), "--validate-only"]) != (
            b"U2_TRIAL_V5 clone=in-memory-valid journal=absent archives=retained\n"):
        raise ValueError("current controller clone unavailable")
    C["PROBE"]["pinned"](C["PROBE"]["SOURCE"], C["PROBE"]["SOURCE_SHA256"], 32 * 1024)
    C["PROBE"]["pinned"](C["PROBE"]["BINARY"], C["PROBE"]["BINARY_SHA256"], 1024 * 1024)
    C["PROBE"]["connection"]()
    C["PROBE"]["host_usb_ready"]()


def capture():
    reference = C["reference"]()
    current = json.loads(reference["snapshot.json"])
    old = dict(current["snapshot"])
    _, live = C["LIVE"]["capture"]()
    current["snapshot"]["live_b64"] = base64.b64encode(live).decode("ascii")
    current["live_sha256"] = hashlib.sha256(live).hexdigest()
    now = current["snapshot"]
    if (now["identity"]["boot_session"] != old["identity"]["boot_session"] or
            any(now["identity"][key] != old["identity"][key]
                for key in ("product_type", "os_build", "source_sha256")) or
            C["live_equals"](base64.b64decode(old["live_b64"], validate=True),
                              base64.b64decode(now["live_b64"], validate=True)) != "original-plus-flag"):
        raise ValueError("current boot or live description changed")
    raw, strings, interfaces, scalars, drivers = C["capture_external"]()
    comparison = C["SEMANTIC"]["compare"](reference["raw-configs.bin"],
                                             reference["strings.bin"], raw, strings)
    if comparison["configurations"] != 5:
        raise ValueError("configuration count changed")
    C["host_interfaces"](reference["host-interfaces.json"], interfaces)
    C["trust"]()
    if C["CHECK"]["canonical"](scalars) != reference["host-usb-scalars.json"]:
        raise ValueError("USB device scalars changed")
    prior_drivers = json.loads(reference["host-network.json"])
    if drivers != (prior_drivers["ethernet"], prior_drivers["ncm_driver"]):
        raise ValueError("NCM driver binding changed")
    if drivers != (1, 4):
        raise ValueError("NCM reference unexpectedly absent")
    packet = command(["/usr/bin/python3", str(
        HOST / "probe-u2-ncm-packet-flow.py")], limit=256)
    if packet != (b"U2_NCM_PACKET peer=one-linklocal echo=reply "
                  b"link=active usbmux=one ssh=healthy\n"):
        raise ValueError("NCM packet flow unavailable")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in (
            b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
            b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=yes\n"):
        raise ValueError("charging or full battery unavailable")
    if C["RECOVERY"]["read_boot_token"]() != now["identity"]["boot_session"] or \
            C["journal"]("absent") != "none":
        raise ValueError("boot or journal changed during capture")
    C["PROBE"]["host_usb_ready"]()
    return {
        "snapshot.json": C["CHECK"]["canonical"](current),
        "raw-configs.bin": raw,
        "host-interfaces.json": C["CHECK"]["canonical"](interfaces),
        "host-usb-scalars.json": C["CHECK"]["canonical"](scalars),
        "strings.bin": strings,
        "power.txt": power,
        "host-network.json": C["CHECK"]["canonical"]({
            "ethernet": drivers[0], "ncm_driver": drivers[1]}),
    }


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private baseline write")
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    preconditions()
    first = capture()
    preconditions()
    if first != capture():
        raise ValueError("v5 baseline unstable")
    preconditions()
    manifest = C["CHECK"]["canonical"]({
        "version": 1,
        "status": "current-boot-reference-only",
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(first.items())},
        "prior_v4_receipt_sha256":
            "50f1f47d0df80d2789e157990cbffc289eb1c0aeb055853db3492128626904ad",
    })
    os.mkdir(DEST, 0o700)
    for name, data in first.items():
        exclusive(DEST / name, data)
    exclusive(DEST / "manifest.json", manifest)
    fd = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print("U2_V5_BASELINE captured=stable files=8 "
          "journal=absent network-packet=reply proof=reference-only")
    print("U2_V5_BASELINE manifest-sha256=" + hashlib.sha256(manifest).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V5_BASELINE rejected; inspect private output")
        raise SystemExit(1)
