#!/usr/bin/env python3
"""Capture a twice-stable private external baseline for auto-heal trials on the current boot.

Effect: read-only on the iPad. Requires no active journal. The live
description must equal the stock 16-field original (taken from the last stock
baseline, build/ipad-hardware/u2-v4-repeat-baseline/) or that original plus
the known `AllowMultipleCreates=true` flag. The baseline stores the 16-field
stock original as its reference live description, with this boot's identity
and freshly captured external state (raw configurations, resolved strings,
host interfaces, device scalars, NCM driver binding and packet reply, power).
The capture runs twice and must match. Writes only the new owner-only
build/ipad-hardware/u2-v9-trial-baseline/ and prints its manifest SHA-256.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BUILD = ROOT / "build/ipad-hardware"
STOCK = BUILD / "u2-v4-repeat-baseline"
OUT = BUILD / "u2-v9-trial-baseline"
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))


def snapshot():
    """Run the pinned device snapshot, accepting the 17-field post-publication shape.

    The Mac then requires the extra field to be exactly AllowMultipleCreates=true
    (checker live_equals), so no other drift is accepted.
    """
    base = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))
    source = base["SOURCE"].read_bytes()
    if hashlib.sha256(source).hexdigest() != base["SOURCE_SHA256"]:
        raise ValueError("snapshot source changed")
    text = source.decode("ascii")
    if text.count("len(decoded) != 16") != 1:
        raise ValueError("snapshot source shape check moved")
    text = text.replace("len(decoded) != 16", "len(decoded) not in (16, 17)")
    payload = ("import base64,json\nm={'__name__':'u2_target_snapshot'}\n"
               "exec(compile(" + repr(text) + ",'u2_target_snapshot.py','exec'),m)\n"
               "identity,live=m['capture']()\n"
               "print(json.dumps({'identity':identity,'live_b64':base64.b64encode(live).decode('ascii')},"
               "sort_keys=True,separators=(',',':')))\n").encode("ascii")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    remote = subprocess.run([*ssh, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"], input=payload,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if remote.returncode:
        raise ValueError("target snapshot unavailable")
    captured = json.loads(remote.stdout)
    identity = captured["identity"]
    if (set(identity) != {"product_type", "os_build", "controller_id", "boot_session", "source_sha256"} or
            identity["product_type"] != "iPad14,5" or identity["os_build"] != "21A329" or
            identity["source_sha256"] != "a0f63c8c2372ebd1ed4e49492344a5c1290c530ae8e5c66d88e9ba481792c5fa"):
        raise ValueError("target identity changed")
    return captured, base["trusted_usb"]()


def capture_once(boot, stock_live, old):
    checker = runpy.run_path(str(HOST / "check-u2-strict-external.py"))
    captured, network_count = snapshot()
    now = captured
    live = base64.b64decode(now["live_b64"], validate=True)
    if now["identity"]["boot_session"] != boot:
        raise ValueError("boot changed")
    shape = checker["live_equals"](stock_live, live)  # original | original-plus-flag
    now["live_b64"] = base64.b64encode(stock_live).decode("ascii")
    current = {"version": 1, "snapshot": now,
               "live_sha256": hashlib.sha256(stock_live).hexdigest(),
               "mac": {"usbmux_count": 1, "network_count": network_count, "same_device": True,
                       "usb_pair_valid": True, "network_pair_valid": True}}
    raw, strings, interfaces, scalars, drivers = checker["capture_external"]()
    if checker["SEMANTIC"]["compare"](old["raw-configs.bin"], old["strings.bin"],
                                       raw, strings)["configurations"] != 5:
        raise ValueError("USB configurations changed")
    checker["host_interfaces"](old["host-interfaces.json"], interfaces)
    canonical = checker["CHECK"]["canonical"]
    if drivers != (1, 4):
        raise ValueError("NCM driver binding missing")
    packet = subprocess.run(["/usr/bin/python3", str(HOST / "probe-u2-ncm-packet-flow.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if packet.returncode or packet.stdout != SUPPORT["PACKET_OK"]:
        raise ValueError("NCM packet flow missing")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in SUPPORT["POWER_OK"]:
        raise ValueError("external power missing")
    SUPPORT["journal_absent"]()
    return shape, {
        "snapshot.json": canonical(current), "raw-configs.bin": raw,
        "host-interfaces.json": canonical(interfaces), "host-usb-scalars.json": canonical(scalars),
        "strings.bin": strings, "power.txt": power,
        "host-network.json": canonical({"ethernet": drivers[0], "ncm_driver": drivers[1]}),
    }


def main():
    if OUT.exists():
        raise ValueError("baseline already exists")
    SUPPORT["journal_absent"]()
    old = {p.name: p.read_bytes() for p in STOCK.iterdir() if p.name != "manifest.json"}
    stock_live = base64.b64decode(json.loads(old["snapshot.json"])["snapshot"]["live_b64"], validate=True)
    boot = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))["read_boot_token"]()
    shape, first = capture_once(boot, stock_live, old)
    _, second = capture_once(boot, stock_live, old)
    if first != second:
        raise ValueError("baseline unstable")
    canonical = runpy.run_path(str(HOST / "check-u2-external-current.py"))["canonical"]
    manifest = canonical({"version": 1, "purpose": "u2-v9-trials", "live_shape_at_capture": shape,
                          "files": {n: hashlib.sha256(d).hexdigest() for n, d in sorted(first.items())}})
    OUT.mkdir(mode=0o700)
    for name, data in list(first.items()) + [("manifest.json", manifest)]:
        fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    print("U2_V9_BASELINE captured=stable live=%s configs=5 ncm=reply" % shape)
    print("U2_V9_BASELINE manifest-sha256=" + hashlib.sha256(manifest).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("U2_V9_BASELINE rejected (%s)" % error)
        raise SystemExit(1)
