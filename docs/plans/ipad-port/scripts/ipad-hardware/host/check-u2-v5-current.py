#!/usr/bin/env python3
"""Compare the current iPad/Mac USB state with the v5 pretrial reference.

This read-only checker accepts the journal phase named by its fixed CLI mode.
It verifies the pinned private reference, same boot, original live description
with the same observed AllowMultipleCreates flag, all five raw configurations
by resolved UTF-16LE string values, device scalars, active Mac interface
properties, NCM driver binding, USB/network pairing, and external power. If
NCM is bound, a separate bounded probe sends one ICMPv6 echo to the existing
unique link-local neighbor and requires a reply. It re-reads live/raw/strings
to reject a changing connection. It opens no USB device exclusively, writes
no file, and never confirms a journal. A pass is one component of U2 recovery,
not by itself a fault-trial result.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-v5-baseline"
MANIFEST_SHA256 = "822e20a0884aa88bad418be04b407645e528b030bcb774b3d6fbe634d8fb1a44"
PROBE = runpy.run_path(str(HOST / "probe-u2-readonly-string-descriptors.py"))
SEMANTIC = runpy.run_path(str(HOST / "u2-string-semantics.py"))
RECOVERY = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))
LIVE = runpy.run_path(str(HOST / "diagnose-u2-live-description-wifi.py"))
SNAPSHOT = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))
CHECK = runpy.run_path(str(HOST / "check-u2-external-current.py"))


def reference():
    info = BASE.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe reference directory")
    path = BASE / "manifest.json"
    details = path.lstat()
    manifest_bytes = path.read_bytes()
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
            details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o600 or
            hashlib.sha256(manifest_bytes).hexdigest() != MANIFEST_SHA256):
        raise ValueError("reference manifest changed")
    manifest = json.loads(manifest_bytes)
    names = {"snapshot.json", "raw-configs.bin", "host-interfaces.json",
             "host-usb-scalars.json", "strings.bin", "power.txt",
             "host-network.json"}
    if (manifest.get("version") != 1 or set(manifest.get("files", {})) != names or
            set(item.name for item in BASE.iterdir()) != names | {"manifest.json"}):
        raise ValueError("reference file set changed")
    data = {}
    for name in names:
        file = BASE / name
        details = file.lstat()
        content = file.read_bytes()
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o600 or
                not 0 < len(content) <= 1024 * 1024 or
                hashlib.sha256(content).hexdigest() != manifest["files"][name]):
            raise ValueError("reference file changed")
        data[name] = content
    return data


def journal(phase):
    result = subprocess.run(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--native-journal"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or len(result.stdout) > 128:
        raise ValueError("journal status unavailable")
    expected = ("U2_NATIVE_JOURNAL phase=" + phase + " sha256=").encode("ascii")
    if not result.stdout.startswith(expected):
        raise ValueError("journal phase changed")
    digest = result.stdout[len(expected):].rstrip(b"\n")
    if phase == "absent":
        if digest != b"none" or result.stdout != expected + b"none\n":
            raise ValueError("unexpected active journal")
    elif not re.fullmatch(rb"[0-9a-f]{64}", digest) or result.stdout != expected + digest + b"\n":
        raise ValueError("journal digest unavailable")
    return digest.decode("ascii")


def trust():
    usb = SNAPSHOT["one_device"](["/opt/homebrew/bin/idevice_id", "-l"])
    network = SNAPSHOT["one_device"](["/opt/homebrew/bin/idevice_id", "-n"])
    if usb != network:
        raise ValueError("USB/network identity differs")
    SNAPSHOT["checked"](["/opt/homebrew/bin/idevicepair", "validate"])
    SNAPSHOT["checked"](["/opt/homebrew/bin/idevicepair", "-n", "validate"])


def live_equals(original, observed):
    saved = plistlib.loads(original)
    current = plistlib.loads(observed)
    if (not isinstance(saved, dict) or len(saved) != 17 or
            saved.get("AllowMultipleCreates") is not True or
            not isinstance(current, dict) or len(current) != 17):
        raise ValueError("live description shape")
    if current != saved:
        raise ValueError("live description changed")
    return "pretrial"


def host_interfaces(saved, current):
    old_rows = json.loads(saved)["interfaces"]
    new_rows = current["interfaces"]
    if len(old_rows) != len(new_rows) or len(old_rows) != 6:
        raise ValueError("host interface count changed")
    for old, new in zip(old_rows, new_rows):
        if (set(old) != set(new) or
                any(old[key] != new[key] for key in old if key != "iInterface")):
            raise ValueError("host interface state changed")


def capture_strings():
    result = subprocess.run([str(PROBE["BINARY"]), "--strings"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode or len(result.stdout) > 32 * 1024:
        raise ValueError("USB strings unavailable")
    PROBE["strings"](result.stdout)
    return result.stdout


def capture_external():
    raw = runpy.run_path(str(HOST / "capture-u2-raw-configs.py"))["capture"]()[0]
    strings = capture_strings()
    if runpy.run_path(str(HOST / "capture-u2-raw-configs.py"))["capture"]()[0] != raw:
        raise ValueError("raw USB descriptors unstable")
    interfaces = runpy.run_path(str(HOST / "capture-u2-host-interfaces.py"))["capture"]()
    scalars = runpy.run_path(str(HOST / "capture-u2-host-usb-scalars.py"))["capture"]()
    drivers = runpy.run_path(str(HOST / "check-u2-host-network-function.py"))["capture"]()
    return raw, strings, interfaces, scalars, drivers


def main(phase):
    if phase not in ("absent", "awaitingVerification"):
        raise ValueError("unsupported journal phase")
    data = reference()
    original = base64.b64decode(json.loads(data["snapshot.json"])["snapshot"]["live_b64"],
                                validate=True)
    boot = json.loads(data["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    if RECOVERY["read_boot_token"]() != boot:
        raise ValueError("reference boot changed")
    PROBE["pinned"](PROBE["SOURCE"], PROBE["SOURCE_SHA256"], 32 * 1024)
    PROBE["pinned"](PROBE["BINARY"], PROBE["BINARY_SHA256"], 1024 * 1024)
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    before_journal = journal(phase)
    _, before_live = LIVE["capture"]()
    shape = live_equals(original, before_live)
    trust()
    raw, strings, interfaces, scalars, drivers = capture_external()
    compare = SEMANTIC["compare"](data["raw-configs.bin"], data["strings.bin"],
                                   raw, strings)
    host_interfaces(data["host-interfaces.json"], interfaces)
    if CHECK["canonical"](scalars) != data["host-usb-scalars.json"]:
        raise ValueError("USB device scalars changed")
    saved_drivers = json.loads(data["host-network.json"])
    if drivers != (saved_drivers["ethernet"], saved_drivers["ncm_driver"]):
        raise ValueError("USB network driver binding changed")
    packet = "inactive"
    if drivers != (0, 0):
        result = subprocess.run(["/usr/bin/python3", str(
            HOST / "probe-u2-ncm-packet-flow.py")], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=20)
        if result.returncode or result.stdout != (
                b"U2_NCM_PACKET peer=one-linklocal echo=reply "
                b"link=active usbmux=one ssh=healthy\n"):
            raise ValueError("NCM packet flow unavailable")
        packet = "reply"
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in (
            b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
            b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=yes\n"):
        raise ValueError("charging or full battery unavailable")
    _, after_live = LIVE["capture"]()
    if after_live != before_live or RECOVERY["read_boot_token"]() != boot:
        raise ValueError("iPad live description or boot changed")
    if journal(phase) != before_journal:
        raise ValueError("journal changed during capture")
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    print("U2_V5_CURRENT boot=same live=" + shape +
          " configs=" + str(compare["configurations"]) +
          " resolved-strings=" + str(compare["resolved_references"]) +
          " renumbered=" + str(compare["renumbered_references"]) +
          " interfaces=equal scalars=equal network-binding=equal "
          "network-packet=" + packet +
          " usbmux=one pairing=valid power=charging-or-full journal=" + phase)
    if phase != "absent":
        print("U2_V5_CURRENT journal-sha256=" + before_journal)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or not sys.argv[1].startswith("--expect-journal="):
            raise ValueError("fixed phase selector required")
        main(sys.argv[1].split("=", 1)[1])
    except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError,
            subprocess.TimeoutExpired, plistlib.InvalidFileException):
        print("U2_V5_CURRENT rejected")
        raise SystemExit(1)
