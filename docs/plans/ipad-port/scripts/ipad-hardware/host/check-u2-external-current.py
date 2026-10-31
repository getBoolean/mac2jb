#!/usr/bin/env python3
"""Recheck the live iPad/Mac U2 baseline without changing either device.

This Mac-only tool reuses the pinned Wi-Fi, USBMux/trust, IORegistry, and
nonexclusive IOUSBLib capture routines. It compares each observation with the
four private baseline files, including every raw configuration byte, and
prints only categorical results. It makes no file write and does not send a
USB request. It is a component for future pre/post trial verification, not
by itself proof that a publication or restore took place.
"""

import hashlib
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
HASHES = {
    "current.json": "39afcfbce83334cec6facc72f2bfadc40c0eae30591acd217fd68ad5422f4883",
    "host-usb-scalars.json": "fa2610eebb7abd7b94848f13524936d7a84c3a3c1bb67d66010c4026a3f76218",
    "host-interfaces.json": "226d9551f3f65a28213b1b0c1888414b9760fea7da9ed6d25942731ff4c0b8c5",
    "raw-configs.bin": "bffeea0b79d6c571b0164b2a2b84f8939148e45b51a63591cb0ad2bec15a599f",
}
CAPTURES = {
    "current.json": "capture-u2-private-baseline.py",
    "host-usb-scalars.json": "capture-u2-host-usb-scalars.py",
    "host-interfaces.json": "capture-u2-host-interfaces.py",
    "raw-configs.bin": "capture-u2-raw-configs.py",
}


def private(name):
    path = BASE / name
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024):
        raise ValueError("unsafe baseline")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != HASHES[name]:
        raise ValueError("baseline changed")
    return data


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def main():
    selector = sys.argv[1] if len(sys.argv) == 2 else "--expect-journal=absent"
    if len(sys.argv) > 2 or selector not in (
            "--expect-journal=absent", "--expect-journal=restoring",
            "--expect-journal=awaitingVerification"):
        raise ValueError("invalid journal selector")
    expected_phase = selector.split("=", 1)[1]
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    baseline = {name: private(name) for name in HASHES}
    for name, script in CAPTURES.items():
        module = runpy.run_path(str(HOST / script))
        observation = module["capture"]()
        if name == "raw-configs.bin":
            current = observation[0]
        else:
            current = canonical(observation)
        if current != baseline[name]:
            raise ValueError("external baseline changed")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in (
            b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
            b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=yes\n"):
        raise ValueError("external power or charging unavailable")
    network_driver = runpy.run_path(str(HOST / "check-u2-host-network-function.py"))[
        "capture"]()
    if network_driver != (0, 0):
        raise ValueError("USB network driver differs from baseline")
    journal = subprocess.run(
        ["/usr/bin/python3", str(HOST / "run-u2-readonly-default-description-wifi.py"),
         "--native-journal"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20)
    if journal.returncode != 0 or len(journal.stdout) > 128:
        raise ValueError("journal unavailable")
    words = journal.stdout.decode("ascii").strip().split()
    if (len(words) != 3 or words[0] != "U2_NATIVE_JOURNAL" or
            words[1] != "phase=" + expected_phase or
            not words[2].startswith("sha256=") or
            (expected_phase == "absent" and words[2] != "sha256=none") or
            (expected_phase in ("restoring", "awaitingVerification") and
             (len(words[2]) != 71 or
              any(ch not in "0123456789abcdef" for ch in words[2][7:])))):
        raise ValueError("journal phase changed")
    print("U2_EXTERNAL_CURRENT identity=match raw-configs=byte-equal "
          "host-interfaces=equal usb-scalars=equal usbmux=one "
          "network=one trust=valid power=external charging=or-full "
          "usb-network-driver=absent journal=" + expected_phase)
    if expected_phase != "absent":
        print("U2_EXTERNAL_CURRENT journal-sha256=" + words[2][7:])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_EXTERNAL_CURRENT rejected")
        raise SystemExit(1)
