#!/usr/bin/env python3
"""Classify whether the connected iPad has an active Mac USB network driver.

This reads the Mac IOService tree only. It neither opens the iPad nor sends a
request. Its count is scoped to the unique iPad subtree and omits identifiers.
An advertised NCM interface without a bound IOEthernetInterface is not proof
of packet-carrying USB network service.
"""

from pathlib import Path
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
DIAGNOSTIC = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/diagnose-usb-recognition.py"


def capture():
    module = runpy.run_path(str(DIAGNOSTIC))
    result = subprocess.run(["/usr/sbin/ioreg", "-p", "IOService", "-l", "-w0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15)
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("IOService query failed")
    lines = result.stdout.decode("utf8", "replace").splitlines()
    if sum("+-o iPad@" in line for line in lines) != 1:
        raise ValueError("ambiguous iPad")
    subtree = module["first_ipad_subtree"](lines)
    if not subtree:
        raise ValueError("iPad absent")
    ethernet = sum("+-o " in line and "<class IOEthernetInterface," in line
                   for line in subtree)
    ncm_driver = sum("+-o " in line and "<class AppleUSBNCM" in line
                     for line in subtree)
    if ethernet > 4 or ncm_driver > 4:
        raise ValueError("ambiguous network driver")
    return ethernet, ncm_driver


def main():
    ethernet, ncm_driver = capture()
    print("U2_HOST_NETWORK ethernet=" + str(ethernet) +
          " ncm-driver=" + str(ncm_driver))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_HOST_NETWORK rejected")
        raise SystemExit(1)
