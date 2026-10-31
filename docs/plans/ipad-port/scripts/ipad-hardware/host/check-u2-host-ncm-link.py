#!/usr/bin/env python3
"""Classify the Mac link state of the iPad's bound USB NCM interface.

Finds the unique IOEthernetInterface only within the iPad IOService subtree,
then reads ifconfig for that BSD interface. It prints only bounded status,
address-presence and UP categories; no IP, MAC or device ID is emitted. It
does not send traffic, open USB, or change network configuration. An active
link is not by itself evidence that packets reach the iPad.
"""

from pathlib import Path
import re
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
USB = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/diagnose-usb-recognition.py"))
NAME = re.compile(r'"BSD Name" = "(en[0-9]{1,3})"')


def capture_named():
    result = subprocess.run(["/usr/sbin/ioreg", "-p", "IOService", "-l", "-w0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("Mac IOService unavailable")
    lines = result.stdout.decode("utf8", "replace").splitlines()
    if sum("+-o iPad@" in line for line in lines) != 1:
        raise ValueError("iPad subtree ambiguous")
    subtree = USB["first_ipad_subtree"](lines)
    positions = [index for index, line in enumerate(subtree)
                 if "+-o " in line and "<class IOEthernetInterface," in line]
    if len(positions) != 1:
        raise ValueError("iPad NCM Ethernet interface count")
    matches = [NAME.search(line) for line in subtree[positions[0] + 1:positions[0] + 24]]
    names = [match.group(1) for match in matches if match]
    if len(names) != 1:
        raise ValueError("iPad NCM BSD name unavailable")
    result = subprocess.run(["/sbin/ifconfig", names[0]],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    if result.returncode or len(result.stdout) > 16 * 1024:
        raise ValueError("iPad NCM link unavailable")
    output = result.stdout.decode("utf8", "replace")
    status = re.search(r"^\s*status: ([a-z]+)$", output, re.M)
    flags = re.search(r"^[^\n]+: flags=[^\n]*<([^>]*)>", output, re.M)
    if not status or status.group(1) not in ("active", "inactive") or not flags:
        raise ValueError("iPad NCM link state unknown")
    return (names[0], status.group(1), "UP" in flags.group(1).split(","),
            bool(re.search(r"^\s*inet ", output, re.M)),
            bool(re.search(r"^\s*inet6 ", output, re.M)))


def capture():
    _, status, up, ipv4, ipv6 = capture_named()
    return status, up, ipv4, ipv6


def main():
    status, up, ipv4, ipv6 = capture()
    print("U2_NCM_LINK status=" + status + " up=" + ("yes" if up else "no") +
          " ipv4=" + ("yes" if ipv4 else "no") +
          " ipv6=" + ("yes" if ipv6 else "no"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, IndexError, subprocess.TimeoutExpired):
        print("U2_NCM_LINK rejected")
        raise SystemExit(1)
