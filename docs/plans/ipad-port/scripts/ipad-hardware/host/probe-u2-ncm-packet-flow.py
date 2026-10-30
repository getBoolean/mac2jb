#!/usr/bin/env python3
"""Verify one bounded packet round trip over the iPad USB NCM link.

Selects the unique Mac Ethernet interface under the exact iPad USB subtree,
requires it active/UP with IPv6, and selects one already-known link-local
neighbor on that interface. It sends exactly one ICMPv6 echo with a five-second
wait, then requires one reply while USBMux and pinned Wi-Fi SSH remain healthy.
No address, MAC, device ID or payload is printed. It writes no system file,
changes no iPad setting, and makes no USB control or descriptor request.
"""

import ipaddress
from pathlib import Path
import re
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
LINK = runpy.run_path(str(HOST / "check-u2-host-ncm-link.py"))
CONTROL = runpy.run_path(str(HOST / "probe-u2-readonly-string-descriptors.py"))
MAC = re.compile(r"(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}", re.I)


def neighbor(interface):
    result = subprocess.run(["/usr/sbin/ndp", "-an"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if result.returncode or len(result.stdout) > 128 * 1024:
        raise ValueError("NCM neighbor table unavailable")
    peers = []
    for line in result.stdout.decode("ascii", "replace").splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] != interface:
            continue
        raw = fields[0]
        if not raw.endswith("%" + interface) or not MAC.fullmatch(fields[1]):
            continue
        try:
            address = ipaddress.IPv6Address(raw.split("%", 1)[0])
        except ValueError:
            continue
        if address.is_link_local:
            peers.append(raw)
    if len(peers) != 1:
        raise ValueError("NCM peer unavailable or ambiguous")
    return peers[0]


def main():
    CONTROL["connection"]()
    CONTROL["host_usb_ready"]()
    interface, state, up, _, ipv6 = LINK["capture_named"]()
    if state != "active" or not up or not ipv6:
        raise ValueError("NCM link inactive")
    peer = neighbor(interface)
    result = subprocess.run(["/sbin/ping6", "-c", "1", "-I", interface, peer],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if (result.returncode or len(result.stdout) > 8 * 1024 or
            not re.search(rb"1 packets transmitted, 1 packets received", result.stdout)):
        raise ValueError("NCM echo reply unavailable")
    if LINK["capture_named"]()[1:3] != ("active", True):
        raise ValueError("NCM link changed")
    CONTROL["connection"]()
    CONTROL["host_usb_ready"]()
    print("U2_NCM_PACKET peer=one-linklocal echo=reply "
          "link=active usbmux=one ssh=healthy")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, IndexError, subprocess.TimeoutExpired):
        print("U2_NCM_PACKET rejected")
        raise SystemExit(1)
