#!/usr/bin/env python3
"""Store the target iPad's Wi-Fi IPv4 privately for later headless SSH checks.

This Mac-only setup helper prompts without echo, accepts one RFC1918 IPv4
literal, and creates a mode-0600 file in the existing durable Mac credential
directory. It refuses an existing file, never prints the address, and makes no
iPad or network change. Check the iPad's current Wi-Fi address before running;
an address change requires deliberate replacement after target verification.
"""

import getpass
import ipaddress
import os
from pathlib import Path
import stat


DIRECTORY = Path("/Users/boolean/.ssh/mac2jb-ipad")
FILE = DIRECTORY / "wifi-ipv4"
NETWORKS = tuple(ipaddress.IPv4Network(value) for value in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def main():
    info = DIRECTORY.lstat()
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700):
        raise SystemExit("Private credential directory failed its metadata check")
    if FILE.exists() or FILE.is_symlink():
        raise SystemExit("Wi-Fi address file already exists; nothing changed")
    try:
        address = ipaddress.IPv4Address(getpass.getpass("iPad Wi-Fi IPv4 (hidden): "))
    except ValueError:
        raise SystemExit("Invalid IPv4 address; nothing changed")
    if not any(address in network for network in NETWORKS):
        raise SystemExit("Expected a private Wi-Fi IPv4 address; nothing changed")
    descriptor = os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = (str(address) + "\n").encode("ascii")
        if os.write(descriptor, data) != len(data):
            raise OSError("short local write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print("WIRELESS_ADDRESS stored-privately")


if __name__ == "__main__":
    main()
