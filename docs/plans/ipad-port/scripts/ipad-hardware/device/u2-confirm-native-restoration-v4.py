#!/var/jb/usr/bin/python3
"""Send one externally verified receipt digest to the native U2 watchdog.

The Mac sends this exact source over pinned root SSH only after its current-
boot external checker passes. This code accepts one 64-hex SHA-256 argument,
connects only to the private root-owned watchdog socket, sends `confirm`,
and requires the watchdog's exact verified-and-cleared response. The watchdog
rechecks live USB state before it removes its own journal. This script never
calls a USB API, modifies a system file directly, or starts a service.
"""

import os
import re
import socket
import sys


SOCKET = "/var/jb/var/lib/mac2jb-u2-native/broker.sock"


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 2 or
            not re.fullmatch(r"[0-9a-f]{64}", sys.argv[1])):
        raise ValueError("invalid receipt digest")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(4)
        connection.connect(SOCKET)
        connection.sendall(("confirm " + sys.argv[1] + "\n").encode("ascii"))
        if connection.recv(128) != b"OK verified-and-cleared\n":
            raise ValueError("watchdog rejected external proof")
    print("U2_CONFIRM_V4 accepted")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, socket.timeout):
        print("U2_CONFIRM_V4 rejected")
        raise SystemExit(1)
