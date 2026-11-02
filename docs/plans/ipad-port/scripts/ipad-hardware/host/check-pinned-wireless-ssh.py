#!/usr/bin/env python3
"""Check target iPad SSH over Wi-Fi against the existing pinned USB host key.

What this code does: read one privately stored RFC1918 IPv4 address from the
durable Mac credential directory, verify the existing key and known-hosts file
against their pinned digests/modes, and run only `/var/jb/usr/bin/id -u` as
mobile and root. OpenSSH HostKeyAlias makes the Wi-Fi connection verify the
same host key already trusted over USB. No host key is accepted interactively,
no default identity is offered, and no address, key, or raw diagnostic is
printed. The script writes no iPad file or network configuration. Normal SSH
authentication/accounting logs can still occur.

Initial setup: while the iPad is on the same Wi-Fi, save its exact current
IPv4 address followed by a newline to the private mode-0600 file named
`wifi-ipv4` in `/Users/boolean/.ssh/mac2jb-ipad/`. Keep that file out of Git,
chat, shell command history, and /tmp. A changed address requires rechecking
the iPad before reuse. A passing SSH key check alone does not prove USB role.
"""

import ipaddress
import os
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
ADDRESS_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/wifi-ipv4")
HOST_KEY_ALIAS = "[127.0.0.1]:2222"
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def read_address():
    try:
        info = ADDRESS_FILE.lstat()
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                7 <= info.st_size <= 16):
            return None
        data = ADDRESS_FILE.read_bytes()
        if len(data) != info.st_size or not data.endswith(b"\n") or data.count(b"\n") != 1:
            return None
        address = ipaddress.IPv4Address(data[:-1].decode("ascii"))
        if not any(address in network for network in PRIVATE_NETWORKS):
            return None
        return str(address)
    except (OSError, UnicodeError, ValueError):
        return None


def main():
    address = read_address()
    if address is None:
        print("WIRELESS_SSH address=missing-or-unsafe")
        return
    helper = runpy.run_path(str(HELPER))
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    print("WIRELESS_SSH pinned-inputs=ok")
    for account, expected in (("mobile", b"501"), ("root", b"0")):
        command = ["/usr/bin/ssh", *helper["ssh_options"](),
                   "-o", "HostKeyAlias=" + HOST_KEY_ALIAS,
                   "-o", "AddressFamily=inet", "-T", "-p", "22",
                   account + "@" + address, "/var/jb/usr/bin/id -u"]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=12)
            valid = result.returncode == 0 and result.stdout.strip() == expected
        except (OSError, subprocess.TimeoutExpired):
            valid = False
        print("WIRELESS_SSH " + account + "=" + ("ok" if valid else "failed"))


if __name__ == "__main__":
    main()
