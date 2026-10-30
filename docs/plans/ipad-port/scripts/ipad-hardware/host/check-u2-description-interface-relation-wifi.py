#!/usr/bin/env python3
"""Compare in-memory U2 description interfaces through pinned read-only SSH.

Requires full new-boot external USB/NCM/pairing/power recovery and the exact
four-journal archived state before and after the device-side in-memory probe.
No controller description is published and no iPad file is changed.
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-description-interface-relation.py"
SOURCE_SHA = "1b28c65c29be0fed1e06b4c6cb1437ce397dd512407ba5fd5d33525a52b0d63e"
CHECKER = HOST / "check-u2-post-v5-reboot.py"
EXPECTED = (b"U2_POST_V5_REBOOT boot=new live=original configs=5 resolved-strings=23 "
            b"renumbered=12 interfaces=equal scalars=equal network-binding=equal "
            b"network-packet=reply usbmux=one pairing=valid power=charging-or-full "
            b"journal=archived-active-absent\n")
PATTERN = re.compile(rb"U2_INTERFACE_RELATION defaults-configs=[0-9]{1,2} "
                     rb"clone-configs=[0-9]{1,2} interfaces=(?:equal|different) "
                     rb"patched-info=equal clone-control=(?:equal|different) "
                     rb"description-object=(?:equal|different)\n\Z")


def external():
    result = subprocess.run(["/usr/bin/python3", str(CHECKER), "--archived"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode or result.stdout != EXPECTED:
        raise ValueError("external USB state changed")


def main():
    info = SOURCE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= 8 * 1024):
        raise ValueError("unsafe probe source")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA:
        raise ValueError("probe source changed")
    external()
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or len(result.stdout) > 256 or not PATTERN.fullmatch(result.stdout):
        raise ValueError("interface relation unavailable")
    external()
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_INTERFACE_RELATION rejected; no controller publication")
        raise SystemExit(1)
