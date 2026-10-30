#!/usr/bin/env python3
"""Read the iPad battery's external-power flags over pinned Wi-Fi SSH.

This sends one digest-pinned, read-only IOKit classifier to the iPad's Python
stdin as root. It opens no USB user client and writes no iPad file. It prints
only three boolean categories, never an address, key, battery level, or ID.
These flags are not an electrical VBUS measurement.
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
SOURCE = ROOT / "scripts/ipad-hardware/device/u1-readonly-power-source-state.py"
SOURCE_SHA256 = "c0ab521efcdfa52b96ac8a1c4e6a8d3cd76a4aad145a32c7528a176fe1d7f677"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
RESULT = re.compile(rb"POWER_SOURCE query=ok external=(?:yes|no) "
                    rb"charging=(?:yes|no) full=(?:yes|no)\n\Z")


def capture():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ValueError("unsafe power classifier")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("power classifier changed")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0 or not RESULT.fullmatch(result.stdout):
        raise ValueError("power classifier unavailable")
    return result.stdout


def main():
    print(capture().decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("POWER_SOURCE rejected")
        raise SystemExit(1)
