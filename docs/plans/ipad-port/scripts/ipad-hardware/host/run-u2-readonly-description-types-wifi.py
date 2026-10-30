#!/usr/bin/env python3
"""Run the fixed read-only controller description-shape probe over Wi-Fi.

Pins the existing device classifier and SSH identity/host record, sends the
script to root Python stdin, and prints only default/live property types and
top-level counts. It writes no iPad file and sends no USB request.
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
SOURCE = ROOT / "scripts/ipad-hardware/device/u1-readonly-controller-description-types.py"
SOURCE_SHA256 = "00f254119c926c8649fbeb7dadf15e0fc048762b4cfd5c1fab38566300afc253"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
RESULT = re.compile(rb"DESCRIPTION_TYPES query=ok default=(?:dict|array|data|string):[0-9]{1,4} "
                    rb"live=(?:dict|array|data|string):[0-9]{1,4}\n\Z")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("source changed")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode != 0 or not RESULT.fullmatch(result.stdout):
        raise ValueError("description types unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("DESCRIPTION_TYPES rejected")
        raise SystemExit(1)
