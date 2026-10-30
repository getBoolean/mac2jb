#!/usr/bin/env python3
"""Run the exact guarded cleanup for a failed native watchdog smoke.

This Mac runner checks the pinned Wi-Fi SSH host/key and source digest, then
sends the fixed device cleanup script through stdin. That script refuses a
live job, any journal, or any changed staged file, and removes only the
three recorded stage paths and the private socket/lock. This does not touch
USB, SSH, or a stock configuration file.
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-clean-service-smoke.py"
PAYLOAD_SHA256 = "8e7cc99a6b8b32011a0a9e58eb24ddebbcc39b5537c9c8947a291365070288de"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"


def main():
    info = PAYLOAD.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ValueError("unsafe cleanup source")
    source = PAYLOAD.read_bytes()
    if hashlib.sha256(source).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("cleanup source changed")
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
                            stderr=subprocess.DEVNULL, timeout=12)
    if (result.returncode != 0 or
            not re.fullmatch(rb"U2_SERVICE_CLEANUP removed\n\Z", result.stdout)):
        raise ValueError("guarded cleanup rejected")
    print("U2_SERVICE_CLEANUP removed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_SERVICE_CLEANUP rejected")
        raise SystemExit(1)
