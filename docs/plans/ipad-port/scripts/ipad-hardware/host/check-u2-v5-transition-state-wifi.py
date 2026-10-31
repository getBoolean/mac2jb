#!/usr/bin/env python3
"""Read categorical U2 v4/v5 stage state over pinned root Wi-Fi SSH."""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-v5-transition-state.py"
SOURCE_SHA256 = "8f4e83553ee9e3b7c7c2c26668967e2b9b59524b233d07cd78e1bf5cae563967"
PATTERN = re.compile(
    rb"U2_V5_TRANSITION_STATE old-job=(?:yes|no) new-job=(?:yes|no) "
    rb"old-binary=(?:regular|absent|other) new-binary=(?:regular|absent|other) "
    rb"old-plist=(?:regular|absent|other) new-plist=(?:regular|absent|other) "
    rb"socket=(?:socket|absent|other) journal=(?:regular|absent|other)\n\Z")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 8 * 1024:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("transition probe changed")
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    remote = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, remote]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=12)
    if result.returncode or not PATTERN.fullmatch(result.stdout):
        raise ValueError("transition state unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V5_TRANSITION_STATE rejected")
        raise SystemExit(1)
