#!/usr/bin/env python3
"""Classify the exact v5 job and socket after a new boot, without changes.

The pinned root Wi-Fi SSH payload reads launchd and file kinds and asks only
the existing broker's status command when its socket can be reached. This
does not publish or restore a USB description and does not change device files.
"""

import hashlib
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-v5-postreboot-state.py"
SOURCE_SHA256 = "c1b5622999839fc94ea6f0cbe7cc92e0dbd765b4b67ec62eab4ea530788124e3"


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16 * 1024:
        raise ValueError("unsafe source")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
        raise ValueError("source changed")
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
                            stderr=subprocess.DEVNULL, timeout=12)
    prefix = (b"U2_V5_POSTREBOOT job=")
    if (result.returncode or len(result.stdout) > 256 or
            not result.stdout.startswith(prefix)):
        raise ValueError("v5 postreboot service unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            UnicodeError, subprocess.TimeoutExpired):
        print("U2_V5_POSTREBOOT rejected")
        raise SystemExit(1)
