#!/usr/bin/env python3
"""Hash-pin and validate one read-only XDCI device lock state over root Wi-Fi SSH.

Effect: runs the pinned device payload once over pinned root SSH; the payload
only reads IORegistry. Prints validated categorical output; writes nothing.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-lock-state.py"
SOURCE_SHA256 = "e9d6b76585577eee7cecf704742d6809d1a89d0cd6f2e3d4beab33307af17515"
LINE = re.compile(rb"U2_LOCK keybag=(-?[0-9]{1,3}|unknown) springboard-lockstate=([0-9]{1,20}|unknown) blanked=([0-9]{1,20}|unknown)\n")


def validate(output):
    if not LINE.fullmatch(output):
        raise ValueError("invalid lock line")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16384:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
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
               "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address,
               "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=25)
    if result.returncode or len(result.stdout) > 16384:
        raise ValueError("device census failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_LOCK rejected")
        raise SystemExit(1)
