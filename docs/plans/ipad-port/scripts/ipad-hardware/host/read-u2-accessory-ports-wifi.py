#!/usr/bin/env python3
"""Hash-pin and validate one read-only XDCI IOAccessoryPort census over root Wi-Fi SSH.

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
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-accessory-ports.py"
SOURCE_SHA256 = "ff68b6d1ed0b4c6dca45c57e760b67e1d1acf0681a4e0580e5717d18e4bd8a35"
LINE = re.compile(rb"U2_APORT match=[A-Za-z]{1,40} class=[A-Za-z][A-Za-z0-9_]{0,99} parents=[A-Za-z0-9_>]{0,330}( [A-Za-z][A-Za-z0-9_-]{0,63}=(yes|no|-?[0-9]{1,5}))*\n")


def validate(output):
    lines = output.splitlines(keepends=True)
    if len(output) > 16384 or not lines or not re.fullmatch(rb"U2_APORT count=[0-9]{1,2} done\n", lines[-1]):
        raise ValueError("incomplete port census")
    if not all(LINE.fullmatch(line) for line in lines[:-1]):
        raise ValueError("invalid port line")


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
        print("U2_APORT rejected")
        raise SystemExit(1)
