#!/usr/bin/env python3
"""Hash-pin and validate one read-only XDCI launchd provider job state over root Wi-Fi SSH.

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
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-ptpd-job-state.py"
SOURCE_SHA256 = "f760b2d44865717bf4204c69dc3feb3bd175a33ad9c1eaa7a0e5469e782d5431"
LINE = re.compile(rb"(U2_JOB label=com\.apple\.[a-z]+ print-exit=[0-9]{1,3}|U2_JOB_LINE label=com\.apple\.[a-z]+ [A-Za-z0-9 ._:=>{}()/,+-]{1,160})\n")


def validate(output):
    lines = output.splitlines(keepends=True)
    if len(output) > 16384 or not lines or lines[-1] != b"U2_JOB done\n":
        raise ValueError("incomplete job state")
    if not all(LINE.fullmatch(line) for line in lines[:-1]):
        raise ValueError("invalid job line")


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
        print("U2_JOB rejected")
        raise SystemExit(1)
