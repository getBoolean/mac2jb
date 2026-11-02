#!/usr/bin/env python3
"""Hash-pin and validate one read-only USB function-provider job/process listing over root Wi-Fi SSH.

Effect: runs the pinned device payload once over pinned root SSH; the payload
only lists launchd jobs and processes. Prints validated output; writes nothing.
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
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-usb-function-providers.py"
SOURCE_SHA256 = "804af067423e8aa01e05f45f2a4ddcbdd7ee12dbe9594fe5b74f30c5d7d1362b"
LINE = re.compile(
    rb"(U2_PROVIDER_JOB label=[A-Za-z0-9._-]{1,96} running=(yes|no) status=(-?[0-9]{1,4}|other)"
    rb"|U2_PROVIDER_PROC name=[A-Za-z0-9._-]{1,48} elapsed=([0-9]{1,10}|unknown))\n")
HEADER = re.compile(rb"U2_PROVIDERS count=([0-9]{1,3})\n")


def validate(output):
    lines = output.splitlines(keepends=True)
    if len(output) > 16384 or len(lines) < 2 or lines[-1] != b"U2_PROVIDERS done\n":
        raise ValueError("incomplete listing")
    head = HEADER.fullmatch(lines[0])
    if not head or int(head[1]) != len(lines) - 2:
        raise ValueError("invalid header")
    if not all(LINE.fullmatch(line) for line in lines[1:-1]):
        raise ValueError("invalid line")


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
    if result.returncode:
        raise ValueError("device listing failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_PROVIDERS rejected")
        raise SystemExit(1)
