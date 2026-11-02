#!/usr/bin/env python3
"""Run the bounded read-only USB-role IOService class scan over pinned Wi-Fi.

Sends an exact-hash Python payload in memory over pinned root SSH, validates
its complete categorical output, and prints no raw registry data or IDs.
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
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-usb-role-classes.py"
SOURCE_SHA256 = "92a6afdd723aba4ca65b17c54406dc2be6b247bb6081bb10093a1c10587bf0f7"
HEADER = re.compile(rb"U2_ROLE_CLASSES scanned=([0-9]{1,4}) matches=([0-9]{1,4}) pairs=([0-9]{1,2})\n")
LINE = re.compile(rb"U2_ROLE_CLASS class=([A-Za-z][A-Za-z0-9_]{0,99}) parent=([A-Za-z][A-Za-z0-9_]{0,99}|None) count=([0-9]{1,4})\n")


def validate(output):
    if len(output) > 8192:
        raise ValueError("oversize scan")
    lines = output.splitlines(keepends=True)
    if len(lines) < 2 or lines[-1] != b"U2_ROLE_CLASSES done\n":
        raise ValueError("incomplete scan")
    header = HEADER.fullmatch(lines[0])
    if not header:
        raise ValueError("invalid scan header")
    scanned, matches, pairs = (int(value) for value in header.groups())
    if not 0 <= scanned <= 4096 or not 0 <= matches <= scanned or not 0 <= pairs <= 80:
        raise ValueError("invalid scan counts")
    if len(lines) != pairs + 2:
        raise ValueError("class-pair count mismatch")
    names = set()
    counted = 0
    for line in lines[1:-1]:
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError("invalid class pair")
        pair = (match[1], match[2])
        if pair in names or int(match[3]) < 1:
            raise ValueError("duplicate class pair")
        names.add(pair)
        counted += int(match[3])
    if counted != matches:
        raise ValueError("matched-service count mismatch")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
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
                            timeout=20)
    if result.returncode != 0:
        raise ValueError("device scan failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_ROLE_CLASSES rejected")
        raise SystemExit(1)
