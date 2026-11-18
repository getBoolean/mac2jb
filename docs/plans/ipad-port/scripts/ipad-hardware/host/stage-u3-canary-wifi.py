#!/usr/bin/env python3
"""Stage the Mac-built HID canary on the iPad over pinned root Wi-Fi SSH.

Usage: stage-u3-canary-wifi.py EXPECTED_SHA256

Effect: requires build/ipad-hardware/u3-hid-canary-v1 at EXPECTED_SHA256, then
streams it to /var/jb/usr/libexec/ipad2jb/keyboard-canary on the device. The
device side creates /var/jb/usr/libexec/ipad2jb (root 0755) if needed, writes a
temporary file exclusively in that folder, sets root 0755, checks its SHA-256
against the expected digest and only then renames it over keyboard-canary, so
a failed transfer never replaces a working canary. It prints the installed
file's SHA-256, which must equal the expected digest. It touches no other file, launches nothing and makes no USB
controller call. Record the staged path in docs/ipad/device-cleanup-ledger.md.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BINARY = ROOT / "build/ipad-hardware/u3-hid-canary-v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
# The canary's fixed, readable install path; its identity is the digest the
# trial runner checks (--canary-sha256), not the file name.
CANARY_PATH = "/var/jb/usr/libexec/ipad2jb/keyboard-canary"
DEVICE = r'''
import hashlib, os, sys
path, expected = sys.argv[1], sys.argv[2]
folder = os.path.dirname(path)
os.makedirs(folder, mode=0o755, exist_ok=True)
data = sys.stdin.buffer.read()
temporary = path + ".incoming"
if os.path.lexists(temporary):
    os.unlink(temporary)
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
try:
    os.write(fd, data)
    os.fchmod(fd, 0o755)
finally:
    os.close(fd)
with open(temporary, "rb") as handle:
    digest = hashlib.sha256(handle.read()).hexdigest()
if digest != expected:
    os.unlink(temporary)
    raise SystemExit("digest")
os.replace(temporary, path)
with open(path, "rb") as handle:
    print(hashlib.sha256(handle.read()).hexdigest())
'''


def main(expected):
    if not HEX64.fullmatch(expected):
        raise ValueError("usage: EXPECTED_SHA256")
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected or len(data) > 1024 * 1024:
        raise ValueError("Mac canary absent or not at the expected digest")
    path = CANARY_PATH
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    result = subprocess.run(ssh + ["/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(DEVICE) +
                                   " " + shlex.quote(path) + " " + expected],
                            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    staged = result.stdout.decode("ascii", "replace").strip()
    if result.returncode != 0 or staged != expected:
        raise ValueError("device refused or digest differs (%s)" %
                         result.stderr.decode("ascii", "replace").strip()[-120:])
    print("U3_STAGE_CANARY staged=%s sha256=%s" % (path, staged))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: EXPECTED_SHA256")
        main(sys.argv[1])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("U3_STAGE_CANARY rejected (%s)" % error)
        raise SystemExit(1)
