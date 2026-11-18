#!/usr/bin/env python3
"""Install the standalone `ipad2jb` command on the iPad over pinned root Wi-Fi SSH.

Usage: install-ipad2jb-command-wifi.py

Effect: builds ios/ipad2jb/ipad2jb.c with ios/ipad2jb/build.sh (arm64 iOS, ad-hoc
signed with ios/ipad2jb/ipad2jb.entitlements) and streams the binary to
/var/jb/usr/bin/ipad2jb (root, 0755). The
device side writes a temporary file in /var/jb/usr/bin exclusively, checks its
SHA-256 against the Mac copy and only then renames it over the old command, so a
failed transfer never leaves a broken command. Prints the installed SHA-256.
It launches nothing, touches no other file and makes no USB controller call.
Run it on the iPad as `sudo ipad2jb [TEXT]`.
"""

import hashlib
from pathlib import Path
import runpy
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BUILD_SCRIPT = ROOT / "ios/ipad2jb/build.sh"
SOURCE = ROOT / "build/ipad-hardware/ipad2jb"
DESTINATION = "/var/jb/usr/bin/ipad2jb"
DEVICE = r'''
import hashlib, os, sys
path, expected = sys.argv[1], sys.argv[2]
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
print(digest)
'''


def main():
    subprocess.run([str(BUILD_SCRIPT), str(SOURCE)], check=True, stdout=subprocess.DEVNULL, timeout=300)
    data = SOURCE.read_bytes()
    expected = hashlib.sha256(data).hexdigest()
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    result = subprocess.run(ssh + ["/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(DEVICE) +
                                   " " + DESTINATION + " " + expected],
                            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    installed = result.stdout.decode("ascii", "replace").strip()
    if result.returncode != 0 or installed != expected:
        raise ValueError("device refused or digest differs (%s)" %
                         result.stderr.decode("ascii", "replace").strip()[-120:])
    print("IPAD2JB_INSTALL installed=%s sha256=%s" % (DESTINATION, installed))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("IPAD2JB_INSTALL rejected (%s)" % error)
        raise SystemExit(1)
