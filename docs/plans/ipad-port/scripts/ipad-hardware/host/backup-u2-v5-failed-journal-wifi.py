#!/usr/bin/env python3
"""Make and verify a durable private Mac backup of the failed v5 journal.

The iPad side only reads the exact root-owned journal over pinned Wi-Fi SSH.
The Mac exclusively creates an owner-only backup under ignored build output,
fsyncs it and its directory, then verifies the digest. An existing exact
backup is accepted without overwrite. No iPad file, job, or USB controller is
changed. This does not archive or clear the active iPad journal.
"""

import hashlib
import os
from pathlib import Path
import runpy
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-copy-v5-failed-journal.py"
RECOVERY = HOST / "check-u2-post-v5-reboot.py"
DEST = ROOT / "build/ipad-hardware/u2-v5-oldboot-archive"
FILE = DEST / "restore-journal.oldboot-v5.json"
EXPECTED = "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"
RECOVERY_OUTPUT = (b"U2_POST_V5_REBOOT boot=new live=original configs=5 "
                   b"resolved-strings=23 renumbered=12 interfaces=equal "
                   b"scalars=equal network-binding=equal network-packet=reply "
                   b"usbmux=one pairing=valid power=charging-or-full "
                   b"journal=retained-exact\n")


def verify_file():
    info = FILE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= 2_000_000 or
            hashlib.sha256(FILE.read_bytes()).hexdigest() != EXPECTED):
        raise ValueError("private backup changed")


def main():
    source_info = SOURCE.lstat()
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1 or
            not 0 < source_info.st_size <= 8 * 1024):
        raise ValueError("unsafe source")
    result = subprocess.run(["/usr/bin/python3", str(RECOVERY)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode or result.stdout != RECOVERY_OUTPUT:
        raise ValueError("new-boot recovery not verified")
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
    result = subprocess.run(command, input=SOURCE.read_bytes(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    data = result.stdout
    if (result.returncode or not 0 < len(data) <= 2_000_000 or
            hashlib.sha256(data).hexdigest() != EXPECTED):
        raise ValueError("remote journal changed")
    if not DEST.exists() and not DEST.is_symlink():
        os.mkdir(DEST, 0o700)
    info = DEST.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            any(path.name != FILE.name for path in DEST.iterdir())):
        raise ValueError("unsafe backup directory")
    if not FILE.exists() and not FILE.is_symlink():
        fd = os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as target:
                target.write(data)
                target.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    verify_file()
    print("U2_V5_JOURNAL_BACKUP new-boot=verified journal=exact "
          "mac-backup=durable ipad-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.TimeoutExpired):
        print("U2_V5_JOURNAL_BACKUP rejected; active journal retained")
        raise SystemExit(1)
