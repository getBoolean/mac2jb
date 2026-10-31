#!/usr/bin/env python3
"""Make and verify a durable private Mac backup of the failed v4 repeat journal.

The iPad side only reads the exact root-owned journal over pinned Wi-Fi SSH.
The Mac exclusively creates an owner-only backup under ignored build output,
fsyncs it and its directory, then verifies the digest. An existing exact
backup is accepted without overwrite. No iPad file, job, or USB controller is
changed. This does not archive or clear the active iPad journal.
"""

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-copy-v4-repeat-journal.py"
SOURCE_SHA = "f7be9d76efa4257aed0adac45431468b94f8f6d83d1a44504e778fabf1717087"
CHECKER = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
BASE = ROOT / "build/ipad-hardware/u2-v4-repeat-baseline"
BASE_MANIFEST_SHA = "3cb0ac315983eb121bb1f1db1a68bc748bb8e6166c8634a582dba0a9395b5a35"
RECOVERY = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))
DEST = ROOT / "build/ipad-hardware/u2-v4-repeat-journal-backup"
FILE = DEST / "restore-journal.awaiting-verification-v4-repeat.json"
EXPECTED = "639c07c183ebc4e0f8c07b099416d8c66c7ebefb92a5d2227bc19068008d1729"


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
            not 0 < source_info.st_size <= 8 * 1024 or
            hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA):
        raise ValueError("unsafe source")
    manifest_bytes = (BASE / "manifest.json").read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != BASE_MANIFEST_SHA:
        raise ValueError("repeat baseline manifest changed")
    manifest = json.loads(manifest_bytes)
    snapshot_bytes = (BASE / "snapshot.json").read_bytes()
    if hashlib.sha256(snapshot_bytes).hexdigest() != manifest["files"]["snapshot.json"]:
        raise ValueError("repeat snapshot changed")
    boot = json.loads(snapshot_bytes)["snapshot"]["identity"]["boot_session"]
    if RECOVERY["read_boot_token"]() != boot or CHECKER["journal"]("awaitingVerification") != EXPECTED:
        raise ValueError("same-boot failed journal changed")
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
    names = set(path.name for path in DEST.iterdir())
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            names not in (set(), {FILE.name})):
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
    if RECOVERY["read_boot_token"]() != boot or CHECKER["journal"]("awaitingVerification") != EXPECTED:
        raise ValueError("same-boot failed journal changed after backup")
    print("U2_V4_REPEAT_JOURNAL_BACKUP same-boot=verified journal=exact "
          "mac-backup=durable ipad-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.TimeoutExpired):
        print("U2_V4_REPEAT_JOURNAL_BACKUP rejected; active journal retained")
        raise SystemExit(1)
