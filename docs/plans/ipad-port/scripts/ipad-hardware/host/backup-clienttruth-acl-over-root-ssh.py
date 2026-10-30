#!/usr/bin/env python3
"""Save a private ACL text backup for ClientTruth.plist over pinned root SSH.

What this code does: imports the existing pinned-key and profile-metadata
checks, verifies the live plist still matches the saved byte backup, streams
only its ACL from the repository's read-only device script, writes ACL text
to a new mode-0600 Mac file beside the backup, then checks the plist again.
The ACL is never printed or stored in Git or /tmp. No iPad write occurs.
"""

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess


HERE = Path(__file__).resolve().parent
backup = runpy.run_path(str(HERE / "backup-clienttruth-over-root-ssh.py"))
ROOT = backup["ROOT"]
SOURCE = ROOT / "scripts/ipad-hardware/device/u1-readonly-clienttruth-acl.py"
ACL_FILE = backup["BACKUP_DIR"] / "acl.txt"


def main():
    backup["checked_local"](backup["IDENTITY"], backup["IDENTITY_SHA256"], 0o600)
    backup["checked_local"](backup["KNOWN_HOSTS"], backup["KNOWN_HOSTS_SHA256"], 0o600)
    info = backup["BACKUP_DIR"].lstat()
    backup["require"](stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                      and stat.S_IMODE(info.st_mode) == 0o700,
                      "unsafe Mac backup directory")
    record = json.loads(backup["METADATA_FILE"].read_bytes())
    original = record["remote"]
    backup["require"](record["verified"] is True and
                      hashlib.sha256(backup["BACKUP_FILE"].read_bytes()).hexdigest()
                      == original["sha256"], "backup plist mismatch")
    meta_source = backup["DEVICE_SCRIPT"].read_bytes()
    backup["require"](backup["remote_metadata"](meta_source) == original,
                      "live profile changed before ACL backup")
    acl_source = SOURCE.read_bytes()
    backup["require"](0 < len(acl_source) <= 8192 and
                      acl_source.startswith(b"#!/var/jb/usr/bin/python3\n"),
                      "unexpected ACL script")
    command = ["/usr/bin/ssh", *backup["ssh_options"](), "-T", "-p", "2222",
               "root@127.0.0.1", "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=acl_source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=12)
    backup["require"](result.returncode == 0 and 0 < len(result.stdout) <= 65536,
                      "ACL query failed")
    fd = os.open(ACL_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        backup["require"](os.write(fd, result.stdout) == len(result.stdout),
                          "short ACL backup write")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        backup["require"](backup["remote_metadata"](meta_source) == original,
                          "live profile changed during ACL backup")
    except Exception:
        ACL_FILE.unlink()
        raise
    print("CLIENTTRUTH_ACL_BACKUP verified " + str(ACL_FILE))
    print("CLIENTTRUTH_ACL_BACKUP bytes=" + str(len(result.stdout)))


if __name__ == "__main__":
    main()
