#!/usr/bin/env python3
"""Invoke the reviewed local U1 toolbox installer over pinned root USB SSH.

What this code does: verify the private pre-install plist and ACL backups,
check live plist metadata and exact staged IPA digest, then send the repo
installer source to isolated root Python with the original plist digest.
Only the device script's three fixed status lines are printed. This is a
persistent iPad app installation; its effects are in the cleanup ledger.
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
stage = runpy.run_path(str(HERE / "stage-toolbox-over-root-ssh.py"))
SOURCE = backup["ROOT"] / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-install-verified-toolbox.py"
STAGED_LINE = ("TOOLBOX_STAGE size=432334 sha256=" + stage["SHA256"] + "\n").encode()


def main():
    backup["checked_local"](backup["IDENTITY"], backup["IDENTITY_SHA256"], 0o600)
    backup["checked_local"](backup["KNOWN_HOSTS"], backup["KNOWN_HOSTS_SHA256"], 0o600)
    record = json.loads(backup["METADATA_FILE"].read_bytes())
    original = record["remote"]
    for path in (backup["BACKUP_FILE"], backup["BACKUP_DIR"] / "acl.txt"):
        info = path.lstat()
        backup["require"](stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                          and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                          "unsafe private backup")
    backup["require"](record["verified"] is True and
                      hashlib.sha256(backup["BACKUP_FILE"].read_bytes()).hexdigest()
                      == original["sha256"], "original plist backup mismatch")
    backup["require"](backup["remote_metadata"](backup["DEVICE_SCRIPT"].read_bytes())
                      == original, "live profile changed before install")
    backup["require"](stage["remote"](stage["VERIFY"]) == STAGED_LINE,
                      "staged IPA changed before install")
    source = SOURCE.read_bytes()
    backup["require"](0 < len(source) <= 8192 and
                      source.startswith(b"#!/var/jb/usr/bin/python3\n"),
                      "unexpected installer source")
    command = ["/usr/bin/ssh", *backup["ssh_options"](), "-T", "-p", "2222",
               "root@127.0.0.1", "/var/jb/usr/bin/python3", "-I", "-S", "-B",
               "-", original["sha256"]]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=110)
    backup["require"](result.returncode == 0 and len(result.stdout) < 256,
                      "toolbox install did not return a complete status; inspect device state")
    lines = result.stdout.decode("ascii").splitlines()
    backup["require"](len(lines) == 3 and
                      lines[0].startswith("TOOLBOX_INSTALL helper=") and
                      lines[1] in ("TOOLBOX_INSTALL profile=unchanged",
                                   "TOOLBOX_INSTALL profile=changed") and
                      lines[2] in ("TOOLBOX_INSTALL toolbox=present",
                                   "TOOLBOX_INSTALL toolbox=absent"),
                      "unexpected installer status; inspect device state")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
