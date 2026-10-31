#!/usr/bin/env python3
"""Save a private, verified ClientTruth.plist backup over pinned root SSH.

What this code does:
1. Checks the durable Mac SSH key and host pin without printing their bytes.
2. Runs the repository's bounded read-only metadata/digest script twice as
   root over the pinned localhost USB tunnel, around one SCP download.
3. Accepts the backup only if both remote metadata records match and the
   downloaded file's size and SHA-256 match them. Stores the plist and its
   metadata under a mode-0700 durable Mac backup directory outside Git.
4. Prints only a fixed success category and the local backup location.

It makes no iPad file write, invokes no TrollStore or profiled command, and
does not put private plist bytes in a terminal, repository, or /tmp file.
The backup is an input to a later restoration plan, not authorization to
overwrite live profile state blindly if it changes concurrently.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
DEVICE_SCRIPT = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-clienttruth-backup-metadata.py"
KEY_DIR = Path("/Users/boolean/.ssh/mac2jb-ipad")
IDENTITY = KEY_DIR / "mac2jb-ipad-probe-ed25519"
KNOWN_HOSTS = KEY_DIR / "mac2jb-ipad-known-hosts"
BACKUP_PARENT = KEY_DIR / "backups"
BACKUP_DIR = BACKUP_PARENT / "clienttruth-before-toolbox-2026-10-30"
BACKUP_FILE = BACKUP_DIR / "ClientTruth.plist"
METADATA_FILE = BACKUP_DIR / "metadata.json"
REMOTE_FILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
IDENTITY_SHA256 = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
KNOWN_HOSTS_SHA256 = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
MAX_FILE = 1048576


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def checked_local(path, digest, mode):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode,
            "unsafe Mac credential metadata")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
            "Mac credential digest mismatch")


def ssh_options():
    return [
        "-F", "/dev/null", "-i", str(IDENTITY),
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PreferredAuthentications=publickey",
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
        "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
        "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1", "-o", "LogLevel=ERROR",
    ]


def remote_metadata(source):
    command = ["/usr/bin/ssh", *ssh_options(), "-T", "-p", "2222",
               "root@127.0.0.1", "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=12)
    require(result.returncode == 0 and len(result.stdout) <= 2048,
            "root metadata query failed")
    try:
        record = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("invalid root metadata record")
    require(isinstance(record, dict) and set(record) == {
        "sha256", "size", "uid", "gid", "mode", "dev", "ino",
        "mtime_ns", "ctime_ns", "flags", "xattrs"},
        "incomplete root metadata record")
    require(isinstance(record["size"], int) and 0 < record["size"] <= MAX_FILE
            and isinstance(record["sha256"], str)
            and len(record["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in record["sha256"])
            and record["xattrs"] in ("present", "absent", "unknown"),
            "invalid root metadata values")
    return record


def ensure_backup_parent():
    info = KEY_DIR.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe durable Mac key directory")
    try:
        BACKUP_PARENT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = BACKUP_PARENT.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe Mac backup parent")


def main():
    checked_local(IDENTITY, IDENTITY_SHA256, 0o600)
    checked_local(KNOWN_HOSTS, KNOWN_HOSTS_SHA256, 0o600)
    source = DEVICE_SCRIPT.read_bytes()
    require(len(source) <= 8192 and source.startswith(b"#!/var/jb/usr/bin/python3\n"),
            "unexpected device metadata script")
    before = remote_metadata(source)
    ensure_backup_parent()
    BACKUP_DIR.mkdir(mode=0o700)
    complete = False
    try:
        command = ["/usr/bin/scp", *ssh_options(), "-P", "2222", "-p",
                   "root@127.0.0.1:" + REMOTE_FILE, str(BACKUP_FILE)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=20)
        require(result.returncode == 0, "root SCP backup failed")
        os.chmod(BACKUP_FILE, 0o600)
        info = BACKUP_FILE.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size == before["size"],
                "unsafe or incomplete Mac backup")
        local_digest = hashlib.sha256(BACKUP_FILE.read_bytes()).hexdigest()
        require(local_digest == before["sha256"], "backup digest mismatch")
        after = remote_metadata(source)
        require(after == before, "live ClientTruth metadata changed during backup")
        record = {"source": REMOTE_FILE, "remote": before,
                  "backup_sha256": local_digest, "verified": True}
        fd = os.open(METADATA_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
        try:
            data = (json.dumps(record, sort_keys=True, separators=(",", ":"))
                    + "\n").encode()
            require(os.write(fd, data) == len(data), "short metadata write")
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(BACKUP_FILE, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        complete = True
    finally:
        if not complete:
            for path in (METADATA_FILE, BACKUP_FILE):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            BACKUP_DIR.rmdir()
    print("CLIENTTRUTH_BACKUP verified " + str(BACKUP_DIR))
    print("CLIENTTRUTH_BACKUP xattrs=" + before["xattrs"])
    print("CLIENTTRUTH_BACKUP flags=" + (
        "unknown" if before["flags"] is None else
        "zero" if before["flags"] == 0 else "nonzero"))


if __name__ == "__main__":
    main()
