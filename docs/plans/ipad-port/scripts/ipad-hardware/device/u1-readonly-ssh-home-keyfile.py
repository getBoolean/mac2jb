#!/var/jb/usr/bin/python3
"""Compare mobile's configured-home authorization file with /var/mobile's.

What this code does:
1. Reads mobile's account home from the local account database but prints only
   a fixed path category, never a raw home path.
2. Checks fixed .ssh and authorized_keys final components without following
   symlinks, then reads at most 64 KiB to classify the exact new public line.
3. Reports whether the configured-home file is the same inode as the prior
   /var/mobile file, and whether its last byte is a newline.
It neither changes a file nor invokes, signals, or restarts sshd or USB.

Exact NewTerm invocation:
/var/jb/usr/bin/sudo -- /var/jb/usr/bin/python3 -I -S -B /var/mobile/Media/.mac2jb-u1-home-keyfile.py
"""

import hashlib
import os
import pwd
import stat


PUBLIC = "/var/mobile/Media/.mac2jb-u1-key.pub"
PRIOR = "/var/mobile/.ssh/authorized_keys"
PUBLIC_SHA256 = "98affc477de019ba8582b3677380f53d763f7be3a1c79c8f101241f9d9eec5c9"


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= limit:
            raise RuntimeError("unsafe input")
        data = os.read(fd, limit + 1)
        if len(data) != info.st_size:
            raise RuntimeError("changed input")
        return info, data
    finally:
        os.close(fd)


def main():
    if os.geteuid() != 0:
        raise SystemExit("HOME_KEYFILE root-required")
    account = pwd.getpwnam("mobile")
    home = account.pw_dir
    kinds = {
        "/var/mobile": "var-mobile",
        "/private/var/mobile": "private-var-mobile",
        "/var/jb/var/mobile": "jb-var-mobile",
    }
    print("HOME_KEYFILE home-kind=" + kinds.get(home, "other"))
    if not home.startswith("/") or ".." in home.split("/") or account.pw_uid != 501:
        print("HOME_KEYFILE home-ssh-dir=unsafe")
        return
    ssh_dir = os.path.join(home, ".ssh")
    key_file = os.path.join(ssh_dir, "authorized_keys")
    try:
        info = os.lstat(ssh_dir)
        directory = "safe" if (stat.S_ISDIR(info.st_mode) and info.st_uid == 501
                               and stat.S_IMODE(info.st_mode) == 0o700) else "other"
    except OSError:
        directory = "unavailable"
    print("HOME_KEYFILE home-ssh-dir=" + directory)
    try:
        info, content = read_regular(key_file, 65536)
        metadata = "safe" if (info.st_uid == 501 and info.st_nlink == 1
                              and stat.S_IMODE(info.st_mode) == 0o600) else "other"
    except (OSError, RuntimeError):
        info, content, metadata = None, b"", "unavailable"
    print("HOME_KEYFILE home-key-file=" + metadata)
    try:
        prior = os.stat(PRIOR, follow_symlinks=False)
        same = "yes" if info is not None and (info.st_dev, info.st_ino) == (prior.st_dev, prior.st_ino) else "no"
    except OSError:
        same = "unknown"
    print("HOME_KEYFILE same-file=" + same)
    print("HOME_KEYFILE final-newline=" + (
        "unavailable" if info is None else
        "yes" if not content or content.endswith(b"\n") else "no"))
    try:
        public = read_regular(PUBLIC, 512)[1]
        if hashlib.sha256(public).hexdigest() != PUBLIC_SHA256:
            key_status = "public-mismatch"
        elif metadata == "unavailable":
            key_status = "unavailable"
        else:
            blob = public.split(b" ")[1]
            matches = [line for line in content.splitlines(keepends=True) if blob in line]
            key_status = "exact-once" if matches == [b"restrict " + public] else "absent" if not matches else "different-or-multiple"
    except (OSError, RuntimeError, IndexError):
        key_status = "unavailable"
    print("HOME_KEYFILE new-key-in-home=" + key_status)


if __name__ == "__main__":
    main()
