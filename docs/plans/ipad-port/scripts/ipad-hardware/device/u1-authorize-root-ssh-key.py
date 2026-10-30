#!/var/jb/usr/bin/python3
"""Authorize the existing Mac probe key for direct root SSH login.

What this code does:
1. Requires interactive sudo/root, reads only the fixed staged public key, and
   verifies its complete SHA-256 digest and Ed25519 grammar.
2. Derives root's actual home from the account database. It opens a safe
   existing .ssh directory and authorized_keys file without following their
   final symlinks, or creates only those two missing objects with 0700/0600.
3. Preserves every existing authorized-key byte and appends exactly one key
   line. The options disable agent, X11, port forwarding, and user rc, while
   allowing a PTY and shell so interactive root login works. The holder of
   the matching private key can run arbitrary commands as root until removed.
4. Syncs and verifies the exact append. A verified short append is truncated
   back to the old size. A power loss during append can leave a partial final
   line, but prior newline-terminated entries remain intact and cleanup is
   tracked in docs/ipad/device-cleanup-ledger.md.

It does not edit sshd configuration, restart SSH, or touch USB. Do not place
the private key on the iPad or in the repository.

Exact NewTerm invocation:
/var/jb/usr/bin/sudo -- /var/jb/usr/bin/python3 -I -S -B /var/mobile/Media/.mac2jb-u1-root-authorize.py
"""

import fcntl
import hashlib
import os
import pwd
import signal
import stat


PUBLIC = "/var/mobile/Media/.mac2jb-u1-key.pub"
PUBLIC_SHA256 = "98affc477de019ba8582b3677380f53d763f7be3a1c79c8f101241f9d9eec5c9"
OPTIONS = b"no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-user-rc "
MAX_AUTHORIZED = 65536


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_exact(fd, size):
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) < size:
        part = os.read(fd, min(8192, size - len(data)))
        require(part, "key file changed during read")
        data.extend(part)
    require(not os.read(fd, 1), "key file grew during read")
    return bytes(data)


def staged_public():
    fd = os.open(PUBLIC, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 501
                and info.st_nlink == 1 and 0 < info.st_size <= 512
                and not stat.S_IMODE(info.st_mode) & 0o022,
                "unsafe staged public key")
        public = read_exact(fd, info.st_size)
    finally:
        os.close(fd)
    require(hashlib.sha256(public).hexdigest() == PUBLIC_SHA256,
            "staged public-key digest mismatch")
    parts = public[:-1].split(b" ") if public.endswith(b"\n") else []
    require(len(parts) == 3 and parts[0] == b"ssh-ed25519"
            and len(parts[1]) == 68 and parts[2] == b"mac2jb-ipad-hardware-probe",
            "staged public-key grammar mismatch")
    return parts[1], OPTIONS + public


def checked_directory(fd, owner, label):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner
            and not stat.S_IMODE(info.st_mode) & 0o022,
            "unsafe " + label)


def checked_file(fd):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o022
            and 0 <= info.st_size <= MAX_AUTHORIZED,
            "unsafe root authorized_keys")
    return info


def main():
    require(os.geteuid() == 0, "root sudo is required")
    blob, entry = staged_public()
    account = pwd.getpwnam("root")
    require(account.pw_uid == 0 and account.pw_dir.startswith("/")
            and ".." not in account.pw_dir.split("/"),
            "unsafe root account home")
    home = os.open(account.pw_dir,
                   os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        checked_directory(home, 0, "root home")
        created_directory = False
        try:
            directory = os.open(".ssh", os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=home)
        except FileNotFoundError:
            os.mkdir(".ssh", 0o700, dir_fd=home)
            created_directory = True
            directory = os.open(".ssh", os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=home)
        try:
            checked_directory(directory, 0, "root SSH directory")
            created_file = False
            try:
                fd = os.open("authorized_keys", os.O_RDWR | os.O_APPEND
                             | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            except FileNotFoundError:
                fd = os.open("authorized_keys", os.O_RDWR | os.O_APPEND
                             | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600, dir_fd=directory)
                created_file = True
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                before = checked_file(fd)
                require(before.st_size <= MAX_AUTHORIZED - len(entry),
                        "root authorized_keys has no append headroom")
                old = read_exact(fd, before.st_size)
                require(not old or old.endswith(b"\n"),
                        "root authorized_keys lacks final newline")
                matches = [line for line in old.splitlines(keepends=True)
                           if blob in line]
                if matches:
                    require(matches == [entry],
                            "same key already present with different options")
                    os.fsync(fd)
                    print("ROOT_KEY already-authorized")
                    return
                current = os.stat("authorized_keys", dir_fd=directory,
                                  follow_symlinks=False)
                require((current.st_dev, current.st_ino)
                        == (before.st_dev, before.st_ino),
                        "root key path changed")
                require(read_exact(fd, before.st_size) == old,
                        "root key bytes changed")
                for sig in (signal.SIGHUP, signal.SIGINT,
                            signal.SIGTERM, signal.SIGQUIT):
                    signal.signal(sig, lambda signum, frame: None)
                try:
                    written = os.write(fd, entry)
                    os.fsync(fd)
                except BaseException:
                    written = -1
                after = checked_file(fd)
                current = os.stat("authorized_keys", dir_fd=directory,
                                  follow_symlinks=False)
                require((current.st_dev, current.st_ino)
                        == (before.st_dev, before.st_ino)
                        and (after.st_dev, after.st_ino)
                        == (before.st_dev, before.st_ino)
                        and (after.st_gid, stat.S_IMODE(after.st_mode))
                        == (before.st_gid, stat.S_IMODE(before.st_mode)),
                        "root key identity or metadata changed")
                observed = read_exact(fd, after.st_size)
                if observed == old + entry:
                    os.fsync(fd)
                    print("ROOT_KEY append-verified"
                          + (" directory-created" if created_directory else "")
                          + (" file-created" if created_file else ""))
                    return
                suffix = observed[len(old):] if observed.startswith(old) else b""
                if 0 < len(suffix) < len(entry) and entry.startswith(suffix):
                    os.ftruncate(fd, len(old))
                    os.fsync(fd)
                    require(read_exact(fd, len(old)) == old,
                            "root key partial rollback uncertain")
                    raise RuntimeError("short root key append rolled back")
                require(written != len(entry) or observed == old,
                        "unexpected root key contents; inspect manually")
                raise RuntimeError("root key append made no verified change")
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    finally:
        os.close(home)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, KeyError) as error:
        print("ROOT_KEY stopped: " + str(error))
        raise SystemExit(1)
