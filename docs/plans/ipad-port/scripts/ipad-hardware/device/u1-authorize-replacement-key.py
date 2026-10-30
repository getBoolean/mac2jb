#!/var/jb/usr/bin/python3
"""Authorize one digest-pinned replacement key for mobile SSH.

What this code does:
1. Requires root via the owner's NewTerm sudo. With --staged-public, reads one
   fixed public-key file from the USB-accessible media area; otherwise reads
   one public-key line interactively from /dev/tty. The terminal may echo it.
2. Accepts only the public key whose complete line matches the Mac's durable
   replacement .pub file. Installs it with OpenSSH's ``restrict`` option.
3. Derives mobile's .ssh directory from its account database home, then opens
   only its existing .ssh directory and authorized_keys file with
   no-follow descriptors; verifies ownership, modes, link count, newline and
   duplicate state; then appends one line without replacing the file or inode.
4. Defers common terminal signals through the short append, sync, and exact
   byte reconciliation. If a partial suffix is proven, it truncates only that
   suffix, syncs, and verifies the original bytes. A crash or power loss could
   still leave a partial new final line; all old lines remain untouched.
5. It never changes sshd, USB, modes, ownership, or any other iPad file.

This persistent mobile-account access grant must receive exact adversarial
review before use. Keep the old authorized entry until the new key proves
authentication over the pinned USB tunnel. This script is not a cleanup tool.
"""

import fcntl
import hashlib
import os
import pwd
import signal
import stat
import sys


EXPECTED_PUBLIC_LINE_SHA256 = "98affc477de019ba8582b3677380f53d763f7be3a1c79c8f101241f9d9eec5c9"
KEY_NAME = "authorized_keys"
MOBILE_UID = 501
MAX_EXISTING = 65536
MAX_PUBLIC_LINE = 512
STAGED_PUBLIC_FILE = "/var/mobile/Media/.mac2jb-u1-key.pub"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def read_public_line():
    if sys.argv[1:] == ["--staged-public"]:
        fd = os.open(STAGED_PUBLIC_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == MOBILE_UID
                    and info.st_nlink == 1 and info.st_size <= MAX_PUBLIC_LINE
                    and not stat.S_IMODE(info.st_mode) & 0o022,
                    "unsafe staged public-key file")
            data = os.read(fd, MAX_PUBLIC_LINE + 1)
            require(len(data) == info.st_size, "staged public-key file changed")
            return validate_public_line(data)
        finally:
            os.close(fd)
    require(not sys.argv[1:], "unsupported helper arguments")
    sys.stdout.write("Paste the replacement public-key line, then Return: ")
    sys.stdout.flush()
    terminal = os.open("/dev/tty", os.O_RDONLY | os.O_CLOEXEC)
    try:
        line = bytearray()
        while len(line) <= MAX_PUBLIC_LINE:
            chunk = os.read(terminal, 1)
            require(chunk, "public-key input ended")
            line.extend(chunk)
            if chunk == b"\n":
                break
        require(len(line) <= MAX_PUBLIC_LINE and line.endswith(b"\n"), "public-key line too long")
    finally:
        os.close(terminal)
    return validate_public_line(bytes(line))


def validate_public_line(public_line):
    require(hashlib.sha256(public_line).hexdigest() == EXPECTED_PUBLIC_LINE_SHA256,
            "public-key digest mismatch")
    parts = public_line[:-1].split(b" ")
    require(len(parts) == 3 and parts[0] == b"ssh-ed25519"
            and parts[2] == b"mac2jb-ipad-hardware-probe"
            and len(parts[1]) == 68, "public-key grammar mismatch")
    return parts[1], b"restrict " + public_line


def read_exact(fd, size):
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) < size:
        chunk = os.read(fd, min(8192, size - len(data)))
        require(chunk, "authorized_keys changed during read")
        data.extend(chunk)
    require(not os.read(fd, 1), "authorized_keys grew during read")
    return bytes(data)


def same_target(directory, before, fd, expected_size=None):
    after = os.fstat(fd)
    current = os.stat(KEY_NAME, dir_fd=directory, follow_symlinks=False)
    require(after.st_ino == before.st_ino and after.st_dev == before.st_dev
            and current.st_ino == before.st_ino and current.st_dev == before.st_dev
            and stat.S_ISREG(after.st_mode)
            and after.st_uid == before.st_uid and after.st_gid == before.st_gid
            and stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
            and after.st_nlink == 1, "authorized_keys identity or metadata changed; inspect manually")
    if expected_size is not None:
        require(after.st_size == expected_size,
                "authorized_keys size changed; inspect manually")
    return after


def reconcile(fd, directory, before, old, entry, error, initial_sync_ok):
    after = same_target(directory, before, fd)
    require(after.st_size <= len(old) + len(entry),
            "authorized_keys grew unexpectedly; inspect manually")
    observed = read_exact(fd, after.st_size)
    if observed == old + entry:
        if not initial_sync_ok:
            try:
                os.fsync(fd)
            except OSError:
                return "committed-visible-sync-uncertain; inspect before reboot"
        try:
            require(read_exact(fd, len(old) + len(entry)) == observed,
                    "authorized_keys changed after sync")
            same_target(directory, before, fd, len(old) + len(entry))
        except (OSError, RuntimeError):
            return "committed-visible-final-verification-uncertain; inspect manually"
        return "restricted-append-verified"
    if observed == old:
        require(error is not None, "append made no change; inspect manually")
        raise RuntimeError("append made no change; original bytes verified")
    suffix = observed[len(old):] if observed.startswith(old) else b""
    require(observed.startswith(old) and 0 < len(suffix) < len(entry)
            and entry.startswith(suffix),
            "unexpected authorized_keys bytes; inspect manually")
    try:
        os.ftruncate(fd, len(old))
        os.fsync(fd)
        require(read_exact(fd, len(old)) == old
                and same_target(directory, before, fd, len(old)).st_size == len(old),
                "rollback verification failed")
    except (OSError, RuntimeError):
        raise RuntimeError("partial suffix recovery uncertain; inspect manually")
    raise RuntimeError("partial append rolled back; original bytes verified")


def main():
    require(os.geteuid() == 0, "root sudo is required")
    blob, entry = read_public_line()
    account = pwd.getpwnam("mobile")
    require(account.pw_uid == MOBILE_UID and account.pw_dir.startswith("/")
            and ".." not in account.pw_dir.split("/"),
            "unsafe mobile account home")
    directory = os.open(os.path.join(account.pw_dir, ".ssh"),
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        ds = os.fstat(directory)
        dm = stat.S_IMODE(ds.st_mode)
        require(stat.S_ISDIR(ds.st_mode) and ds.st_uid == MOBILE_UID
                and dm & 0o700 == 0o700 and not dm & 0o022,
                "unsafe mobile SSH directory")
        fd = os.open(KEY_NAME,
                     os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = os.fstat(fd)
            mode = stat.S_IMODE(before.st_mode)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == MOBILE_UID
                    and before.st_nlink == 1 and not mode & 0o022
                    and mode & 0o600 == 0o600
                    and 0 <= before.st_size <= MAX_EXISTING,
                    "unsafe authorized_keys metadata")
            old = read_exact(fd, before.st_size)
            require(not old or old.endswith(b"\n"),
                    "authorized_keys lacks final newline")
            matches = [line for line in old.splitlines(keepends=True) if blob in line]
            if matches:
                require(matches == [entry], "key already present with different options or multiple times")
                same_target(directory, before, fd)
                os.fsync(fd)
                print("REPLACEMENT_KEY already-authorized")
                return
            same_target(directory, before, fd, before.st_size)
            require(read_exact(fd, before.st_size) == old,
                    "authorized_keys changed before append")
            same_target(directory, before, fd, before.st_size)
            pending_signals = []
            for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT):
                signal.signal(sig, lambda signum, frame: pending_signals.append(signum))
            error = None
            initial_sync_ok = False
            try:
                written = os.write(fd, entry)
                if written != len(entry):
                    error = RuntimeError("short append")
                else:
                    os.fsync(fd)
                    initial_sync_ok = True
            except BaseException as caught:
                error = caught
            result = reconcile(fd, directory, before, old, entry, error, initial_sync_ok)
            if pending_signals:
                result += "-after-signal"
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    print("REPLACEMENT_KEY " + result)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print("REPLACEMENT_KEY stopped: " + str(error), file=sys.stderr)
        raise SystemExit(1)
