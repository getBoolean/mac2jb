#!/var/jb/usr/bin/python3
"""Classify why the newly appended mobile key is not accepted by SSH.

What this code does:
1. Reads the local account database to classify mobile's home, without
   printing a raw home path or account record.
2. Reads only the fixed staged public key and fixed authorization file to
   report whether the exact restricted line exists once. It prints no key.
3. If a fixed root-owned sshd executable exists, runs ``sshd -T`` for mobile
   with a five-second limit, keeps its output in memory, and releases only
   categorical AuthorizedKeysFile, pubkey-auth, and StrictModes results.
It neither changes SSH configuration nor restarts a service or touches USB.

Exact NewTerm invocation:
/var/jb/usr/bin/sudo -- /var/jb/usr/bin/python3 -I -S -B /var/mobile/Media/.mac2jb-u1-auth-diagnostic.py
"""

import hashlib
import os
import pwd
import stat
import subprocess


PUBLIC = "/var/mobile/Media/.mac2jb-u1-key.pub"
AUTHORIZED = "/var/mobile/.ssh/authorized_keys"
PUBLIC_SHA256 = "98affc477de019ba8582b3677380f53d763f7be3a1c79c8f101241f9d9eec5c9"
SSHD_CANDIDATES = ("/var/jb/usr/sbin/sshd", "/var/jb/usr/bin/sshd")


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_size < 0:
            raise RuntimeError("unsafe input")
        data = os.read(fd, limit + 1)
        if len(data) != info.st_size:
            raise RuntimeError("changed input")
        return data
    finally:
        os.close(fd)


def key_line_status():
    try:
        public = read_bounded(PUBLIC, 512)
        if hashlib.sha256(public).hexdigest() != PUBLIC_SHA256:
            return "public-mismatch"
        authorized = read_bounded(AUTHORIZED, 65536)
    except (OSError, RuntimeError):
        return "unavailable"
    entry = b"restrict " + public
    matches = [line for line in authorized.splitlines(keepends=True)
               if public.split(b" ")[1] in line]
    if matches == [entry]:
        return "exact-once"
    if not matches:
        return "absent"
    return "different-or-multiple"


def sshd_binary():
    for candidate in SSHD_CANDIDATES:
        try:
            info = os.stat(candidate, follow_symlinks=False)
        except OSError:
            continue
        if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and info.st_mode & 0o111 and not info.st_mode & 0o022):
            return candidate
    return None


def config_status():
    binary = sshd_binary()
    if binary is None:
        return ("absent", "unknown", "unknown", "unknown")
    try:
        result = subprocess.run(
            [binary, "-T", "-C", "user=mobile,host=localhost,addr=127.0.0.1"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
            env={"PATH": "/var/jb/usr/bin:/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return ("query-failed", "unknown", "unknown", "unknown")
    if result.returncode or len(result.stdout) > 65536:
        return ("query-failed", "unknown", "unknown", "unknown")
    settings = {}
    for raw in result.stdout.splitlines():
        parts = raw.lower().split(maxsplit=1)
        if len(parts) == 2 and parts[0] in (
                b"authorizedkeysfile", b"pubkeyauthentication", b"strictmodes"):
            settings[parts[0]] = parts[1]
    paths = settings.get(b"authorizedkeysfile", b"").split()
    if b".ssh/authorized_keys" in paths or b"/var/mobile/.ssh/authorized_keys" in paths:
        path_status = "expected-included"
    elif paths:
        path_status = "other"
    else:
        path_status = "unknown"
    def yes_no(value):
        return "yes" if value == b"yes" else "no" if value == b"no" else "unknown"
    return ("queried", path_status,
            yes_no(settings.get(b"pubkeyauthentication")),
            yes_no(settings.get(b"strictmodes")))


def main():
    if os.geteuid() != 0:
        raise SystemExit("DIAGNOSTIC root-required")
    try:
        account = pwd.getpwnam("mobile")
        home = "expected" if account.pw_dir == "/var/mobile" else "other"
        uid = "expected" if account.pw_uid == 501 else "other"
    except KeyError:
        home, uid = "unavailable", "unavailable"
    print("DIAGNOSTIC mobile-home=" + home)
    print("DIAGNOSTIC mobile-uid=" + uid)
    print("DIAGNOSTIC new-key-line=" + key_line_status())
    query, paths, pubkey, strict = config_status()
    print("DIAGNOSTIC sshd-query=" + query)
    print("DIAGNOSTIC authorizedkeysfile=" + paths)
    print("DIAGNOSTIC pubkeyauthentication=" + pubkey)
    print("DIAGNOSTIC strictmodes=" + strict)


if __name__ == "__main__":
    main()
