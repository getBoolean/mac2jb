#!/var/jb/usr/bin/python3
"""Bounded read-only export of every mac2jb U2 file needed for a Wi-Fi restore.

Effect: lists and reads (never writes) regular files in the fixed U2 state
directory, mac2jb launchd plists, and mac2jb U2 binaries under rootless
libexec, plus the kernel boot session uuid. Prints each as path, mode, uid,
size, SHA-256 and base64 bytes. Sockets/locks are listed without content.
"""

import base64
import hashlib
import os
import stat
import ctypes

ROOTS = (("/var/jb/var/lib/mac2jb-u2-native", lambda n: True),
         ("/var/jb/Library/LaunchDaemons", lambda n: n.startswith("dev.mac2jb.u2")),
         ("/var/jb/usr/libexec", lambda n: n.startswith(".mac2jb-u2") or n.startswith("mac2jb-u2")))
LIMIT = 16 * 1024 * 1024


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    buffer = ctypes.create_string_buffer(64)
    size = ctypes.c_size_t(len(buffer))
    ok = libc.sysctlbyname(b"kern.bootsessionuuid", buffer, ctypes.byref(size), None, 0) == 0
    token = hashlib.sha256(buffer.value).hexdigest() if ok else "unknown"
    print("U2_KIT boot-sha256=%s" % token)
    for root, keep in ROOTS:
        try:
            names = sorted(os.listdir(root))
        except FileNotFoundError:
            print("U2_KIT root=%s absent" % root)
            continue
        for name in names:
            if not keep(name):
                continue
            path = os.path.join(root, name)
            info = os.lstat(path)
            kind = ("file" if stat.S_ISREG(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode)
                    else "dir" if stat.S_ISDIR(info.st_mode) else "other")
            head = "U2_KIT path=%s kind=%s mode=%o uid=%d links=%d size=%d" % (
                path, kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink, info.st_size)
            if kind != "file" or info.st_size > LIMIT:
                print(head)
                continue
            with open(path, "rb") as handle:
                data = handle.read(LIMIT + 1)
            print("%s sha256=%s data=%s" % (head, hashlib.sha256(data).hexdigest(),
                                            base64.b64encode(data).decode("ascii")))
    print("U2_KIT done")


if __name__ == "__main__":
    main()
