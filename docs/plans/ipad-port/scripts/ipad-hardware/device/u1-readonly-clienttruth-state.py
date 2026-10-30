#!/var/jb/usr/bin/python3
"""Inspect the fixed TrollStore cleanRestrictions input without reading it.

What this code does:
1. Runs under the owner's interactive NewTerm sudo and checks only the fixed
   configuration-profiles directory and ClientTruth.plist final components.
2. Reports fixed categories for presence, type, owner, permissions, size, and
   whether a no-follow read-only open succeeds. It never reads plist bytes or
   prints any path, identifier, metadata value, or diagnostic from the file.
3. Makes no file write, invokes no TrollStore/profiled code, and does not
   alter SSH or USB. The incidental access metadata of a read-only open may
   change under the filesystem's normal behavior.

Exact NewTerm invocation:
/var/jb/usr/bin/sudo -- /var/jb/usr/bin/python3 -I -S -B /var/mobile/Media/.mac2jb-u1-clienttruth-state.py
"""

import os
import stat


PARENT = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles"
TARGET = PARENT + "/ClientTruth.plist"


def main():
    if os.geteuid() != 0:
        raise SystemExit("CLIENTTRUTH root-required")
    try:
        parent = os.lstat(PARENT)
    except OSError:
        print("CLIENTTRUTH parent=unavailable")
        print("CLIENTTRUTH target=unknown")
        return
    if not stat.S_ISDIR(parent.st_mode):
        print("CLIENTTRUTH parent=other")
        print("CLIENTTRUTH target=unknown")
        return
    print("CLIENTTRUTH parent=directory")
    try:
        target = os.lstat(TARGET)
    except FileNotFoundError:
        print("CLIENTTRUTH target=absent")
        return
    except OSError:
        print("CLIENTTRUTH target=inaccessible")
        return
    if stat.S_ISLNK(target.st_mode):
        print("CLIENTTRUTH target=symlink")
        return
    if not stat.S_ISREG(target.st_mode):
        print("CLIENTTRUTH target=other")
        return
    print("CLIENTTRUTH target=regular")
    print("CLIENTTRUTH owner=" + ("root" if target.st_uid == 0 else "other"))
    mode = stat.S_IMODE(target.st_mode)
    print("CLIENTTRUTH mode=" + (
        "owner-only" if mode & 0o077 == 0 else "shared"))
    print("CLIENTTRUTH size=" + (
        "empty" if target.st_size == 0 else
        "small" if 0 < target.st_size <= 1048576 else
        "large" if target.st_size <= 4194304 else "oversize"))
    try:
        fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            readable = (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino)
        finally:
            os.close(fd)
    except OSError:
        readable = False
    print("CLIENTTRUTH readable=" + ("yes" if readable else "no"))


if __name__ == "__main__":
    main()
