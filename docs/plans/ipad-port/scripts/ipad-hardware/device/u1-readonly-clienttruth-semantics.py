#!/var/jb/usr/bin/python3
"""Classify the one nested ClientTruth.plist input to cleanRestrictions().

What this code does:
1. Opens only the fixed plist with O_NOFOLLOW, requires a regular file no
   larger than 1 MiB, and parses it locally with Python's standard plistlib.
2. Looks only for the fixed nested removedSystemAppBundleIDs.values array.
   It prints fixed presence/type categories, never plist values or raw bytes.
3. It performs no file write and does not invoke TrollStore, profiled, SSH,
   USB, app registration, or installation. A nonempty list means TrollStore
   might remove entries; this probe does not guess which are removable apps.

Exact NewTerm invocation if direct root SSH is unavailable:
/var/jb/usr/bin/sudo -- /var/jb/usr/bin/python3 -I -S -B /var/mobile/Media/.mac2jb-u1-clienttruth-semantics.py
"""

import os
import plistlib
import stat


TARGET = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
LIMIT = 1048576


def main():
    if os.geteuid() != 0:
        raise SystemExit("CLIENTTRUTH_SEMANTIC root-required")
    try:
        fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= LIMIT:
                print("CLIENTTRUTH_SEMANTIC plist=unsafe")
                return
            data = os.read(fd, LIMIT + 1)
            if len(data) != info.st_size:
                print("CLIENTTRUTH_SEMANTIC plist=changed")
                return
        finally:
            os.close(fd)
    except OSError:
        print("CLIENTTRUTH_SEMANTIC plist=unavailable")
        return
    try:
        tree = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException):
        print("CLIENTTRUTH_SEMANTIC plist=unparseable")
        return
    if not isinstance(tree, dict):
        print("CLIENTTRUTH_SEMANTIC plist=non-dictionary")
        return
    print("CLIENTTRUTH_SEMANTIC plist=dictionary")
    node = tree
    for key in ("com.apple.lsd.appremoval", "clientRestrictions", "union",
                "removedSystemAppBundleIDs"):
        node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            print("CLIENTTRUTH_SEMANTIC values=absent")
            print("CLIENTTRUTH_SEMANTIC cleanup-write=not-reached")
            return
    if not isinstance(node, dict):
        print("CLIENTTRUTH_SEMANTIC values=unexpected-type")
        print("CLIENTTRUTH_SEMANTIC cleanup-write=not-reached")
        return
    values = node.get("values")
    if values is None:
        print("CLIENTTRUTH_SEMANTIC values=absent")
        print("CLIENTTRUTH_SEMANTIC cleanup-write=not-reached")
    elif not isinstance(values, list):
        print("CLIENTTRUTH_SEMANTIC values=unexpected-type")
        print("CLIENTTRUTH_SEMANTIC cleanup-write=not-reached")
    elif not values:
        print("CLIENTTRUTH_SEMANTIC values=empty")
        print("CLIENTTRUTH_SEMANTIC cleanup-write=not-reached")
    else:
        print("CLIENTTRUTH_SEMANTIC values=nonempty")
        print("CLIENTTRUTH_SEMANTIC cleanup-write=possible")


if __name__ == "__main__":
    main()
