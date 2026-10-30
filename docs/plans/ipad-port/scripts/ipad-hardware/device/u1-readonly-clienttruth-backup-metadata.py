#!/var/jb/usr/bin/python3
"""Stream bounded metadata and digest for a private ClientTruth backup.

What this code does:
1. Opens only the fixed ClientTruth.plist with O_NOFOLLOW as root and reads at
   most 1 MiB through one descriptor.
2. Emits one JSON object with its SHA-256, size, owner/group/mode, inode/device,
   times, flags, and an xattr-presence category. It emits no plist bytes or
   values. The Mac backup runner stores this JSON privately, outside Git.
3. Makes no device file write and does not call TrollStore, profiled, SSH
   configuration, app registration, or USB APIs.

The host runner sends this exact repository file to isolated root Python on
stdin over pinned USB SSH; it is not stored on the iPad.
"""

import hashlib
import json
import os
import stat


TARGET = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
LIMIT = 1048576


def main():
    if os.geteuid() != 0:
        raise SystemExit(65)
    fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= LIMIT:
            raise SystemExit(66)
        content = bytearray()
        while len(content) <= LIMIT:
            chunk = os.read(fd, min(65536, LIMIT + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(fd)
        if len(content) != before.st_size or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise SystemExit(67)
        try:
            xattrs = "present" if os.listxattr(fd) else "absent"
        except (AttributeError, OSError, TypeError):
            xattrs = "unknown"
        record = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": before.st_size,
            "uid": before.st_uid,
            "gid": before.st_gid,
            "mode": stat.S_IMODE(before.st_mode),
            "dev": before.st_dev,
            "ino": before.st_ino,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "flags": getattr(before, "st_flags", None),
            "xattrs": xattrs,
        }
    finally:
        os.close(fd)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
