#!/var/jb/usr/bin/python3
"""Classify only the SpringBoard marker app's fixed data-container receipt.

What this code does: scan at most 2,048 immediate app-data containers, read
bounded metadata to find exactly the marker bundle ID, then classify only its
fixed tmp receipt by type, owner, mode, link count, and exact bytes. It emits
categories only; no container ID, path, metadata, or content leaves the iPad.
It changes no app, USB, SSH, trust, system file, or data-container file.
"""

import glob
import os
import plistlib
import stat
import sys


ROOT = "/var/mobile/Containers/Data/Application"
APP_ID = "dev.mac2jb.u1probe.springboardmarker"
META = ".com.apple.mobile_container_manager.metadata.plist"
NAME = ".mac2jb-u1-springboard-marker"
CONTENT = b"MAC2JB_U1_SPRINGBOARD_REACHED_MAIN v1\n"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit(64)
    paths = glob.glob(ROOT + "/*")
    if len(paths) > 2048:
        print("MARKER_RECEIPT container=too-many receipt=unknown")
        return
    matched = []
    for path in paths:
        try:
            if os.path.islink(path) or not os.path.isdir(path):
                continue
            meta = path + "/" + META
            info = os.lstat(meta)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 8192:
                continue
            fd = os.open(meta, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                data = os.read(fd, 8193)
            finally:
                os.close(fd)
            if len(data) > 8192:
                continue
            value = plistlib.loads(data)
            if isinstance(value, dict) and value.get("MCMMetadataIdentifier") == APP_ID:
                matched.append(path)
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            continue
    if len(matched) != 1:
        print("MARKER_RECEIPT container=" + ("absent" if not matched else "many") +
              " receipt=unknown")
        return
    path = matched[0] + "/tmp/" + NAME
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        print("MARKER_RECEIPT container=one receipt=absent")
        return
    except OSError:
        print("MARKER_RECEIPT container=one receipt=other")
        return
    try:
        info = os.fstat(fd)
        data = os.read(fd, len(CONTENT) + 1)
        safe = (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == 501 and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_size == len(CONTENT) and data == CONTENT)
    finally:
        os.close(fd)
    print("MARKER_RECEIPT container=one receipt=" + ("verified" if safe else "other"))


if __name__ == "__main__":
    main()
