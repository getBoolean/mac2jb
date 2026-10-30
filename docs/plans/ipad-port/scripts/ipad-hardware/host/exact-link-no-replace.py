#!/usr/bin/python3
"""Create one exact-path hard link without command-line directory semantics.

This helper exists because the macOS `ln source destination` CLI treats an
existing destination directory as a container. `os.link()` maps directly to an
exact destination pathname: any pre-existing file, symlink, or directory makes
the call fail instead of creating a child entry. The caller supplies a private
regular source and the fixed absent destination, then independently verifies the
published content digest before using it.

The helper emits no path, key material, or diagnostic. It never overwrites,
renames, edits, or removes a path. Exit 0 means the destination and source were
verified as the same regular inode immediately after the atomic link operation.
"""

from __future__ import annotations

import os
import stat
import sys


def fail() -> int:
    return 1


def main() -> int:
    if len(sys.argv) != 3:
        return fail()

    source, destination = sys.argv[1:]
    try:
        source_before = os.lstat(source)
    except OSError:
        return fail()
    if not stat.S_ISREG(source_before.st_mode):
        return fail()
    if source_before.st_uid != os.getuid() or stat.S_IMODE(source_before.st_mode) != 0o600:
        return fail()
    if source_before.st_nlink != 1:
        return fail()

    try:
        os.link(source, destination, follow_symlinks=False)
    except OSError:
        return fail()

    try:
        source_after = os.lstat(source)
        destination_after = os.lstat(destination)
    except OSError:
        return fail()
    if not stat.S_ISREG(destination_after.st_mode):
        return fail()
    if (source_after.st_dev, source_after.st_ino) != (
        destination_after.st_dev,
        destination_after.st_ino,
    ):
        return fail()
    if source_after.st_nlink != 2 or destination_after.st_nlink != 2:
        return fail()
    if destination_after.st_uid != os.getuid():
        return fail()
    if stat.S_IMODE(destination_after.st_mode) != 0o600:
        return fail()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
