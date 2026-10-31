#!/var/jb/usr/bin/python3
"""Bounded read-only export of fixed Apple USB-function launchd job plists.

Effect: for an allowlisted set of Apple launchd labels, reads
/System/Library/LaunchDaemons/<label>.plist if it is a regular file under
64 KiB and prints it base64-encoded. Reads nothing else; writes nothing.
"""

import base64
import os
import stat

LABELS = ("com.apple.ptpd", "com.apple.iapd", "com.apple.idamd",
          "com.apple.accessoryd", "com.apple.ptpcamerad", "com.apple.iapauthd")


def main():
    for label in LABELS:
        path = "/System/Library/LaunchDaemons/%s.plist" % label
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            print("U2_PLIST label=%s state=absent" % label)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            print("U2_PLIST label=%s state=unsafe" % label)
            continue
        with open(path, "rb") as handle:
            data = handle.read(65537)
        print("U2_PLIST label=%s state=present data=%s" %
              (label, base64.b64encode(data).decode("ascii")))
    print("U2_PLIST done")


if __name__ == "__main__":
    main()
