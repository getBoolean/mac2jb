#!/var/jb/usr/bin/python3
"""Classify U1 app bundles across the three known iPad installation roots.

What this code does: read bounded app Info.plist files from the standard app
roots and count only the known TrollStore, toolbox, platform diagnostic, and
ordinary diagnostic bundle IDs. It emits categorical counts, never paths,
container identifiers, or full plists. It does not launch an app, change app
registration, write a file, or touch USB/SSH settings.
"""

import glob
import os
import plistlib
import stat
import sys


PATTERNS = (
    "/var/containers/Bundle/Application/*/*.app",
    "/Applications/*.app",
    "/var/jb/Applications/*.app",
)
IDS = {
    "store": "com.opa334.TrollStore",
    "toolbox": "dev.mac2jb.u1probe.toolbox",
    "platform": "dev.mac2jb.u1probe.admission",
    "ordinary": "dev.mac2jb.u1probe.ordinaryadmission",
}


def category(value):
    return "0" if value == 0 else "1" if value == 1 else "many"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit(65)
    paths = [path for pattern in PATTERNS for path in glob.glob(pattern)]
    if len(paths) > 2048:
        print("APP_INVENTORY query=too-many")
        return
    counts = {key: 0 for key in IDS}
    for path in paths:
        try:
            if os.path.islink(path):
                continue
            info = path + "/Info.plist"
            item = os.lstat(info)
            if not stat.S_ISREG(item.st_mode) or not 0 < item.st_size <= 262144:
                continue
            with open(info, "rb") as stream:
                tree = plistlib.load(stream)
            if not isinstance(tree, dict):
                continue
            bundle_id = tree.get("CFBundleIdentifier")
            for key, expected in IDS.items():
                if bundle_id == expected:
                    counts[key] += 1
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            continue
    print("APP_INVENTORY query=ok " + " ".join(
        key + "=" + category(counts[key]) for key in IDS))


if __name__ == "__main__":
    main()
