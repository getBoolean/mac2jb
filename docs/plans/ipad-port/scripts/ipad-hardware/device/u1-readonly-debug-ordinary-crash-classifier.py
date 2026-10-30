#!/var/jb/usr/bin/python3
"""Classify recent debug ordinary U1 app crash reports without exporting content.

What this code does: inspect at most 2048 entries, two levels deep, in the
two fixed mobile CrashReporter roots; prioritize up to 16 reports whose names
contain the fixed app name, then read up to 16 other recent reports from the
last 24 hours, each at most 2 MiB; count only reports mentioning this app and
code-signing, AMFI, jetsam, or kill terms. It emits counts only, never paths,
filenames, identifiers, report text, or private device data. It changes no
file, app registration, USB setting, SSH setting, or trust state.
"""

import os
import stat
import sys
import time


ROOTS = (
    "/var/mobile/Library/Logs/CrashReporter",
    "/var/jb/var/mobile/Library/Logs/CrashReporter",
)
NEEDLES = (b"mac2jb-u1-debug", b"dev.mac2jb.u1probe.debugordinary")
LIMIT = 2097152


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit(65)
    stack = [(root, 0) for root in ROOTS]
    scanned = 0
    recent = []
    threshold = time.time() - 86400
    while stack:
        directory, depth = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        scanned += len(entries)
        if scanned > 2048:
            print("DEBUG_ORDINARY_CRASH query=too-many-entries")
            return
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode) and depth < 2:
                stack.append((entry.path, depth + 1))
            elif (stat.S_ISREG(info.st_mode) and info.st_mtime >= threshold
                  and 0 < info.st_size <= LIMIT):
                recent.append((info.st_mtime, entry.path))
    recent.sort(reverse=True)
    named = [(when, path) for when, path in recent
             if "mac2jb-u1-debug" in os.path.basename(path).lower()
             or "debugordinary" in os.path.basename(path).lower()]
    selected = named[:16]
    selected_paths = {path for _, path in selected}
    selected.extend((when, path) for when, path in recent
                    if path not in selected_paths and len(selected) < 32)
    selected = selected[:32]
    truncated = len(recent) > len(selected)
    counts = {"matching": 0, "codesign": 0, "amfi": 0,
              "jetsam": 0, "kill": 0}
    for _, path in selected:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
                    continue
                data = os.read(fd, LIMIT + 1).lower()
            finally:
                os.close(fd)
        except OSError:
            continue
        if not any(needle in data for needle in NEEDLES):
            continue
        counts["matching"] += 1
        counts["codesign"] += b"codesign" in data or b"code signature" in data
        counts["amfi"] += b"amfid" in data or b"amfi" in data
        counts["jetsam"] += b"jetsam" in data
        counts["kill"] += b"sigkill" in data or b"kill" in data
    print("DEBUG_ORDINARY_CRASH query=ok truncated=" + ("yes" if truncated else "no")
          + " named=" + str(min(len(named), 99)) + " " + " ".join(
        key + "=" + str(counts[key]) for key in counts))


if __name__ == "__main__":
    main()
