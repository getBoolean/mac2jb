#!/var/jb/usr/bin/python3
"""Classify recent crash evidence for the U1 toolbox without exporting logs.

What this code does: reads at most 16 recent regular crash reports, each at
most 2 MiB, under the fixed mobile CrashReporter directory. It reports only
whether a report mentions MAC2JB and fixed code-signing, jetsam, or generic
kill terms. It never prints a filename, raw report, identifier, or path from
the iPad, and makes no device file or service change.
"""

import os
import stat
import time


ROOT = "/var/mobile/Library/Logs/CrashReporter"
LIMIT = 2097152


def main():
    stack = [(ROOT, 0)]
    scanned = 0
    recent = []
    threshold = time.time() - 3600
    while stack:
        directory, depth = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        scanned += len(entries)
        if scanned > 2048:
            raise SystemExit(65)
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode) and depth < 2:
                stack.append((entry.path, depth + 1))
            elif (stat.S_ISREG(info.st_mode) and info.st_mtime >= threshold
                  and 0 < info.st_size <= LIMIT):
                recent.append(entry.path)
    if len(recent) > 16:
        raise SystemExit(66)
    matches = 0
    signing = 0
    jetsam = 0
    kill = 0
    for path in recent:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                data = os.read(fd, LIMIT + 1).lower()
            finally:
                os.close(fd)
        except OSError:
            continue
        if b"mac2jb" not in data:
            continue
        matches += 1
        signing += b"codesign" in data or b"amfid" in data
        jetsam += b"jetsam" in data
        kill += b"sigkill" in data or b"kill" in data
    print("TOOLBOX_CRASH_CONTENT matching=" + str(matches))
    print("TOOLBOX_CRASH_CONTENT signing-term=" + str(signing))
    print("TOOLBOX_CRASH_CONTENT jetsam-term=" + str(jetsam))
    print("TOOLBOX_CRASH_CONTENT kill-term=" + str(kill))


if __name__ == "__main__":
    main()
