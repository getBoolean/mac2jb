#!/var/jb/usr/bin/python3
"""Count recent toolbox crash reports without exposing report contents.

What this code does: scans at most 2048 entries and two directory levels
under the fixed mobile CrashReporter tree, counts recent regular files whose
basenames contain the fixed MAC2JB probe name, and prints only counts. It
reads no crash-report content and changes no file or service on the iPad.
"""

import os
import stat
import time


ROOT = "/var/mobile/Library/Logs/CrashReporter"
NAME = "mac2jb"


def main():
    stack = [(ROOT, 0)]
    scanned = 0
    recent = 0
    matching = 0
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
            elif stat.S_ISREG(info.st_mode) and info.st_mtime >= threshold:
                recent += 1
                if NAME in entry.name.lower():
                    matching += 1
    print("TOOLBOX_CRASH recent=" + str(recent))
    print("TOOLBOX_CRASH matching-name=" + str(matching))


if __name__ == "__main__":
    main()
