#!/var/jb/usr/bin/python3
"""Read only the exact failed v5 journal's modification time and digest.

The mtime records when the watchdog last atomically replaced the journal.
This script does not print journal contents or change any iPad state.
"""

import hashlib
import os
import stat


PATH = "/var/jb/var/lib/mac2jb-u2-native/restore-journal.json"
EXPECTED = "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    info = os.lstat(PATH)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= 2_000_000):
        raise ValueError("journal metadata changed")
    with open(PATH, "rb") as source:
        data = source.read(2_000_001)
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError("journal digest changed")
    print("U2_V5_JOURNAL_TIMING mtime-ns=" + str(info.st_mtime_ns) +
          " ctime-ns=" + str(info.st_ctime_ns) + " digest=exact")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        print("U2_V5_JOURNAL_TIMING rejected")
        raise SystemExit(1)
