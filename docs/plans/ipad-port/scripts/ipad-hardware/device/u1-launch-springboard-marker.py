#!/var/jb/usr/bin/python3
"""Request one exact launch of the attested SpringBoard marker app.

What this code does: as mobile, find exactly one marker app, verify its main
executable against the private installed-code attestation hash supplied by
the Mac, and ask uiopen to launch its fixed bundle ID once using its explicit
--bundleid option. A bare argument is treated as a URL by this CLI. The marker C main
can only create one exclusive receipt in its own app-data tmp directory. The
app, stage, and receipt are in the cleanup ledger. This payload does not
change SSH, USB, trust, registry, or system files and emits one category.
"""

import glob
import hashlib
import os
import stat
import subprocess
import sys


APP_ID = "dev.mac2jb.u1probe.springboardmarker"
PATTERNS = (
    "/var/containers/Bundle/Application/*/Mac2JBU1-SpringBoardMarker.app",
    "/Applications/Mac2JBU1-SpringBoardMarker.app",
    "/var/jb/Applications/Mac2JBU1-SpringBoardMarker.app",
)
EXECUTABLE = "mac2jb-u1-springboard-marker"


def main():
    if os.geteuid() != 501 or len(sys.argv) != 2 or len(sys.argv[1]) != 64 or any(
            c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit(64)
    apps = [path for pattern in PATTERNS for path in glob.glob(pattern)]
    if len(apps) != 1 or os.path.islink(apps[0]):
        raise SystemExit(65)
    path = apps[0] + "/" + EXECUTABLE
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1048576:
            raise SystemExit(66)
        sha = hashlib.sha256()
        total = 0
        while total <= 1048576:
            block = os.read(fd, min(65536, 1048577 - total))
            if not block:
                break
            sha.update(block)
            total += len(block)
        after = os.fstat(fd)
        if total != before.st_size or sha.hexdigest() != sys.argv[1] or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SystemExit(67)
    finally:
        os.close(fd)
    try:
        result = subprocess.run(["/var/jb/usr/bin/uiopen", "--bundleid", APP_ID],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10)
        status = "accepted" if result.returncode == 0 else "rejected"
    except subprocess.TimeoutExpired:
        status = "timeout"
    print("MARKER_LAUNCH status=" + status)


if __name__ == "__main__":
    main()
