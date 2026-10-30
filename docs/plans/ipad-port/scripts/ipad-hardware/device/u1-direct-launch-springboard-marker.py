#!/var/jb/usr/bin/python3
"""Classify the attested marker executable's direct mobile startup boundary.

What this code does: verify the exact installed marker executable SHA-256,
then launch it once without arguments under a five-second deadline. Under the
SSH process environment its guarded C main exits 66 if TMPDIR is not its own
app-data container; 66 proves it reached main. It may create the one ledgered
receipt only if TMPDIR actually is that container. It opens no USB service and
changes no SSH, trust, registry, or system file. Only a status category leaves.
"""

import glob
import hashlib
import os
import stat
import subprocess
import sys


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
    executable = apps[0] + "/" + EXECUTABLE
    fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1048576:
            raise SystemExit(66)
        sha = hashlib.sha256()
        total = 0
        while total <= 1048576:
            part = os.read(fd, min(65536, 1048577 - total))
            if not part:
                break
            sha.update(part)
            total += len(part)
        after = os.fstat(fd)
        if total != before.st_size or sha.hexdigest() != sys.argv[1] or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SystemExit(67)
    finally:
        os.close(fd)
    try:
        result = subprocess.run([executable], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5)
        status = str(result.returncode) if result.returncode in (0, 66, -9) else "other"
    except subprocess.TimeoutExpired:
        status = "timeout"
    print("MARKER_DIRECT status=" + status)


if __name__ == "__main__":
    main()
