#!/var/jb/usr/bin/python3
"""Classify whether each attested debug ordinary executable reaches its parser.

What this code does: find the one installed debug ordinary admission app, hash the exact
selected executable against the private Mac attestation, and launch it with
no arguments under a five-second deadline. The audited stdout-only probe
rejects missing arguments before any IOKit call or file write. Child stdout
and stderr are discarded; only its status category leaves the iPad. It does
not modify USB, SSH, trust, registry, or system files.
"""

import glob
import hashlib
import os
import stat
import subprocess
import sys


PATTERNS = (
    "/var/containers/Bundle/Application/*/Mac2JBU1-DebugOrdinary.app",
    "/Applications/Mac2JBU1-DebugOrdinary.app",
    "/var/jb/Applications/Mac2JBU1-DebugOrdinary.app",
)
VARIANTS = {
    "debug-baseline": ("mac2jb-u1-debug-baseline",
                          "a2e1b371aa1091dd295a53d721097e4ad7606f3fac60fa3f95b7f6fb901a22e9"),
    "debug-setdescription": (
        "Probes/mac2jb-u1-debug-setdescription",
        "52d6f38a64c3c00eb21ee2597955a87b7e480358edb45c055b4a05c5e3ff7626"),
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in VARIANTS:
        raise SystemExit(64)
    paths = [p for pattern in PATTERNS for p in glob.glob(pattern)]
    if len(paths) != 1 or os.path.islink(paths[0]):
        raise SystemExit(65)
    relative, expected = VARIANTS[sys.argv[1]]
    executable = paths[0] + "/" + relative
    if os.path.islink(executable):
        raise SystemExit(66)
    fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1048576:
            raise SystemExit(67)
        digest = hashlib.sha256()
        total = 0
        while total <= 1048576:
            part = os.read(fd, min(65536, 1048577 - total))
            if not part:
                break
            digest.update(part)
            total += len(part)
        after = os.fstat(fd)
        if (total != info.st_size or digest.hexdigest() != expected or
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise SystemExit(68)
    finally:
        os.close(fd)
    try:
        result = subprocess.run([executable], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5)
        status = str(result.returncode)
    except subprocess.TimeoutExpired:
        status = "timeout"
    print("DEBUG_ORDINARY_STARTUP variant=" + sys.argv[1] + " status=" + status)


if __name__ == "__main__":
    main()
