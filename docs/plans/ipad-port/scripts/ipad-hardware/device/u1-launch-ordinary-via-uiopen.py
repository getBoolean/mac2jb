#!/var/jb/usr/bin/python3
"""Request one SpringBoard launch of the attested ordinary U1 app.

What this code does: find exactly one installed ordinary test app, verify its
main executable's fixed SHA-256, and call uiopen with its explicit `--bundleid`
option and exact bundle ID. A bare argument is interpreted as a URL.
The app receives no arguments and its audited parser exits before IOKit or
report writing. Only a bounded launch-request category leaves the device.
This may create ordinary transient launch/log state; it does not alter USB,
SSH, trust, registry, or system files. The app is in the cleanup ledger.
"""

import glob
import hashlib
import os
import stat
import subprocess
import sys


APP_ID = "dev.mac2jb.u1probe.ordinaryadmission"
PATTERNS = (
    "/var/containers/Bundle/Application/*/Mac2JBU1-OrdinaryAdmission.app",
    "/Applications/Mac2JBU1-OrdinaryAdmission.app",
    "/var/jb/Applications/Mac2JBU1-OrdinaryAdmission.app",
)
EXECUTABLE = "mac2jb-u1-ordinary-baseline"
DIGEST = "cf28a795e1fb1feb840b3c769a0c351323cfd4847d0132922ba9a5066308bbeb"


def main():
    if len(sys.argv) != 1 or os.geteuid() != 501:
        raise SystemExit(64)
    apps = [path for pattern in PATTERNS for path in glob.glob(pattern)]
    if len(apps) != 1 or os.path.islink(apps[0]):
        raise SystemExit(65)
    path = apps[0] + "/" + EXECUTABLE
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1048576:
            raise SystemExit(66)
        digest = hashlib.sha256()
        total = 0
        while total <= 1048576:
            block = os.read(fd, min(65536, 1048577 - total))
            if not block:
                break
            digest.update(block)
            total += len(block)
        after = os.fstat(fd)
        if (total != info.st_size or digest.hexdigest() != DIGEST or
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise SystemExit(67)
    finally:
        os.close(fd)
    try:
        result = subprocess.run(["/var/jb/usr/bin/uiopen", "--bundleid", APP_ID],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10)
        category = "accepted" if result.returncode == 0 else "rejected"
    except subprocess.TimeoutExpired:
        category = "timeout"
    print("ORDINARY_UIOPEN status=" + category)


if __name__ == "__main__":
    main()
