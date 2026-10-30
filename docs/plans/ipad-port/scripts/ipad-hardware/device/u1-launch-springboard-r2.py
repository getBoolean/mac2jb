#!/var/jb/usr/bin/python3
"""Request one exact launch of an attested R2 collector via SpringBoard.

What this code does: mobile finds exactly one fixed app bundle, hashes its
installed executable against the Mac's private attestation, and invokes
`uiopen --bundleid` once. The app makes read-only IOKit queries and may create
one exclusive bounded JSON report in its own tmp container. This helper itself
does not write a file or change USB, SSH, trust, or system configuration.
Its accepted status is only a request; the separate report check proves run.
"""

import glob
import hashlib
import os
import stat
import subprocess
import sys


APPS = {
    "baseline": ("Mac2JBU1-R2Baseline.app", "dev.mac2jb.u1probe.r2baseline"),
    "setdescription": ("Mac2JBU1-R2SetDescription.app", "dev.mac2jb.u1probe.r2setdescription"),
}
ROOTS = ("/var/containers/Bundle/Application/*/", "/Applications/", "/var/jb/Applications/")


def main():
    if (os.geteuid() != 501 or len(sys.argv) != 3 or sys.argv[1] not in APPS or
            len(sys.argv[2]) != 64 or any(c not in "0123456789abcdef" for c in sys.argv[2])):
        raise SystemExit(64)
    label = sys.argv[1]
    name, app_id = APPS[label]
    apps = [path for root in ROOTS for path in glob.glob(root + name)]
    if len(apps) != 1 or os.path.islink(apps[0]):
        raise SystemExit(65)
    fd = os.open(apps[0] + "/mac2jb-u1-springboard-r2", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1_048_576:
            raise SystemExit(66)
        data = os.read(fd, 1_048_577)
        after = os.fstat(fd)
        if (len(data) != before.st_size or hashlib.sha256(data).hexdigest() != sys.argv[2] or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise SystemExit(67)
    finally:
        os.close(fd)
    try:
        result = subprocess.run(["/var/jb/usr/bin/uiopen", "--bundleid", app_id],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10)
        status = "accepted" if result.returncode == 0 else "rejected"
    except subprocess.TimeoutExpired:
        status = "timeout"
    print("SPRINGBOARD_R2_LAUNCH profile=" + label + " status=" + status)


if __name__ == "__main__":
    main()
