#!/var/jb/usr/bin/python3
"""Classify a fixed entitlement-free C probe's launch as mobile.

What this code does: verify the exact staged root-owned executable's type,
mode, size, and SHA-256, run only that binary with a five-second limit, and
report whether its fixed main marker appeared or the child was killed. The
child only writes a marker to stdout. This script does not write a file, open
IOKit, change USB or SSH, or alter code trust. If the staged bytes differ it
refuses to launch them.
"""

import hashlib
import os
import stat
import subprocess
import sys


PATH = "/var/mobile/Media/.mac2jb-u1-admission-smoke"
SIZE = 49840
SHA256 = "9d4750ca37548b30653c4550b1307b5fc5da5a65e9ec0cadeaaf23f002e231e0"
MARKER = b"U1_ADMISSION_SMOKE reached-main\n"


def main():
    if os.geteuid() != 501 or len(sys.argv) != 1:
        print("SMOKE_RUN rejected")
        return
    try:
        info = os.lstat(PATH)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o755 or
                info.st_size != SIZE):
            print("SMOKE_RUN rejected")
            return
        digest = hashlib.sha256()
        with open(PATH, "rb", buffering=0) as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        if digest.hexdigest() != SHA256:
            print("SMOKE_RUN rejected")
            return
        result = subprocess.run((PATH,), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5,
                                check=False)
    except subprocess.TimeoutExpired:
        print("SMOKE_RUN timeout")
        return
    except OSError:
        print("SMOKE_RUN launch-error")
        return
    if result.returncode == 0 and result.stdout == MARKER:
        print("SMOKE_RUN reached-main")
    elif result.returncode < 0:
        print("SMOKE_RUN signal-" + str(-result.returncode))
    else:
        print("SMOKE_RUN other")


if __name__ == "__main__":
    main()
