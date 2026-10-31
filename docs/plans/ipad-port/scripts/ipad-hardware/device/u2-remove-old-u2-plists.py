#!/var/jb/usr/bin/python3
"""Remove exact retired U2 launchd plists so they cannot contend after a reboot.

Effect: `--inspect` is read-only. `--remove` unlinks only the named plists
from a fixed allowlist after checking each is root-owned 0644, single-link,
byte-exact, and its job is not loaded; then fsyncs the directory. Binaries,
journals, archives and the v8 job are untouched. No USB call.
Usage: --inspect|--remove LABEL...
"""

import hashlib
import os
import stat
import subprocess
import sys

DIR = "/var/jb/Library/LaunchDaemons"
LAUNCHCTL = "/var/jb/bin/launchctl"
ALLOWED = {
    "dev.mac2jb.u2.nooptrialv4": "706466045d7a93b16226da350d55b91113e7b122b7485e7419562526278f15f5",
    "dev.mac2jb.u2.nooptrialv7": "0910009ca57c33cf2c23a248a171f5b4cb729a839157b9e72b4edae4041041e3",
    "dev.mac2jb.u2.watchdog": "1d1ecfa6936c1b082983c0d7f1924ddfaef529e68bcec85df4ce292a70901364",
}


def loaded(label):
    return subprocess.run([LAUNCHCTL, "print", "system/" + label], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=6).returncode == 0


def check(label):
    path = DIR + "/" + label + ".plist"
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o644 or info.st_size > 65536):
        raise ValueError("unsafe plist " + label)
    with open(path, "rb") as handle:
        if hashlib.sha256(handle.read()).hexdigest() != ALLOWED[label]:
            raise ValueError("plist changed " + label)
    if loaded(label):
        raise ValueError("job still loaded " + label)


def main():
    mode, labels = sys.argv[1] if len(sys.argv) > 1 else "", sys.argv[2:]
    if (os.geteuid() != 0 or mode not in ("--inspect", "--remove") or not labels or
            len(set(labels)) != len(labels) or any(label not in ALLOWED for label in labels)):
        raise ValueError("fixed mode and allowlisted labels required")
    if not loaded("dev.mac2jb.u2.nooptrialv8"):
        raise ValueError("v8 broker not loaded")
    for label in labels:
        check(label)
    if mode == "--inspect":
        print("U2_PLIST_RETIRE inspect=ready count=%d" % len(labels))
        return
    directory = os.open(DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for label in labels:
            os.unlink(label + ".plist", dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)
    if any(os.path.lexists(DIR + "/" + label + ".plist") for label in labels):
        raise ValueError("plist remains")
    print("U2_PLIST_RETIRE removed=%d" % len(labels))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("U2_PLIST_RETIRE rejected (%s)" % error)
        raise SystemExit(1)
