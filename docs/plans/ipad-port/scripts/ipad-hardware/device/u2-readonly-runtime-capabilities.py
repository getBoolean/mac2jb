#!/var/jb/usr/bin/python3
"""Classify rootless watchdog runtime paths without changing the iPad.

This script checks only file types, ownership, and executable flags for fixed
launchd, Python, package-manager, and trust tooling paths. It prints categories
only. It never opens a private key, launches a daemon, changes a service,
installs a package, or writes a file.
"""

import os
import stat
import base64
import ctypes
import fcntl
import hashlib
import json
import plistlib
import socket


PATHS = {
    "launchctl-system": "/bin/launchctl",
    "launchctl-rootless": "/var/jb/bin/launchctl",
    "python": "/var/jb/usr/bin/python3",
    "ldid": "/var/jb/usr/bin/ldid",
    "dpkg": "/var/jb/usr/bin/dpkg",
    "jbctl": "/var/jb/usr/bin/jbctl",
    "daemon-dir": "/var/jb/Library/LaunchDaemons",
    "libexec-dir": "/var/jb/usr/libexec",
}


def classify(path):
    try:
        details = os.stat(path)
    except OSError:
        return "absent"
    if details.st_uid != 0:
        return "other-owner"
    if stat.S_ISDIR(details.st_mode):
        return "directory"
    if stat.S_ISREG(details.st_mode) and details.st_mode & 0o111:
        return "executable"
    return "other"


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("U2_RUNTIME rejected")
    else:
        for name, path in PATHS.items():
            print("U2_RUNTIME " + name + "=" + classify(path))
        ready = (all((base64, ctypes, fcntl, hashlib, json, plistlib, socket)) and
                 os.link in os.supports_dir_fd and os.open in os.supports_dir_fd and
                 os.unlink in os.supports_dir_fd)
        print("U2_RUNTIME stdlib=" + ("ready" if ready else "limited"))
