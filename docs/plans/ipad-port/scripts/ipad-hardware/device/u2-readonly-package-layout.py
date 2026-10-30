#!/var/jb/usr/bin/python3
"""Classify rootless package path layout before any U2 package installation.

This read-only iPad probe asks dpkg for the installed Python package's file
list and checks the /var/jb path type. It prints only path categories, not
package contents or device identity. It does not install, modify, or restart
any package or service.
"""

import os
import stat
import subprocess


def main():
    result = subprocess.run(["/var/jb/usr/bin/dpkg", "-L", "python3"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=8)
    if result.returncode != 0 or len(result.stdout) > 256 * 1024:
        raise ValueError("dpkg list unavailable")
    paths = set(result.stdout.decode("utf-8", "strict").splitlines())
    if "/var/jb/usr/bin/python3" in paths:
        layout = "var-jb-prefix"
    elif "/usr/bin/python3" in paths:
        layout = "usr-prefix"
    else:
        layout = "other"
    info = os.lstat("/var/jb")
    kind = "symlink" if stat.S_ISLNK(info.st_mode) else (
        "directory" if stat.S_ISDIR(info.st_mode) else "other")
    architecture = subprocess.run(["/var/jb/usr/bin/dpkg", "--print-architecture"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=5)
    if architecture.returncode != 0 or len(architecture.stdout) > 64:
        raise ValueError("architecture unavailable")
    value = architecture.stdout.strip()
    arch = value.decode("ascii") if value in (b"iphoneos-arm64", b"iphoneos-arm") else "other"
    print("U2_PACKAGE_LAYOUT installed=" + layout + " jb=" + kind + " arch=" + arch)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("U2_PACKAGE_LAYOUT rejected")
        raise SystemExit(1)
