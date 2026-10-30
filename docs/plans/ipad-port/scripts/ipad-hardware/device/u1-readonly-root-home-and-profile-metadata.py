#!/var/jb/usr/bin/python3
"""Classify root SSH home and profile backup metadata without changing the iPad.

What this code does:
1. Reads root's configured home from the account database, then checks only
   its .ssh directory and authorized_keys file types and permission modes.
2. Checks whether the fixed ClientTruth.plist has extended attributes. It
   prints no attribute names, values, plist data, or SSH key contents.
3. Checks whether BSD ls reports an ACL on that fixed plist, printing only a
   yes/no/unknown category. No application or service is started or changed.
"""

import ctypes
import json
import os
import pwd
import stat
import subprocess


PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"


def kind(path):
    try:
        st = os.lstat(path)
    except OSError:
        return "absent-or-inaccessible"
    if stat.S_ISDIR(st.st_mode):
        label = "directory"
    elif stat.S_ISREG(st.st_mode):
        label = "regular"
    else:
        label = "other"
    return f"{label}:{st.st_uid}:{stat.S_IMODE(st.st_mode):o}"


def main():
    if os.geteuid() != 0:
        raise SystemExit(65)
    home = pwd.getpwnam("root").pw_dir
    if not home.startswith("/") or ".." in home.split("/"):
        raise SystemExit(66)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        listxattr = libc.listxattr
        listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                              ctypes.c_size_t, ctypes.c_int]
        listxattr.restype = ctypes.c_ssize_t
        size = listxattr(os.fsencode(PROFILE), None, 0, 0)
        xattrs = ("present" if size > 0 else "absent" if size == 0 else
                  "unknown-errno-" + str(ctypes.get_errno()))
    except (AttributeError, OSError, TypeError):
        xattrs = "unknown"
    try:
        proc = subprocess.run(["/var/jb/usr/bin/ls", "-ld", "--", PROFILE],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=3, check=False)
        first = proc.stdout.splitlines()[0].split(None, 1)[0] if proc.stdout else b""
        acl = ("present" if first.endswith(b"+") else "absent"
               if proc.returncode == 0 and first else "unknown-exit-" + str(proc.returncode))
    except (OSError, subprocess.TimeoutExpired):
        acl = "unknown"
    print(json.dumps({"root_home": home, "ssh_dir": kind(home + "/.ssh"),
                      "authorized_keys": kind(home + "/.ssh/authorized_keys"),
                      "profile_xattrs": xattrs, "profile_acl": acl},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
