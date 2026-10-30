#!/var/jb/usr/bin/python3
"""Stream the fixed profile plist's ACL to a private Mac backup.

What this code does: as root, it calls Darwin's read-only acl_get_file and
acl_to_text for the exact ClientTruth.plist path, bounds the result to 64 KiB,
and writes the ACL text only to SSH stdout. The paired host script captures
those bytes directly into a mode-0600 file outside Git and /tmp. Never run
this device script in a terminal: ACL identities are private metadata.
No iPad file, profile daemon, USB state, or SSH configuration is changed.
"""

import ctypes
import os
import sys


TARGET = b"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
ACL_TYPE_EXTENDED = 0x00000100
LIMIT = 65536


def main():
    if os.geteuid() != 0:
        raise SystemExit(65)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int
    acl = libc.acl_get_file(TARGET, ACL_TYPE_EXTENDED)
    if not acl:
        raise SystemExit(66)
    try:
        length = ctypes.c_ssize_t()
        ptr = libc.acl_to_text(acl, ctypes.byref(length))
        if not ptr:
            raise SystemExit(67)
        try:
            if not 0 < length.value <= LIMIT:
                raise SystemExit(68)
            data = ctypes.string_at(ptr, length.value)
        finally:
            libc.acl_free(ptr)
    finally:
        libc.acl_free(acl)
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
