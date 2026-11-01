#!/var/jb/usr/bin/python3
"""Raise the running U2/U3 broker's own jetsam memory limit, as root.

The broker is killed with JETSAM_REASON_MEMORY_PERPROCESSLIMIT during a
publication: its limit is the generic daemon category's 6 MB, and a Swift
binary using Foundation and IOKit exceeds that as soon as it allocates a
description. The job plist cannot raise it - launchd ignores JetsamProperties
for a third-party job, because iOS takes a daemon's jetsam properties from its
own label-keyed configuration. Taking tweak injection out of the process helped
(6.22 MB idle to 1.41 MB) but did not make the working set fit.

`memorystatus_control` does raise it, and on this kernel it needs only root -
no entitlement, so the broker's signature is unchanged. Verified by reading the
limit back through the same call.

The limit is a property of the *process*, so it is lost when launchd restarts
the broker and has to be re-applied to the new pid. That is why this is a
separate tool rather than a deployment step: it is run against whatever broker
is live, immediately before work that would otherwise kill it.

Nothing else is touched: no plist, no journal, no USB controller call, no other
process. `--inspect` only reads.

Usage: --inspect | --raise  LABEL  [MB]
"""

import ctypes
import os
import re
import struct
import subprocess
import sys


LAUNCHCTL = "/var/jb/bin/launchctl"
LABEL = re.compile(r"dev\.mac2jb\.u2\.[a-z0-9]{1,24}\Z")
TAG = "U3_BROKER_MEMLIMIT "
GET, SET = 8, 7
DEFAULT_MB = 96
MAX_MB = 256
# struct memorystatus_memlimit_properties: the active and inactive limits in MB
# with their attribute words; bit 0 of an attribute word is "fatal".
LAYOUT = "<iIiI"
FATAL = 1


def libc():
    handle = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    handle.memorystatus_control.argtypes = (ctypes.c_uint32, ctypes.c_int32,
                                            ctypes.c_uint32, ctypes.c_void_p,
                                            ctypes.c_size_t)
    handle.proc_pid_rusage.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    return handle


def broker_pid(label):
    out = subprocess.run([LAUNCHCTL, "print", "system/" + label], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, timeout=20)
    if out.returncode:
        raise ValueError("job not loaded")
    text = out.stdout.decode("utf-8", "replace")
    found = re.search(r"^\s*pid = (\d+)", text, re.M)
    if not found:
        raise ValueError("broker not running")
    runs = re.search(r"^\s*runs = (\d+)", text, re.M)
    exits = re.search(r"^\s*last exit reason = (\S+)", text, re.M)
    return (int(found.group(1)), runs.group(1) if runs else "?",
            exits.group(1) if exits else "none")


def limits(handle, pid):
    buffer = ctypes.create_string_buffer(16)
    if handle.memorystatus_control(GET, pid, 0, buffer, 16) != 0:
        raise ValueError("limit unreadable (errno %d)" % ctypes.get_errno())
    return struct.unpack(LAYOUT, buffer.raw)


def footprint(handle, pid):
    buffer = ctypes.create_string_buffer(1024)
    if handle.proc_pid_rusage(pid, 4, buffer) != 0:
        raise ValueError("footprint unavailable")
    return int.from_bytes(buffer.raw[16 + 56:24 + 56], "little") / 1048576


def report(handle, pid, runs, exit_reason):
    active, active_attr, inactive, inactive_attr = limits(handle, pid)
    return ("%spid=%s runs=%s last-exit=%s footprint=%.2fMB active=%dMB%s "
            "inactive=%dMB%s"
            % (TAG, pid, runs, exit_reason, footprint(handle, pid),
               active, "/fatal" if active_attr & FATAL else "",
               inactive, "/fatal" if inactive_attr & FATAL else ""))


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    if not 3 <= len(sys.argv) <= 4 or sys.argv[1] not in ("--inspect", "--raise"):
        raise ValueError("usage: --inspect|--raise LABEL [MB]")
    label = sys.argv[2]
    if not LABEL.match(label):
        raise ValueError("label not allowlisted")
    megabytes = int(sys.argv[3]) if len(sys.argv) == 4 else DEFAULT_MB
    if not 8 <= megabytes <= MAX_MB:
        raise ValueError("limit out of range")
    handle = libc()
    pid, runs, exit_reason = broker_pid(label)
    if sys.argv[1] == "--inspect":
        print(report(handle, pid, runs, exit_reason), flush=True)
        return
    active = limits(handle, pid)[0]
    if active >= megabytes:
        print(report(handle, pid, runs, exit_reason) + " raised=already", flush=True)
        return
    # Both limits are set, and neither is marked fatal: the point is to stop a
    # publication being killed for crossing a ceiling it was always going to
    # cross. The cap still bounds it, and the limit dies with the process.
    request = ctypes.create_string_buffer(
        struct.pack(LAYOUT, megabytes, 0, megabytes, 0), 16)
    if handle.memorystatus_control(SET, pid, 0, request, 16) != 0:
        raise ValueError("limit not raised (errno %d)" % ctypes.get_errno())
    if limits(handle, pid)[0] != megabytes:
        raise ValueError("limit did not read back as set")
    print(report(handle, pid, runs, exit_reason) + " raised=yes", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, struct.error,
            subprocess.SubprocessError) as error:
        print(TAG + "rejected (%s)" % error, flush=True)
        raise SystemExit(1)
