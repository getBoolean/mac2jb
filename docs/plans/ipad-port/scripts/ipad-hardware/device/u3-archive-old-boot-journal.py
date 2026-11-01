#!/var/jb/usr/bin/python3
"""Guarded archival of one U2/U3 restore journal left over from a previous boot.

A journal records the live USB description so it can be put back. Its recipe is
bound to the boot session it was written in, and every broker path validates
that, so after a reboot the journal can be neither confirmed nor restored - it
is unresolvable by design, and it blocks the next trial, which requires no
journal. A reboot has already made its restore target moot: USB descriptions do
not survive one, and the live description is stock again.

So this retires it rather than acting on it: the exact bytes are hard-linked
under a fixed archive name and the active name is unlinked, which keeps the
evidence on the device and leaves nothing for the broker to find. Nothing is
ever deleted, no USB controller call is made, no description is published, and a
journal from the *current* boot is refused outright - that one is resolvable
through the ordinary strict-check-and-confirm path and must not come here.

Usage: <mode> <expected-sha256> <expected-boot-session>, where mode is
--inspect (read-only), --archive or --verify. The expected digest and boot
session are supplied by the host wrapper, which pins them; this refuses unless
the active journal matches the digest exactly AND its recorded boot session
differs from the running one.
"""

import base64
import ctypes
import hashlib
import json
import os
import re
import stat
import sys


STATE = "/var/jb/var/lib/mac2jb-u2-native"
JOURNAL = STATE + "/restore-journal.json"
TAG = "U3_OLD_JOURNAL "
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_JOURNAL = 1024 * 1024


def digest(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_JOURNAL + 1)
    if len(data) > MAX_JOURNAL:
        raise ValueError("journal implausibly large")
    return hashlib.sha256(data).hexdigest(), data


def current_boot_session():
    """The running boot's session, derived exactly as the broker derives it.

    The broker takes the SHA-256 of the *raw* `kern.boottime` sysctl bytes, so
    this reads them the same way through libc. Shelling out to `sysctl -n`
    would digest a decimal rendering instead and never match, which would make
    every journal look like it came from another boot - the opposite of the
    guard this is for.
    """
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.sysctlbyname.argtypes = (ctypes.c_char_p, ctypes.c_void_p,
                                  ctypes.POINTER(ctypes.c_size_t),
                                  ctypes.c_void_p, ctypes.c_size_t)
    length = ctypes.c_size_t(0)
    if libc.sysctlbyname(b"kern.boottime", None, ctypes.byref(length), None, 0) != 0:
        raise ValueError("boot time unavailable")
    if not 1 <= length.value <= 256:
        raise ValueError("implausible boot time size")
    buffer = ctypes.create_string_buffer(length.value)
    if libc.sysctlbyname(b"kern.boottime", buffer, ctypes.byref(length), None, 0) != 0:
        raise ValueError("boot time unavailable")
    return hashlib.sha256(buffer.raw[:length.value]).hexdigest()


def recorded_boot_session(data):
    """The boot session inside the journal's base64 payload envelope."""
    envelope = json.loads(data)
    inner = json.loads(base64.b64decode(envelope["payload"], validate=True))
    return inner["recipe"]["bootSession"], inner["phase"]


def archive_path(expected):
    return "%s/restore-journal.oldboot-%s.json" % (STATE, expected[:8])


def inspect(expected, expected_boot):
    """Read-only: the active journal is exactly the one named, from another boot."""
    if not os.path.lexists(JOURNAL):
        raise ValueError("no active journal")
    info = os.lstat(JOURNAL)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("active journal is not a regular file")
    actual, data = digest(JOURNAL)
    if actual != expected:
        raise ValueError("active journal is not the expected one")
    # The whole justification for retiring rather than resolving it. A journal
    # from this boot is resolvable and must never reach this tool.
    recorded, phase = recorded_boot_session(data)
    if recorded != expected_boot:
        raise ValueError("journal boot session is not the expected one")
    if recorded == current_boot_session():
        raise ValueError("journal belongs to the running boot; resolve it normally")
    if os.path.lexists(archive_path(expected)):
        raise ValueError("an archive under this name already exists")
    return "journal=exact boot=previous phase=%s archive=absent" % phase


def archive(expected, expected_boot):
    """Hard-link the exact bytes aside, then unlink the active name."""
    inspect(expected, expected_boot)
    target = archive_path(expected)
    os.link(JOURNAL, target)
    if digest(target)[0] != expected:
        raise ValueError("archive does not match after linking")
    os.unlink(JOURNAL)
    handle = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)
    if os.path.lexists(JOURNAL):
        raise ValueError("active journal still present")
    return "archive=retained active=absent"


def verify(expected, _expected_boot):
    """The archive holds the exact bytes and no active journal remains."""
    target = archive_path(expected)
    if not os.path.lexists(target) or digest(target)[0] != expected:
        raise ValueError("archive missing or changed")
    if os.path.lexists(JOURNAL):
        raise ValueError("an active journal is present")
    return "archive=verified active=absent"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    if len(sys.argv) != 4 or sys.argv[1] not in ("--inspect", "--archive", "--verify"):
        raise ValueError("usage: --inspect|--archive|--verify SHA256 BOOT_SESSION")
    expected, expected_boot = sys.argv[2], sys.argv[3]
    if not HEX64.match(expected) or not expected_boot.strip():
        raise ValueError("bad expected digest or boot session")
    modes = {"--inspect": inspect, "--archive": archive, "--verify": verify}
    print(TAG + modes[sys.argv[1]](expected, expected_boot), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(TAG + "rejected (%s)" % error, flush=True)
        raise SystemExit(1)
