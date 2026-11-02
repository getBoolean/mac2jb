#!/usr/bin/env python3
"""Run the pinned Mac nonexclusive USB string-descriptor probe.

The C helper sends only bounded standard IN GET_DESCRIPTOR(STRING) requests,
without USBDeviceOpen, and returns private bytes to this process. This host
wrapper validates the helper's exact source/binary hashes and binary framing,
prints only counts and a SHA-256, and checks pinned Wi-Fi SSH both before and
after. It never writes a file or runs a command on the iPad. `--languages`
issues one descriptor-zero request; `--diagnose` reads string indices named
by the five current USB configuration descriptors.
"""

import hashlib
from pathlib import Path
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = HOST / "u2-readonly-string-descriptors.c"
SOURCE_SHA256 = "523f0442ec9ac79bbaa39818fdbe46f6b90c9a1fdd300a647450f4bb51489254"
BINARY = ROOT / "build/ipad-hardware/u2-readonly-string-descriptors"
BINARY_SHA256 = "f3e35fb54fdb671550bfd629fbbf5dcee2fee1ba2346eaaeba64c7ac4f8ea4e3"
WIRELESS = HOST / "check-pinned-wireless-ssh.py"
USB = HOST / "diagnose-usb-recognition.py"


def pinned(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum or
            hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise ValueError("probe input changed")


def connection():
    result = subprocess.run(["/usr/bin/python3", str(WIRELESS)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15)
    if result.returncode != 0 or result.stdout != (
            b"WIRELESS_SSH pinned-inputs=ok\n"
            b"WIRELESS_SSH mobile=ok\n"
            b"WIRELESS_SSH root=ok\n"):
        raise ValueError("pinned control channel unavailable")


def host_usb_ready():
    result = subprocess.run(["/usr/bin/python3", str(USB)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15)
    if (result.returncode != 0 or len(result.stdout) > 1024 or
            b"USBMUX query=ok count=1\n" not in result.stdout or
            b"IOREG raw-ipad=yes " not in result.stdout):
        raise ValueError("Mac USB iPad unavailable")


def languages(data):
    if not data.startswith(b"U2LANG1\0"):
        raise ValueError("language envelope")
    raw = data[8:]
    if (not 4 <= len(raw) <= 254 or raw[0] != len(raw) or
            raw[1] != 3 or len(raw) % 2):
        raise ValueError("language descriptor")
    ids = [int.from_bytes(raw[i:i + 2], "little")
           for i in range(2, len(raw), 2)]
    if not ids or any(not item for item in ids) or len(set(ids)) != len(ids):
        raise ValueError("language IDs")
    return ids


def strings(data):
    if not data.startswith(b"U2STR1\0\0") or len(data) < 11:
        raise ValueError("string envelope")
    language = int.from_bytes(data[8:10], "little")
    count = data[10]
    if not language or not 1 <= count <= 64:
        raise ValueError("string count/language")
    offset = 11
    found = {}
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("short string entry")
        index, size = data[offset:offset + 2]
        offset += 2
        raw = data[offset:offset + size]
        offset += size
        if (not index or index in found or len(raw) != size or
                not 4 <= size <= 254 or size % 2 or raw[0] != size or raw[1] != 3):
            raise ValueError("invalid string entry")
        raw[2:].decode("utf-16-le")
        found[index] = raw
    if offset != len(data):
        raise ValueError("trailing string data")
    return language, found


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("--languages", "--diagnose"):
        raise ValueError("invalid probe mode")
    pinned(SOURCE, SOURCE_SHA256, 32 * 1024)
    pinned(BINARY, BINARY_SHA256, 1024 * 1024)
    connection()
    host_usb_ready()
    mode = "--languages" if sys.argv[1] == "--languages" else "--strings"
    result = subprocess.run([str(BINARY), mode], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0 or len(result.stdout) > 32 * 1024:
        raise ValueError("bounded USB read unavailable")
    if mode == "--languages":
        count = len(languages(result.stdout))
        connection()
        host_usb_ready()
        print("U2_USB_STRINGS language-count=" + str(count) +
              " request=read-only connection=healthy")
    else:
        _, found = strings(result.stdout)
        connection()
        host_usb_ready()
        print("U2_USB_STRINGS resolved-count=" + str(len(found)) +
              " sha256=" + hashlib.sha256(result.stdout).hexdigest() +
              " request=read-only connection=healthy")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("U2_USB_STRINGS rejected")
        raise SystemExit(1)
