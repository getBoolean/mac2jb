#!/var/jb/usr/bin/python3
"""Discover USB role-related IOService class pairs without reading values.

Uses read-only IOKit iteration over at most 4096 IOService-plane entries and
prints only bounded class/parent-class counts. It emits no service names,
registry IDs, properties, paths, serials, or data. No user client, USB
request, controller command, registry write, or file write is reachable.
An incomplete or slow scan is rejected and publishes no partial inventory.
"""

import ctypes
import os
import re
import signal
import time


MAX_ENTRIES = 4096
MAX_PAIRS = 80
MAX_SECONDS = 5
CLASS = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}\Z")
INTEREST = re.compile(r"usb|typec|atc|phy|powerdelivery|portcontroller|pdcontroller", re.I)


def timeout(_signum, _frame):
    raise TimeoutError("registry scan timed out")


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    io.IORegistryCreateIterator.argtypes = (
        ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryCreateIterator.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectGetClass.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
    io.IOObjectGetClass.restype = ctypes.c_int32
    io.IORegistryEntryGetParentEntry.argtypes = (
        ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetParentEntry.restype = ctypes.c_int32

    def class_of(entry):
        buffer = ctypes.create_string_buffer(128)
        if io.IOObjectGetClass(entry, buffer) != 0:
            raise ValueError("class unavailable")
        try:
            value = buffer.value.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("unsafe class") from None
        if not CLASS.fullmatch(value):
            raise ValueError("unsafe class")
        return value

    iterator = ctypes.c_uint32()
    if io.IORegistryCreateIterator(0, b"IOService", 1, ctypes.byref(iterator)) != 0:
        raise ValueError("IOService iterator unavailable")
    deadline = time.monotonic() + MAX_SECONDS
    pairs = {}
    scanned = matches = 0
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(8)
    try:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("registry scan deadline")
            service = io.IOIteratorNext(iterator.value)
            if not service:
                break
            try:
                scanned += 1
                if scanned > MAX_ENTRIES:
                    raise ValueError("registry scan truncated")
                name = class_of(service)
                if not INTEREST.search(name):
                    continue
                parent = ctypes.c_uint32()
                if io.IORegistryEntryGetParentEntry(service, b"IOService", ctypes.byref(parent)) == 0 and parent.value:
                    try:
                        parent_name = class_of(parent.value)
                    finally:
                        io.IOObjectRelease(parent.value)
                else:
                    parent_name = "None"
                pair = (name, parent_name)
                pairs[pair] = pairs.get(pair, 0) + 1
                matches += 1
                if len(pairs) > MAX_PAIRS:
                    raise ValueError("too many class pairs")
            finally:
                io.IOObjectRelease(service)
    finally:
        signal.alarm(0)
        io.IOObjectRelease(iterator.value)
    lines = ["U2_ROLE_CLASSES scanned=%d matches=%d pairs=%d" %
             (scanned, matches, len(pairs))]
    for (name, parent), count in sorted(pairs.items()):
        lines.append("U2_ROLE_CLASS class=%s parent=%s count=%d" %
                     (name, parent, count))
    lines.append("U2_ROLE_CLASSES done")
    output = "\n".join(lines) + "\n"
    if len(output.encode("ascii")) > 8192:
        raise ValueError("output too large")
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError):
        print("U2_ROLE_CLASSES rejected")
        raise SystemExit(1)
