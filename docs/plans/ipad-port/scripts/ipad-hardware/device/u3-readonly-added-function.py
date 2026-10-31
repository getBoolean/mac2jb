#!/var/jb/usr/bin/python3
"""Read-only registry answer for one named gadget function interface.

Effect: reads IORegistry only. Given a function name, it reports whether an
IOUSBDeviceInterface whose USBDeviceFunction property is exactly that name
exists, whether it sits under the sole USB device controller, and how many
IOService clients it already has. It never opens a user client and never
attempts a configuration selector, so the open field is always reported as not
attempted; an authorized trial is what turns that into granted or denied. No
IDs, serials, registry paths, or file writes.
"""

import ctypes
import os
import re
import signal
import sys


NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")
MAX_ANCESTORS = 16
MAX_MATCHES = 32
UTF8 = 0x08000100


def timed_out(_signum, _frame):
    raise TimeoutError("deadline")


def bind():
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectConformsTo.argtypes = (ctypes.c_uint32, ctypes.c_char_p)
    io.IOObjectConformsTo.restype = ctypes.c_bool
    io.IORegistryEntryGetParentEntry.argtypes = (ctypes.c_uint32, ctypes.c_char_p,
                                                 ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetParentEntry.restype = ctypes.c_int32
    io.IORegistryEntryGetChildIterator.argtypes = (ctypes.c_uint32, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetChildIterator.restype = ctypes.c_int32
    io.IORegistryEntryGetRegistryEntryID.argtypes = (ctypes.c_uint32,
                                                     ctypes.POINTER(ctypes.c_uint64))
    io.IORegistryEntryGetRegistryEntryID.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperty.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                                   ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                             ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFStringGetLength.restype = ctypes.c_long
    cf.CFStringGetCString.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)
    return io, cf


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    if len(sys.argv) != 2 or not NAME.fullmatch(sys.argv[1]):
        raise ValueError("function name invalid")
    wanted = sys.argv[1]
    io, cf = bind()

    def string_property(entry, key_name):
        key = cf.CFStringCreateWithCString(None, key_name.encode("ascii"), UTF8)
        if not key:
            raise ValueError("key unavailable")
        try:
            value = io.IORegistryEntryCreateCFProperty(entry, key, None, 0)
        finally:
            cf.CFRelease(key)
        if not value:
            return None
        try:
            if cf.CFGetTypeID(value) != cf.CFStringGetTypeID():
                return None
            length = cf.CFStringGetLength(value)
            if length < 1 or length > 64:
                return None
            buffer = ctypes.create_string_buffer(128)
            if not cf.CFStringGetCString(value, buffer, len(buffer), UTF8):
                return None
            text = buffer.value.decode("utf-8", "replace")
            # A value that did not survive the copy intact cannot be an exact
            # match, so refuse it rather than compare a truncation.
            return text if len(text) == length else None
        finally:
            cf.CFRelease(value)

    def sole_controller_id():
        matching = io.IOServiceMatching(b"IOUSBDeviceController")
        if not matching:
            raise ValueError("matching unavailable")
        iterator = ctypes.c_uint32()
        if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
            raise ValueError("query failed")
        try:
            entry = io.IOIteratorNext(iterator.value)
            if not entry:
                raise ValueError("controller absent")
            extra = io.IOIteratorNext(iterator.value)
            if extra:
                io.IOObjectRelease(extra)
                io.IOObjectRelease(entry)
                raise ValueError("controller cardinality")
        finally:
            io.IOObjectRelease(iterator.value)
        try:
            identifier = ctypes.c_uint64()
            if io.IORegistryEntryGetRegistryEntryID(entry, ctypes.byref(identifier)) != 0:
                raise ValueError("controller id unavailable")
            return identifier.value
        finally:
            io.IOObjectRelease(entry)

    def ancestor_controller_id(entry):
        current, owned = entry, False
        try:
            for _ in range(MAX_ANCESTORS):
                parent = ctypes.c_uint32()
                if io.IORegistryEntryGetParentEntry(current, b"IOService",
                                                    ctypes.byref(parent)) != 0:
                    return None
                if not parent.value:
                    return None
                if owned:
                    io.IOObjectRelease(current)
                current, owned = parent.value, True
                if not io.IOObjectConformsTo(current, b"IOUSBDeviceController"):
                    continue
                identifier = ctypes.c_uint64()
                if io.IORegistryEntryGetRegistryEntryID(current,
                                                        ctypes.byref(identifier)) != 0:
                    return None
                return identifier.value
            return None
        finally:
            if owned:
                io.IOObjectRelease(current)

    def client_count(entry):
        children = ctypes.c_uint32()
        if io.IORegistryEntryGetChildIterator(entry, b"IOService",
                                              ctypes.byref(children)) != 0:
            raise ValueError("children unavailable")
        count = 0
        try:
            while count < 9:
                child = io.IOIteratorNext(children.value)
                if not child:
                    break
                io.IOObjectRelease(child)
                count += 1
        finally:
            io.IOObjectRelease(children.value)
        return count

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(10)
    try:
        controller = sole_controller_id()
        matching = io.IOServiceMatching(b"IOUSBDeviceInterface")
        if not matching:
            raise ValueError("matching unavailable")
        iterator = ctypes.c_uint32()
        if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
            raise ValueError("query failed")
        state, place, clients, seen = "absent", "unknown", 0, 0
        try:
            while True:
                entry = io.IOIteratorNext(iterator.value)
                if not entry:
                    break
                try:
                    seen += 1
                    if seen > MAX_MATCHES:
                        raise ValueError("match limit")
                    # Exact, case-sensitive, whole-string: a prefix or a case
                    # variant is a different function.
                    if string_property(entry, "USBDeviceFunction") != wanted:
                        continue
                    same = ancestor_controller_id(entry) == controller
                    if state == "absent" or (same and place != "same"):
                        state = "present"
                        place = "same" if same else "other"
                        clients = client_count(entry) if same else 0
                finally:
                    io.IOObjectRelease(entry)
        finally:
            io.IOObjectRelease(iterator.value)
    finally:
        signal.alarm(0)

    print("U2_ADDED_FUNCTION name=%s state=%s controller=%s clients=%d "
          "open=not-attempted" % (wanted, state, place, clients))
    print("U2_ADDED_FUNCTION done")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError, UnicodeError):
        print("U2_ADDED_FUNCTION rejected")
        raise SystemExit(1)
