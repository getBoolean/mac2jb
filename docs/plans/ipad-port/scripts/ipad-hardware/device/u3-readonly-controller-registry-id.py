#!/var/jb/usr/bin/python3
"""Print the sole IOUSBDeviceController's registry entry ID, for a trial argument.

Effect: reads IORegistry only. Matches IOUSBDeviceController, requires exactly
one, and prints `U3_CONTROLLER id=<decimal>`. The ID changes every boot, so the
HID trial runner's --controller argument has to be read on the current boot.
It opens no user client, makes no controller call and writes no file. The
caller keeps the printed value in private build/ evidence rather than in Git.
"""

import ctypes


def main():
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (
        ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IORegistryEntryGetRegistryEntryID.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64))
    io.IORegistryEntryGetRegistryEntryID.restype = ctypes.c_int32
    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    iterator = ctypes.c_uint32()
    if not matching or io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)):
        raise SystemExit("U3_CONTROLLER rejected (match)")
    try:
        first = io.IOIteratorNext(iterator.value)
        if not first:
            raise SystemExit("U3_CONTROLLER rejected (absent)")
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            io.IOObjectRelease(first)
            raise SystemExit("U3_CONTROLLER rejected (cardinality)")
        identifier = ctypes.c_uint64()
        status = io.IORegistryEntryGetRegistryEntryID(first, ctypes.byref(identifier))
        io.IOObjectRelease(first)
        if status or identifier.value == 0:
            raise SystemExit("U3_CONTROLLER rejected (id)")
        print("U3_CONTROLLER id=%d" % identifier.value)
    finally:
        io.IOObjectRelease(iterator.value)


if __name__ == "__main__":
    main()
