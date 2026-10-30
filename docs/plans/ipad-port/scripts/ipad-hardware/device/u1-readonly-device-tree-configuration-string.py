#!/var/jb/usr/bin/python3
"""Classify device-tree configuration-string presence without exposing its value.

This bounded root payload uses read-only IOKit to open only IODeviceTree:/ and
copy its configuration-string property. It emits presence and CF type only.
It sends no USB request, opens no user client, and writes no iPad file.
"""

import ctypes


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
UTF8 = 0x08000100


def main():
    io = ctypes.CDLL(IOKIT)
    cf = ctypes.CDLL(CORE)
    io.IORegistryEntryFromPath.argtypes = (ctypes.c_uint32, ctypes.c_char_p)
    io.IORegistryEntryFromPath.restype = ctypes.c_uint32
    io.IORegistryEntryCreateCFProperty.argtypes = (
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectRelease.restype = ctypes.c_int32
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    root = io.IORegistryEntryFromPath(0, b"IODeviceTree:/")
    if not root:
        print("CONFIG_STRING query=root-unavailable")
        return
    try:
        key = cf.CFStringCreateWithCString(None, b"configuration-string", UTF8)
        if not key:
            print("CONFIG_STRING query=key-unavailable")
            return
        try:
            value = io.IORegistryEntryCreateCFProperty(root, key, None, 0)
        finally:
            cf.CFRelease(key)
        if not value:
            print("CONFIG_STRING query=ok result=absent")
            return
        try:
            result = "present-string" if cf.CFGetTypeID(value) == cf.CFStringGetTypeID() else "present-other"
            print("CONFIG_STRING query=ok result=" + result)
        finally:
            cf.CFRelease(value)
    finally:
        io.IOObjectRelease(root)


if __name__ == "__main__":
    main()
