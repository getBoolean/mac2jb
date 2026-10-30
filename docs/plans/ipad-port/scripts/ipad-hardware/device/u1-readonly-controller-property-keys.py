#!/var/jb/usr/bin/python3
"""List only role-related IOUSBDeviceController property names.

What this code does: use public IOKit/CoreFoundation read-only APIs to match
controller services and copy each service's current property dictionary. It
prints only bounded, filtered key names, never values, registry IDs, serials,
addresses, or paths. No user client is opened, no USB request is sent, and no
registry or system file is changed. Run under a bounded SSH session; a loader
or permission failure is inconclusive and must not be treated as no role.
"""

import ctypes
import re


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
MAX_SERVICES = 4
MAX_KEYS = 512
MAX_MATCHES = 48
UTF8 = 0x08000100
KEY = re.compile(r"[A-Za-z0-9 ._/-]{1,127}\Z")
INTEREST = ("role", "power", "connect", "vbus", "host", "device",
            "usb", "current", "port", "attach", "state")


def main():
    io = ctypes.CDLL(IOKIT)
    cf = ctypes.CDLL(CORE)
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                               ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectRelease.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetKeysAndValues.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p))
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetCString.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        print("CONTROLLER_KEYS query=matching-unavailable")
        return
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        print("CONTROLLER_KEYS query=matching-failed")
        return
    seen = 0
    selected = set()
    try:
        while True:
            service = io.IOIteratorNext(iterator.value)
            if service == 0:
                break
            seen += 1
            try:
                if seen > MAX_SERVICES:
                    print("CONTROLLER_KEYS query=too-many-services")
                    return
                properties = ctypes.c_void_p()
                status = io.IORegistryEntryCreateCFProperties(
                    service, ctypes.byref(properties), None, 0)
                if status != 0 or not properties.value:
                    print("CONTROLLER_KEYS query=properties-unavailable")
                    return
                try:
                    count = cf.CFDictionaryGetCount(properties)
                    if not 0 <= count <= MAX_KEYS:
                        print("CONTROLLER_KEYS query=too-many-properties")
                        return
                    keys = (ctypes.c_void_p * count)()
                    values = (ctypes.c_void_p * count)()
                    cf.CFDictionaryGetKeysAndValues(properties, keys, values)
                    for key in keys:
                        if cf.CFGetTypeID(key) != cf.CFStringGetTypeID():
                            continue
                        buffer = ctypes.create_string_buffer(256)
                        if not cf.CFStringGetCString(key, buffer, len(buffer), UTF8):
                            continue
                        name = buffer.value.decode("ascii", "ignore")
                        if KEY.fullmatch(name) and any(
                                word in name.lower() for word in INTEREST):
                            selected.add(name)
                finally:
                    cf.CFRelease(properties)
            finally:
                io.IOObjectRelease(service)
        if len(selected) > MAX_MATCHES:
            print("CONTROLLER_KEYS query=too-many-matching-keys")
            return
        print("CONTROLLER_KEYS query=ok services=" + str(seen) +
              " matching-keys=" + str(len(selected)))
        for name in sorted(selected):
            print("CONTROLLER_KEY " + name)
    finally:
        io.IOObjectRelease(iterator.value)


if __name__ == "__main__":
    main()
