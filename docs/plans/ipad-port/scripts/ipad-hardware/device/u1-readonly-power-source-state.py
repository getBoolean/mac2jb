#!/var/jb/usr/bin/python3
"""Classify iPad battery external-power and charging flags without writes.

This reads one AppleSmartBattery registry service through read-only IOKit,
emitting only ExternalConnected, IsCharging, and FullyCharged booleans. It does
not print battery level, identifiers, or raw properties, and it opens no USB
user client, sends no request, or changes any file or power setting. These
flags are battery state, not a direct measurement of USB-C VBUS voltage.
"""

import ctypes


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
UTF8 = 0x08000100
SINT32 = 3


def main():
    io = ctypes.CDLL(IOKIT)
    cf = ctypes.CDLL(CORE)
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (
        ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectRelease.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetValue.argtypes = (
        ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    matching = io.IOServiceMatching(b"AppleSmartBattery")
    if not matching:
        print("POWER_SOURCE query=matching-unavailable")
        return
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        print("POWER_SOURCE query=matching-failed")
        return
    service = io.IOIteratorNext(iterator.value)
    if not service:
        io.IOObjectRelease(iterator.value)
        print("POWER_SOURCE query=no-service")
        return
    try:
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            print("POWER_SOURCE query=multiple-services")
            return
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(
                service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            print("POWER_SOURCE query=properties-unavailable")
            return
        try:
            def flag(key):
                name = cf.CFStringCreateWithCString(None, key, UTF8)
                if not name:
                    return "unknown"
                try:
                    value = cf.CFDictionaryGetValue(properties, name)
                finally:
                    cf.CFRelease(name)
                if not value:
                    return "unknown"
                type_id = cf.CFGetTypeID(value)
                if type_id == cf.CFBooleanGetTypeID():
                    return "yes" if cf.CFBooleanGetValue(value) else "no"
                if type_id == cf.CFNumberGetTypeID():
                    number = ctypes.c_int32()
                    if cf.CFNumberGetValue(value, SINT32, ctypes.byref(number)) and number.value in (0, 1):
                        return "yes" if number.value else "no"
                return "unknown"

            print("POWER_SOURCE query=ok external=" + flag(b"ExternalConnected") +
                  " charging=" + flag(b"IsCharging") +
                  " full=" + flag(b"FullyCharged"))
        finally:
            cf.CFRelease(properties)
    finally:
        io.IOObjectRelease(service)
        io.IOObjectRelease(iterator.value)


if __name__ == "__main__":
    main()
