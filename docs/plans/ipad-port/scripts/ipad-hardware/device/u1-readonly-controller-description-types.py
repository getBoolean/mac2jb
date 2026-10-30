#!/var/jb/usr/bin/python3
"""Classify the controller's two description properties without changing USB.

This script copies the existing IOUSBDeviceController registry properties with
read-only IOKit, checks only DefaultDeviceDescription and DeviceDescription,
and emits their CoreFoundation type and bounded top-level count. It does not
print property values, open a user client, issue a USB request, or write a file.
"""

import ctypes


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
UTF8 = 0x08000100


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
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFArrayGetTypeID.restype = ctypes.c_ulong
    cf.CFDataGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFArrayGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFDataGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFStringGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFStringGetLength.restype = ctypes.c_long
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def classify(properties, key):
        name = cf.CFStringCreateWithCString(None, key, UTF8)
        if not name:
            return "unavailable"
        try:
            value = cf.CFDictionaryGetValue(properties, name)
        finally:
            cf.CFRelease(name)
        if not value:
            return "absent"
        type_id = cf.CFGetTypeID(value)
        for kind, expected, count in (
                ("dict", cf.CFDictionaryGetTypeID(), cf.CFDictionaryGetCount),
                ("array", cf.CFArrayGetTypeID(), cf.CFArrayGetCount),
                ("data", cf.CFDataGetTypeID(), cf.CFDataGetLength),
                ("string", cf.CFStringGetTypeID(), cf.CFStringGetLength)):
            if type_id == expected:
                size = count(value)
                return kind + ":" + (str(size) if 0 <= size <= 9999 else "large")
        return "other"

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        print("DESCRIPTION_TYPES query=matching-unavailable")
        return
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        print("DESCRIPTION_TYPES query=matching-failed")
        return
    service = io.IOIteratorNext(iterator.value)
    if not service:
        io.IOObjectRelease(iterator.value)
        print("DESCRIPTION_TYPES query=no-service")
        return
    try:
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            print("DESCRIPTION_TYPES query=multiple-services")
            return
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(
                service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            print("DESCRIPTION_TYPES query=properties-unavailable")
            return
        try:
            default = classify(properties, b"DefaultDeviceDescription")
            live = classify(properties, b"DeviceDescription")
            print("DESCRIPTION_TYPES query=ok default=" + default + " live=" + live)
        finally:
            cf.CFRelease(properties)
    finally:
        io.IOObjectRelease(service)
        io.IOObjectRelease(iterator.value)


if __name__ == "__main__":
    main()
