#!/var/jb/usr/bin/python3
"""Copy the controller's existing default and live descriptions without USB writes.

This fixed root payload reads one IOUSBDeviceController's two registry
properties, requires bounded dictionaries, serializes them as binary plists,
and streams only a length-framed pair to the pinned Mac SSH client. It opens
no user client, sends no USB request, and changes no iPad file or setting.
The output may contain private device details and must never enter Git/logs.
"""

import ctypes
import os
import struct
import sys


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
UTF8 = 0x08000100
PLIST_BINARY = 200
MAX_PLIST = 512 * 1024
MAGIC = b"MAC2JB-U1-DESC\x00"


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        return 1
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
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFPropertyListCreateData.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
    cf.CFPropertyListCreateData.restype = ctypes.c_void_p
    cf.CFDataGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetBytePtr.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetBytePtr.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def copy_plist(properties, key):
        name = cf.CFStringCreateWithCString(None, key, UTF8)
        if not name:
            return None
        try:
            value = cf.CFDictionaryGetValue(properties, name)
        finally:
            cf.CFRelease(name)
        if not value or cf.CFGetTypeID(value) != cf.CFDictionaryGetTypeID():
            return None
        count = cf.CFDictionaryGetCount(value)
        if count < 1 or count > 128:
            return None
        error = ctypes.c_void_p()
        data = cf.CFPropertyListCreateData(
            None, value, PLIST_BINARY, 0, ctypes.byref(error))
        if error.value:
            cf.CFRelease(error)
        if not data:
            return None
        try:
            size = cf.CFDataGetLength(data)
            if size < 8 or size > MAX_PLIST:
                return None
            address = cf.CFDataGetBytePtr(data)
            return ctypes.string_at(address, size) if address else None
        finally:
            cf.CFRelease(data)

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        return 1
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        return 1
    service = io.IOIteratorNext(iterator.value)
    if not service:
        io.IOObjectRelease(iterator.value)
        return 1
    try:
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            return 1
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(
                service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            return 1
        try:
            default = copy_plist(properties, b"DefaultDeviceDescription")
            live = copy_plist(properties, b"DeviceDescription")
            if default is None or live is None:
                return 1
            sys.stdout.buffer.write(MAGIC + struct.pack(">II", len(default), len(live)) + default + live)
            sys.stdout.buffer.flush()
            return 0
        finally:
            cf.CFRelease(properties)
    finally:
        io.IOObjectRelease(service)
        io.IOObjectRelease(iterator.value)


if __name__ == "__main__":
    raise SystemExit(main())
