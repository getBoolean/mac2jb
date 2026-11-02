#!/var/jb/usr/bin/python3
"""Read the exact iPad identity and live USB description for the watchdog.

This module reads the fixed stock configuration plist, sysctl identity and
boot time, and the sole IOUSBDeviceController's registry ID and current
DeviceDescription dictionary. It returns private bytes only to its caller;
the CLI emits categories. It opens no USB user client, invokes no controller
write, sends no USB request, and writes no iPad file.
"""

import ctypes
import hashlib
import os
import plistlib


STOCK_SOURCE = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
EXPECTED_PRODUCT = "iPad14,5"
EXPECTED_BUILD = "21A329"
EXPECTED_SOURCE_SHA256 = "a0f63c8c2372ebd1ed4e49492344a5c1290c530ae8e5c66d88e9ba481792c5fa"


class SnapshotError(Exception):
    pass


def _sysctl(name):
    libc = ctypes.CDLL(None)
    function = libc.sysctlbyname
    function.argtypes = (ctypes.c_char_p, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
                         ctypes.c_size_t)
    function.restype = ctypes.c_int
    size = ctypes.c_size_t()
    if function(name, None, ctypes.byref(size), None, 0) != 0 or not 1 <= size.value <= 256:
        raise SnapshotError("sysctl unavailable")
    buffer = ctypes.create_string_buffer(size.value)
    if function(name, buffer, ctypes.byref(size), None, 0) != 0:
        raise SnapshotError("sysctl changed")
    return bytes(buffer[:size.value])


def _configuration_digest():
    details = os.stat(STOCK_SOURCE, follow_symlinks=False)
    if not 1 <= details.st_size <= 2 * 1024 * 1024:
        raise SnapshotError("stock configuration size")
    with open(STOCK_SOURCE, "rb") as source:
        data = source.read(2 * 1024 * 1024 + 1)
    if len(data) != details.st_size:
        raise SnapshotError("stock configuration changed")
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SOURCE_SHA256:
        raise SnapshotError("stock configuration digest changed")
    return digest


def _controller():
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
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
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                              ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFPropertyListCreateData.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
    cf.CFPropertyListCreateData.restype = ctypes.c_void_p
    cf.CFDataGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetBytePtr.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetBytePtr.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        raise SnapshotError("controller matching unavailable")
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        raise SnapshotError("controller query failed")
    service = io.IOIteratorNext(iterator.value)
    if not service:
        io.IOObjectRelease(iterator.value)
        raise SnapshotError("controller absent")
    try:
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            raise SnapshotError("controller ambiguous")
        identifier = ctypes.c_uint64()
        if io.IORegistryEntryGetRegistryEntryID(service, ctypes.byref(identifier)) != 0:
            raise SnapshotError("controller identity unavailable")
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(
                service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            raise SnapshotError("controller properties unavailable")
        try:
            key = cf.CFStringCreateWithCString(None, b"DeviceDescription", 0x08000100)
            if not key:
                raise SnapshotError("description key unavailable")
            try:
                value = cf.CFDictionaryGetValue(properties, key)
            finally:
                cf.CFRelease(key)
            if not value or cf.CFGetTypeID(value) != cf.CFDictionaryGetTypeID():
                raise SnapshotError("live description unavailable")
            error = ctypes.c_void_p()
            serialized = cf.CFPropertyListCreateData(
                None, value, 200, 0, ctypes.byref(error))
            if error.value:
                cf.CFRelease(error)
            if not serialized:
                raise SnapshotError("live description serialization failed")
            try:
                size = cf.CFDataGetLength(serialized)
                address = cf.CFDataGetBytePtr(serialized)
                if not 8 <= size <= 512 * 1024 or not address:
                    raise SnapshotError("live description size")
                data = ctypes.string_at(address, size)
                decoded = plistlib.loads(data)
                if not isinstance(decoded, dict) or len(decoded) != 16:
                    raise SnapshotError("live description shape")
                return str(identifier.value), data
            finally:
                cf.CFRelease(serialized)
        finally:
            cf.CFRelease(properties)
    finally:
        io.IOObjectRelease(service)
        io.IOObjectRelease(iterator.value)


def capture():
    product = _sysctl(b"hw.machine").rstrip(b"\0").decode("ascii")
    build = _sysctl(b"kern.osversion").rstrip(b"\0").decode("ascii")
    if product != EXPECTED_PRODUCT or build != EXPECTED_BUILD:
        raise SnapshotError("target build changed")
    # kern.boottime is a struct timeval; time-sync rewrites its tv_usec field
    # without a reboot, so hash only tv_sec (the first 8 bytes). The broker,
    # diagnose, and archive helpers slice identically so the sessions match.
    boot_time = _sysctl(b"kern.boottime")
    if len(boot_time) < 8:
        raise SnapshotError("boot time too short")
    boot = hashlib.sha256(boot_time[:8]).hexdigest()
    source = _configuration_digest()
    controller_id, live = _controller()
    return {
        "product_type": product,
        "os_build": build,
        "controller_id": controller_id,
        "boot_session": boot,
        "source_sha256": source,
    }, live


if __name__ == "__main__":
    try:
        identity, description = capture()
        print("U2_SNAPSHOT target=expected controller=one live=dict:16 source=read boot=read")
    except (SnapshotError, OSError, ValueError, UnicodeError):
        print("U2_SNAPSHOT rejected")
        raise SystemExit(1)
