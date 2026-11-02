#!/var/jb/usr/bin/python3
"""List bounded USB controller CurrentState key names without changing it.

This reads one IOUSBDeviceController registry property dictionary through
IOKit, serializes only its CurrentState dictionary in memory, and prints
allowlisted key names and types. No values, device IDs, or raw plist leave
the iPad. It opens no controller user client and calls no mutation API.
"""

import ctypes
import os
import plistlib
import re


KEY = re.compile(r"[A-Za-z0-9_. -]{1,100}\Z")


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    force_off = getattr(io, "IOUSBDeviceControllerForceOffBus", None)
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectGetClass.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
    io.IOObjectGetClass.restype = ctypes.c_int32
    io.IORegistryEntryGetParentEntry.argtypes = (ctypes.c_uint32, ctypes.c_char_p,
                                                  ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetParentEntry.restype = ctypes.c_int32
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
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p))
    cf.CFPropertyListCreateData.restype = ctypes.c_void_p
    cf.CFDataGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetBytePtr.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetBytePtr.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        raise ValueError("matching unavailable")
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        raise ValueError("service query failed")
    try:
        service = io.IOIteratorNext(iterator.value)
        if not service:
            raise ValueError("no controller")
        try:
            extra = io.IOIteratorNext(iterator.value)
            if extra:
                io.IOObjectRelease(extra)
                raise ValueError("multiple controllers")
            parent_classes = []
            current = service
            owns_current = False
            try:
                for _ in range(10):
                    class_name = ctypes.create_string_buffer(128)
                    if io.IOObjectGetClass(current, class_name) != 0:
                        raise ValueError("class unavailable")
                    name = class_name.value.decode("ascii", "strict")
                    if not re.fullmatch(r"[A-Za-z0-9_]{1,100}", name):
                        raise ValueError("unsafe class")
                    parent_classes.append(name)
                    parent = ctypes.c_uint32()
                    status = io.IORegistryEntryGetParentEntry(
                        current, b"IOService", ctypes.byref(parent))
                    if owns_current:
                        io.IOObjectRelease(current)
                        owns_current = False
                    if status != 0 or not parent.value:
                        break
                    current = parent.value
                    owns_current = True
            finally:
                if owns_current:
                    io.IOObjectRelease(current)
            properties = ctypes.c_void_p()
            if io.IORegistryEntryCreateCFProperties(
                    service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
                raise ValueError("registry unavailable")
            try:
                name = cf.CFStringCreateWithCString(None, b"CurrentState", 0x08000100)
                if not name:
                    raise ValueError("key unavailable")
                try:
                    state = cf.CFDictionaryGetValue(properties, name)
                finally:
                    cf.CFRelease(name)
                if not state or cf.CFGetTypeID(state) != cf.CFDictionaryGetTypeID():
                    raise ValueError("CurrentState unavailable")
                error = ctypes.c_void_p()
                data = cf.CFPropertyListCreateData(None, state, 200, 0,
                                                    ctypes.byref(error))
                if error.value:
                    cf.CFRelease(error)
                if not data:
                    raise ValueError("serialization unavailable")
                try:
                    size = cf.CFDataGetLength(data)
                    if not 8 <= size <= 8192:
                        raise ValueError("state too large")
                    content = ctypes.string_at(cf.CFDataGetBytePtr(data), size)
                finally:
                    cf.CFRelease(data)
            finally:
                cf.CFRelease(properties)
        finally:
            io.IOObjectRelease(service)
    finally:
        io.IOObjectRelease(iterator.value)
    state = plistlib.loads(content)
    if not isinstance(state, dict) or not 1 <= len(state) <= 48:
        raise ValueError("invalid state")
    print("CONTROLLER_STATE_KEYS count=" + str(len(state)))
    for key, value in sorted(state.items()):
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise ValueError("unsafe key")
        kind = ("bool" if isinstance(value, bool) else
                "integer" if isinstance(value, int) else
                "string" if isinstance(value, str) else
                "data" if isinstance(value, bytes) else
                "dictionary" if isinstance(value, dict) else
                "array" if isinstance(value, list) else "other")
        print("CONTROLLER_STATE_KEY " + key + " type=" + kind)
    link = state.get("SoftwareLinkState")
    link = link if isinstance(link, str) and re.fullmatch(r"[ -~]{1,160}", link) else "other"
    print("CONTROLLER_STATE link=" + link)
    for key in ("DefaultPreferredConfiguration", "PreferredConfiguration",
                "SelectedConfiguration"):
        value = state.get(key)
        value = str(value) if type(value) is int and 0 <= value <= 255 else "other"
        print("CONTROLLER_STATE " + key + "=" + value)
    print("CONTROLLER_STATE force-off-symbol=" +
          ("present" if force_off is not None else "absent"))
    print("CONTROLLER_PARENTS count=" + str(len(parent_classes)))
    for depth, name in enumerate(parent_classes):
        print("CONTROLLER_PARENT depth=" + str(depth) + " class=" + name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        print("CONTROLLER_STATE_KEYS rejected")
        raise SystemExit(1)
