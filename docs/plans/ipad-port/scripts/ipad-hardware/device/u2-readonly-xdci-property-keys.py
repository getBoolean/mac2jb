#!/var/jb/usr/bin/python3
"""List bounded USB XDCI and ancestor property names/types, without values.

The sole IOUSBDeviceController is AppleT8112USBXDCI on this target. Copy its
IOService-plane properties and those of its known ancestors through public
read-only IOKit calls. Output contains no registry IDs, paths, property values,
or nested data. No user client, USB request, registry write, or file write.
"""

import ctypes
import os
import re


CLASSES = (
    "AppleT8112USBXDCI", "AppleARMIODevice", "AppleT811xIO",
    "IOPlatformDevice", "AppleARMPE", "IOPlatformExpertDevice",
    "IORegistryEntry",
)
KEY = re.compile(r"[A-Za-z0-9_. /-]{1,100}\Z")
INTEREST = re.compile(r"power|state|role|attach|connect|vbus|cc|phy|port|usb|pd|enable|reset|clock", re.I)
PRIVATE_NAME = re.compile(r"serial|unique|uuid|address|identifier|token|path|location|vendor|product", re.I)
MAX_PROPERTIES = 256
MAX_SELECTED = 32
MAX_POWER_KEYS = 24
UTF8 = 0x08000100


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
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
    io.IOObjectGetClass.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
    io.IOObjectGetClass.restype = ctypes.c_int32
    io.IORegistryEntryGetParentEntry.argtypes = (
        ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetParentEntry.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetKeysAndValues.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p))
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFDataGetTypeID.restype = ctypes.c_ulong
    cf.CFArrayGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetCString.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def name_of(value):
        if cf.CFGetTypeID(value) != cf.CFStringGetTypeID():
            return None
        buffer = ctypes.create_string_buffer(128)
        if not cf.CFStringGetCString(value, buffer, len(buffer), UTF8):
            return None
        try:
            name = buffer.value.decode("ascii")
        except UnicodeDecodeError:
            return None
        return name if KEY.fullmatch(name) else None

    def kind_of(value):
        value_type = cf.CFGetTypeID(value)
        for kind, getter in (("bool", cf.CFBooleanGetTypeID),
                             ("integer", cf.CFNumberGetTypeID),
                             ("string", cf.CFStringGetTypeID),
                             ("dictionary", cf.CFDictionaryGetTypeID),
                             ("data", cf.CFDataGetTypeID),
                             ("array", cf.CFArrayGetTypeID)):
            if value_type == getter():
                return kind
        return "other"

    def selected_properties(dictionary, limit):
        count = cf.CFDictionaryGetCount(dictionary)
        if count < 0 or count > MAX_PROPERTIES:
            raise ValueError("too many properties")
        keys = (ctypes.c_void_p * count)()
        values = (ctypes.c_void_p * count)()
        cf.CFDictionaryGetKeysAndValues(dictionary, keys, values)
        selected = []
        for key, value in zip(keys, values):
            name = name_of(key)
            if name and INTEREST.search(name) and not PRIVATE_NAME.search(name):
                selected.append((name, kind_of(value), value))
        if len(selected) > limit:
            raise ValueError("too many selected properties")
        return sorted(selected, key=lambda item: item[0])

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        raise ValueError("matching unavailable")
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        raise ValueError("controller query failed")
    try:
        service = io.IOIteratorNext(iterator.value)
        if not service:
            raise ValueError("controller absent")
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            io.IOObjectRelease(service)
            raise ValueError("multiple controllers")
    finally:
        io.IOObjectRelease(iterator.value)

    lines = []
    current = service
    try:
        for depth, expected_class in enumerate(CLASSES):
            class_buffer = ctypes.create_string_buffer(128)
            if io.IOObjectGetClass(current, class_buffer) != 0 or class_buffer.value != expected_class.encode():
                raise ValueError("ancestor class changed")
            properties = ctypes.c_void_p()
            if io.IORegistryEntryCreateCFProperties(current, ctypes.byref(properties), None, 0) != 0 or not properties.value:
                raise ValueError("properties unavailable")
            try:
                selected = selected_properties(properties, MAX_SELECTED)
                lines.append("U2_XDCI_SERVICE depth=%d class=%s keys=%d" %
                             (depth, expected_class, len(selected)))
                for name, kind, value in selected:
                    lines.append("U2_XDCI_KEY depth=%d name=%s type=%s" %
                                 (depth, name, kind))
                    if name == "IOPowerManagement" and kind == "dictionary":
                        power = selected_properties(value, MAX_POWER_KEYS)
                        for nested_name, nested_kind, _ in power:
                            lines.append("U2_XDCI_POWER_KEY depth=%d name=%s type=%s" %
                                         (depth, nested_name, nested_kind))
            finally:
                cf.CFRelease(properties)
            if depth + 1 < len(CLASSES):
                parent = ctypes.c_uint32()
                if io.IORegistryEntryGetParentEntry(current, b"IOService", ctypes.byref(parent)) != 0 or not parent.value:
                    raise ValueError("ancestor unavailable")
                io.IOObjectRelease(current)
                current = parent.value
        parent = ctypes.c_uint32()
        if io.IORegistryEntryGetParentEntry(current, b"IOService", ctypes.byref(parent)) == 0:
            if parent.value:
                io.IOObjectRelease(parent.value)
            raise ValueError("unexpected extra ancestor")
    finally:
        io.IOObjectRelease(current)
    output = "U2_XDCI_SCAN count=7\n" + "\n".join(lines) + "\nU2_XDCI_SCAN done\n"
    if len(output.encode("ascii")) > 8192:
        raise ValueError("output too large")
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError):
        print("U2_XDCI_SCAN rejected")
        raise SystemExit(1)
