#!/var/jb/usr/bin/python3
"""Compare in-memory USB description interfaces and objects, without writes.

Creates one controller reference and separate descriptions via the exact
defaults-plus-controller path used by U2 v1-v3 and controller-clone path used
by v4-v5. CopyInterfaces returns their in-memory interface arrays. The probe
adds only the four known live-only fields to the default object's in-memory
dictionary, then compares object equality with a two-clone control. It
prints only categorical results, releases all references, and never calls
SetDescription, GoOffAndOnBus, ForceOffBus, or any file writer.
"""

import ctypes
import os


def main():
    if os.geteuid() != 0:
        return "U2_INTERFACE_RELATION rejected"
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    create = io.IOUSBDeviceControllerCreate
    create.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    create.restype = ctypes.c_int32
    constructors = (
        io.IOUSBDeviceDescriptionCreateFromDefaultsAndController,
        io.IOUSBDeviceDescriptionCreateFromController,
    )
    for constructor in constructors:
        constructor.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        constructor.restype = ctypes.c_void_p
    copy = io.IOUSBDeviceDescriptionCopyInterfaces
    copy.argtypes = (ctypes.c_void_p,)
    copy.restype = ctypes.c_void_p
    get_info = io._IOUSBDeviceDescriptionGetInfo
    get_info.argtypes = (ctypes.c_void_p,)
    get_info.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFArrayGetTypeID.restype = ctypes.c_ulong
    cf.CFArrayGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionarySetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p)
    cf.CFDictionarySetValue.restype = None
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                              ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFEqual.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFEqual.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)
    cf.CFRelease.restype = None

    controller = ctypes.c_void_p()
    if create(None, ctypes.byref(controller)) != 0 or not controller.value:
        return "U2_INTERFACE_RELATION controller=unavailable"
    descriptions = []
    arrays = []
    keys = []
    try:
        for constructor in constructors:
            description = constructor(None, controller)
            if not description:
                return "U2_INTERFACE_RELATION description=unavailable"
            descriptions.append(description)
            interfaces = copy(description)
            if not interfaces:
                return "U2_INTERFACE_RELATION interfaces=unavailable"
            arrays.append(interfaces)
            if cf.CFGetTypeID(interfaces) != cf.CFArrayGetTypeID():
                return "U2_INTERFACE_RELATION interfaces=unexpected-type"
        counts = [cf.CFArrayGetCount(item) for item in arrays]
        if any(not 1 <= count <= 16 for count in counts):
            return "U2_INTERFACE_RELATION interfaces=unexpected-count"
        clone_control = constructors[1](None, controller)
        if not clone_control:
            return "U2_INTERFACE_RELATION clone-control=unavailable"
        descriptions.append(clone_control)
        default_info, clone_info = (get_info(item) for item in descriptions[:2])
        if (not default_info or not clone_info or
                cf.CFGetTypeID(default_info) != cf.CFDictionaryGetTypeID() or
                cf.CFGetTypeID(clone_info) != cf.CFDictionaryGetTypeID() or
                cf.CFDictionaryGetCount(default_info) != 12 or
                cf.CFDictionaryGetCount(clone_info) != 16):
            return "U2_INTERFACE_RELATION info=unexpected"
        for name in (b"uniqueDeviceID", b"serialNumber", b"BcdUSBVersion", b"MPS0"):
            key = cf.CFStringCreateWithCString(None, name, 0x08000100)
            if not key:
                return "U2_INTERFACE_RELATION key=unavailable"
            keys.append(key)
            value = cf.CFDictionaryGetValue(clone_info, key)
            if not value or cf.CFDictionaryGetValue(default_info, key):
                return "U2_INTERFACE_RELATION missing-field=unexpected"
            cf.CFDictionarySetValue(default_info, key, value)
        if (cf.CFDictionaryGetCount(default_info) != 16 or
                not cf.CFEqual(default_info, clone_info)):
            return "U2_INTERFACE_RELATION patched-info=different"
        clone_equals_clone = cf.CFEqual(descriptions[1], descriptions[2])
        default_equals_clone = cf.CFEqual(descriptions[0], descriptions[1])
        return ("U2_INTERFACE_RELATION defaults-configs=" + str(counts[0]) +
                " clone-configs=" + str(counts[1]) +
                " interfaces=" + ("equal" if cf.CFEqual(arrays[0], arrays[1]) else "different") +
                " patched-info=equal clone-control=" +
                ("equal" if clone_equals_clone else "different") +
                " description-object=" +
                ("equal" if default_equals_clone else "different"))
    finally:
        for item in keys:
            cf.CFRelease(item)
        for item in arrays:
            cf.CFRelease(item)
        for item in descriptions:
            cf.CFRelease(item)
        cf.CFRelease(controller)


if __name__ == "__main__":
    try:
        print(main())
    except (AttributeError, OSError, ValueError):
        print("U2_INTERFACE_RELATION rejected")
