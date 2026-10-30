#!/var/jb/usr/bin/python3
"""Check only in-memory mutation of a cloned stock USB description.

This requires the cloned info to equal the 16-field live registry description.
It sets and removes the replacement-permission key on the clone, writes the
two saved scalar values back to that same clone, and checks equality again.
It never calls SetDescription, cycles the bus, changes registry state, sends
a USB request, or writes a file. Output is categorical, without private data.
"""

import ctypes
import os


def main():
    if os.geteuid() != 0:
        return "U2_FROM_CONTROLLER rejected"
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    constructor = getattr(io, "IOUSBDeviceDescriptionCreateFromController", None)
    if constructor is None:
        return "U2_FROM_CONTROLLER symbol=absent"

    create = io.IOUSBDeviceControllerCreate
    create.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    create.restype = ctypes.c_int32
    constructor.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    constructor.restype = ctypes.c_void_p
    get_info = io._IOUSBDeviceDescriptionGetInfo
    get_info.argtypes = (ctypes.c_void_p,)
    get_info.restype = ctypes.c_void_p
    get_service = io.IOUSBDeviceControllerGetService
    get_service.argtypes = (ctypes.c_void_p,)
    get_service.restype = ctypes.c_uint32
    get_property = io.IORegistryEntryCreateCFProperty
    get_property.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_uint32)
    get_property.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionarySetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p)
    cf.CFDictionarySetValue.restype = None
    cf.CFDictionaryRemoveValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryRemoveValue.restype = None
    cf.CFEqual.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFEqual.restype = ctypes.c_bool
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                              ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)
    cf.CFRelease.restype = None

    controller = ctypes.c_void_p()
    if create(None, ctypes.byref(controller)) != 0 or not controller.value:
        return "U2_FROM_CONTROLLER controller=unavailable"
    try:
        description = constructor(None, controller)
        if not description:
            return "U2_FROM_CONTROLLER description=absent"
        try:
            info = get_info(description)
            if not info or cf.CFGetTypeID(info) != cf.CFDictionaryGetTypeID():
                return "U2_FROM_CONTROLLER info=unavailable"
            count = cf.CFDictionaryGetCount(info)
            if not 1 <= count <= 128:
                return "U2_FROM_CONTROLLER info=unexpected-count"
            service = get_service(controller)
            if not service:
                return "U2_FROM_CONTROLLER registry=unavailable"
            key = cf.CFStringCreateWithCString(None, b"DeviceDescription", 0x08000100)
            if not key:
                return "U2_FROM_CONTROLLER registry=unavailable"
            try:
                live = get_property(service, key, None, 0)
            finally:
                cf.CFRelease(key)
            if not live:
                return "U2_FROM_CONTROLLER registry=unavailable"
            try:
                if cf.CFGetTypeID(live) != cf.CFDictionaryGetTypeID():
                    return "U2_FROM_CONTROLLER registry=unavailable"
                if count != 16 or cf.CFDictionaryGetCount(live) != 16 or not cf.CFEqual(info, live):
                    return "U2_CLONE_IN_MEMORY stock=unexpected"
                names = (b"AllowMultipleCreates", b"BcdUSBVersion", b"MPS0")
                keys = [cf.CFStringCreateWithCString(None, name, 0x08000100)
                        for name in names]
                if not all(keys):
                    for item in keys:
                        if item:
                            cf.CFRelease(item)
                    return "U2_CLONE_IN_MEMORY keys=unavailable"
                try:
                    flag = ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue").value
                    bcd = cf.CFDictionaryGetValue(live, keys[1])
                    mps = cf.CFDictionaryGetValue(live, keys[2])
                    if not flag or not bcd or not mps:
                        return "U2_CLONE_IN_MEMORY values=unavailable"
                    cf.CFDictionarySetValue(info, keys[0], flag)
                    if cf.CFDictionaryGetCount(info) != 17:
                        return "U2_CLONE_IN_MEMORY mutable=no"
                    cf.CFDictionaryRemoveValue(info, keys[0])
                    cf.CFDictionarySetValue(info, keys[1], bcd)
                    cf.CFDictionarySetValue(info, keys[2], mps)
                    if cf.CFDictionaryGetCount(info) != 16 or not cf.CFEqual(info, live):
                        return "U2_CLONE_IN_MEMORY roundtrip=different"
                    return "U2_CLONE_IN_MEMORY stock=equal mutable=yes roundtrip=equal"
                finally:
                    for item in keys:
                        cf.CFRelease(item)
            finally:
                cf.CFRelease(live)
        finally:
            cf.CFRelease(description)
    finally:
        cf.CFRelease(controller)


if __name__ == "__main__":
    try:
        print(main())
    except (AttributeError, OSError, ValueError):
        print("U2_CLONE_IN_MEMORY rejected")
