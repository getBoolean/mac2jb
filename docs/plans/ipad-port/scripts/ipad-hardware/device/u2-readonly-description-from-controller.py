#!/var/jb/usr/bin/python3
"""Inspect the controller's existing opaque USB description in memory.

This uses the two-argument CreateFromController API demonstrated by the
vphone-cli native source, then compares its info dictionary with the live
registry dictionary. It returns only categorical results. It makes no USB
publication, bus cycle, request, registry change, or file write, and it
releases every CoreFoundation object it owns.
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
                relation = "equal" if cf.CFEqual(info, live) else "different"
                return ("U2_FROM_CONTROLLER info=dict count=" + str(count) +
                        " live-count=" + str(cf.CFDictionaryGetCount(live)) +
                        " relation=" + relation)
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
        print("U2_FROM_CONTROLLER rejected")
