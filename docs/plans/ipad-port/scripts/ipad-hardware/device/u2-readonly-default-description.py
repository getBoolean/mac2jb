#!/var/jb/usr/bin/python3
"""Classify the target controller's default-description constructor.

This script dynamically loads IOKit, creates a controller reference, calls
IOUSBDeviceDescriptionCreateFromDefaultsAndController once with the two
arguments used by Apple's USBDeviceConfiguration bundle, queries only CF type
IDs, and releases returned references. It prints fixed categories, never raw
description values, pointers, device IDs, or paths. It does not call any USB
publication, bus-cycle, registry-write, or file-write API.
"""

import ctypes


def main():
    iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")

    create_controller = iokit.IOUSBDeviceControllerCreate
    create_controller.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    create_controller.restype = ctypes.c_int32
    create_default = iokit.IOUSBDeviceDescriptionCreateFromDefaultsAndController
    create_default.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    create_default.restype = ctypes.c_void_p
    type_id = core.CFGetTypeID
    type_id.argtypes = [ctypes.c_void_p]
    type_id.restype = ctypes.c_ulong
    release = core.CFRelease
    release.argtypes = [ctypes.c_void_p]
    release.restype = None

    controller = ctypes.c_void_p()
    status = create_controller(None, ctypes.byref(controller))
    if status != 0 or not controller.value:
        print("U2_DEFAULT controller=unavailable description=unattempted")
        return
    try:
        description = create_default(None, controller)
        if not description:
            print("U2_DEFAULT controller=created description=absent")
            return
        try:
            valid = type_id(description) != 0 and type_id(description) != type_id(controller)
            print("U2_DEFAULT controller=created description=" +
                  ("cf-object" if valid else "unexpected-type"))
        finally:
            release(description)
    finally:
        release(controller)


if __name__ == "__main__":
    try:
        main()
    except (AttributeError, OSError):
        print("U2_DEFAULT controller=unavailable description=unattempted")
