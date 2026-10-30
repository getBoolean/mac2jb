#!/var/jb/usr/bin/python3
"""Read the installed Python process's USB publication entitlements.

The proposed watchdog package runs the already trusted rootless Python
interpreter. This probe calls only SecTaskCopyValueForEntitlement on itself
and reports yes/no for the two relevant keys. It does not request USB access,
write a file, alter code signing, or publish a descriptor.
"""

import ctypes


def main():
    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    security.SecTaskCreateFromSelf.argtypes = (ctypes.c_void_p,)
    security.SecTaskCreateFromSelf.restype = ctypes.c_void_p
    security.SecTaskCopyValueForEntitlement.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    security.SecTaskCopyValueForEntitlement.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)
    task = security.SecTaskCreateFromSelf(None)
    if not task:
        raise ValueError("self task unavailable")
    try:
        for label, name in (
                ("setdescription", b"com.apple.private.usbdevice.setdescription"),
                ("platform", b"platform-application")):
            key = cf.CFStringCreateWithCString(None, name, 0x08000100)
            if not key:
                raise ValueError("entitlement key unavailable")
            error = ctypes.c_void_p()
            try:
                value = security.SecTaskCopyValueForEntitlement(
                    task, key, ctypes.byref(error))
            finally:
                cf.CFRelease(key)
            if error.value:
                cf.CFRelease(error)
            if value:
                try:
                    enabled = (cf.CFGetTypeID(value) == cf.CFBooleanGetTypeID() and
                               cf.CFBooleanGetValue(value))
                finally:
                    cf.CFRelease(value)
            else:
                enabled = False
            print("U2_PYTHON_ENTITLEMENT " + label + "=" + ("yes" if enabled else "no"))
    finally:
        cf.CFRelease(task)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        print("U2_PYTHON_ENTITLEMENT rejected")
        raise SystemExit(1)
