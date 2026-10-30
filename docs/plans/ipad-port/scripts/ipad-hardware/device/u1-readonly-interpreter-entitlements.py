#!/var/jb/usr/bin/python3
"""Classify this interpreter's own USB-related entitlements without device writes.

What this code does: ask Security.framework's SecTask API whether this exact
running Python process has each allowlisted entitlement. It prints only yes,
no, or unknown, never entitlement contents or device identifiers. It does not
open a USB user client, change a service, or write an iPad file. If the API
cannot answer a query, that field stays unknown rather than claiming absence.
"""

import ctypes


def main():
    try:
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
    except (OSError, AttributeError):
        print("INTERPRETER_ENTITLEMENTS query=unavailable")
        return

    task = security.SecTaskCreateFromSelf(None)
    if not task:
        print("INTERPRETER_ENTITLEMENTS query=task-unavailable")
        return
    names = (
        ("platform", b"platform-application"),
        ("setdescription", b"com.apple.private.usbdevice.setdescription"),
        ("userclient", b"com.apple.security.exception.iokit-user-client-class"),
        ("no-sandbox", b"com.apple.private.security.no-sandbox"),
    )
    results = []
    try:
        for label, raw_name in names:
            name = cf.CFStringCreateWithCString(None, raw_name, 0x08000100)
            if not name:
                results.append((label, "unknown"))
                continue
            error = ctypes.c_void_p()
            value = 0
            try:
                value = security.SecTaskCopyValueForEntitlement(
                    task, name, ctypes.byref(error))
                if error.value:
                    status = "unknown"
                elif not value:
                    status = "no"
                elif cf.CFGetTypeID(value) == cf.CFBooleanGetTypeID():
                    status = "yes" if cf.CFBooleanGetValue(value) else "no"
                else:
                    status = "yes"
                results.append((label, status))
            finally:
                if value:
                    cf.CFRelease(value)
                if error.value:
                    cf.CFRelease(error)
                cf.CFRelease(name)
    finally:
        cf.CFRelease(task)
    print("INTERPRETER_ENTITLEMENTS query=ok " +
          " ".join(label + "=" + status for label, status in results))


if __name__ == "__main__":
    main()
