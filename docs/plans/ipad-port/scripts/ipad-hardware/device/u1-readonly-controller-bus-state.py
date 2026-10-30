#!/var/jb/usr/bin/python3
"""Classify one controller's current bus state without changing USB state.

What this code does: copy the existing IOUSBDeviceController CurrentState
registry dictionary with public read-only IOKit/CoreFoundation calls. It
reports only the allowlisted DeviceState category, OnBus boolean, bounded
connection-speed number, and selected-configuration number. Unknown values
stay unknown; no identifiers or raw dictionary leave the iPad. It opens no
user client, sends no USB request, and writes no device or system file.
"""

import ctypes


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
UTF8 = 0x08000100
SINT32 = 3
KNOWN_STATES = {
    "Disconnected": "disconnected",
    "Attached": "attached",
    "Powered": "powered",
    "Default": "default",
    "Addressed": "addressed",
    "Configured": "configured",
    "Suspended": "suspended",
}


def main():
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
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringGetCString.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = (
        ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def member(dictionary, key):
        name = cf.CFStringCreateWithCString(None, key, UTF8)
        if not name:
            return None
        try:
            return cf.CFDictionaryGetValue(dictionary, name)
        finally:
            cf.CFRelease(name)

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        print("CONTROLLER_BUS query=matching-unavailable")
        return
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        print("CONTROLLER_BUS query=matching-failed")
        return
    service = io.IOIteratorNext(iterator.value)
    if not service:
        io.IOObjectRelease(iterator.value)
        print("CONTROLLER_BUS query=no-service")
        return
    try:
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            print("CONTROLLER_BUS query=multiple-services")
            return
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(
                service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            print("CONTROLLER_BUS query=properties-unavailable")
            return
        try:
            current = member(properties, b"CurrentState")
            if not current or cf.CFGetTypeID(current) != cf.CFDictionaryGetTypeID():
                print("CONTROLLER_BUS query=current-state-unavailable")
                return
            state = "unknown"
            value = member(current, b"DeviceState")
            if value and cf.CFGetTypeID(value) == cf.CFStringGetTypeID():
                buffer = ctypes.create_string_buffer(64)
                if cf.CFStringGetCString(value, buffer, len(buffer), UTF8):
                    state = KNOWN_STATES.get(buffer.value.decode("ascii", "ignore"),
                                             "other")
            onbus = "unknown"
            value = member(current, b"OnBus")
            if value and cf.CFGetTypeID(value) == cf.CFBooleanGetTypeID():
                onbus = "yes" if cf.CFBooleanGetValue(value) else "no"

            def bounded_number(key, maximum):
                item = member(current, key)
                if not item or cf.CFGetTypeID(item) != cf.CFNumberGetTypeID():
                    return "unknown"
                number = ctypes.c_int32()
                if not cf.CFNumberGetValue(item, SINT32, ctypes.byref(number)):
                    return "unknown"
                return str(number.value) if 0 <= number.value <= maximum else "other"

            speed = bounded_number(b"ConnectionSpeed", 100000)
            config = bounded_number(b"SelectedConfiguration", 255)
            print("CONTROLLER_BUS query=ok state=" + state + " onbus=" +
                  onbus + " speed=" + speed + " config=" + config)
        finally:
            cf.CFRelease(properties)
    finally:
        io.IOObjectRelease(service)
        io.IOObjectRelease(iterator.value)


if __name__ == "__main__":
    main()
