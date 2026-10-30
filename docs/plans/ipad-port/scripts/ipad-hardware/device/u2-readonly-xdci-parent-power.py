#!/var/jb/usr/bin/python3
"""Read two XDCI ancestor power scalars and the controller's bus state.

No identifiers, paths, raw dictionaries, user clients, commands, or writes.
"""

import ctypes
import os
import signal


UTF8 = 0x08000100
STAGE = "setup"


def timeout(_signal, _frame):
    raise TimeoutError()


def main():
    global STAGE
    if os.geteuid() != 0:
        raise ValueError()
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(8)
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectGetClass.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
    io.IOObjectGetClass.restype = ctypes.c_int32
    io.IORegistryEntryGetParentEntry.argtypes = (ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetParentEntry.restype = ctypes.c_int32
    io.IORegistryEntryGetRegistryEntryID.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64))
    io.IORegistryEntryGetRegistryEntryID.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetValue.argtypes = (ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def member(dictionary, name):
        key = cf.CFStringCreateWithCString(None, name.encode("ascii"), UTF8)
        if not key:
            raise ValueError()
        try:
            return cf.CFDictionaryGetValue(dictionary, key)
        finally:
            cf.CFRelease(key)

    def props(entry):
        value = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(entry, ctypes.byref(value), None, 0) != 0 or not value.value:
            raise ValueError()
        return value

    def dictionary(value):
        if not value or cf.CFGetTypeID(value) != cf.CFDictionaryGetTypeID():
            raise ValueError()
        return value

    def integer(value, maximum):
        if not value or cf.CFGetTypeID(value) != cf.CFNumberGetTypeID():
            raise ValueError()
        result = ctypes.c_int64()
        if not cf.CFNumberGetValue(value, 4, ctypes.byref(result)) or not 0 <= result.value <= maximum:
            raise ValueError()
        return result.value

    def exact_class(entry, expected):
        buf = ctypes.create_string_buffer(128)
        if io.IOObjectGetClass(entry, buf) != 0 or buf.value != expected:
            raise ValueError()

    def entry_id(entry):
        value = ctypes.c_uint64()
        if io.IORegistryEntryGetRegistryEntryID(entry, ctypes.byref(value)) != 0:
            raise ValueError()
        return value.value

    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    STAGE = "match"
    if not matching:
        raise ValueError()
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        raise ValueError()
    try:
        root = io.IOIteratorNext(iterator.value)
        if not root:
            raise ValueError()
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            io.IOObjectRelease(root)
            raise ValueError()
    finally:
        io.IOObjectRelease(iterator.value)
    current = root
    try:
        STAGE = "xdci"
        exact_class(current, b"AppleT8112USBXDCI")
        p = props(current)
        try:
            state = dictionary(member(p, "CurrentState"))
            bus = member(state, "OnBus")
            if not bus or cf.CFGetTypeID(bus) != cf.CFBooleanGetTypeID():
                raise ValueError()
            onbus = "yes" if cf.CFBooleanGetValue(bus) else "no"
            config = integer(member(state, "SelectedConfiguration"), 255)
        finally:
            cf.CFRelease(p)
        for expected in (b"AppleARMIODevice", b"AppleT811xIO"):
            STAGE = "ancestor"
            parent = ctypes.c_uint32()
            if io.IORegistryEntryGetParentEntry(current, b"IOService", ctypes.byref(parent)) != 0 or not parent.value:
                raise ValueError()
            io.IOObjectRelease(current)
            current = parent.value
            exact_class(current, expected)
        p = props(current)
        try:
            STAGE = "power-dictionary"
            power = dictionary(member(p, "IOPowerManagement"))
            STAGE = "power-current"
            current_power = integer(member(power, "CurrentPowerState"), 65535)
            STAGE = "power-child"
            child_value = member(power, "ChildProxyPowerState")
            if not child_value or cf.CFGetTypeID(child_value) != cf.CFNumberGetTypeID():
                raise ValueError()
            child_number = ctypes.c_int64()
            if not cf.CFNumberGetValue(child_value, 4, ctypes.byref(child_number)):
                raise ValueError()
            child_power = ("negative" if child_number.value < 0 else
                           str(child_number.value) if child_number.value <= 65535 else "above-range")
        finally:
            cf.CFRelease(p)
        parent_id = entry_id(current)
    finally:
        io.IOObjectRelease(current)
    STAGE = "typec"
    matching = io.IOServiceMatching(b"AppleTCControllerType10")
    if not matching:
        raise ValueError()
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        raise ValueError()
    try:
        typec = io.IOIteratorNext(iterator.value)
        if not typec:
            raise ValueError()
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            io.IOObjectRelease(typec)
            raise ValueError()
    finally:
        io.IOObjectRelease(iterator.value)
    same_parent = "no"
    current = typec
    try:
        exact_class(current, b"AppleTCControllerType10")
        for _ in range(12):
            if entry_id(current) == parent_id:
                same_parent = "yes"
                break
            parent = ctypes.c_uint32()
            if io.IORegistryEntryGetParentEntry(current, b"IOService", ctypes.byref(parent)) != 0 or not parent.value:
                break
            io.IOObjectRelease(current)
            current = parent.value
    finally:
        io.IOObjectRelease(current)
        signal.alarm(0)
    print("U2_XDCI_PARENT_POWER OnBus=%s SelectedConfiguration=%d CurrentPowerState=%d ChildProxyPowerState=%s" %
          (onbus, config, current_power, child_power))
    print("U2_XDCI_PARENT_POWER TypeCSharesAncestor=%s" % same_parent)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError):
        print("U2_XDCI_PARENT_POWER rejected stage=" + STAGE)
        raise SystemExit(1)
