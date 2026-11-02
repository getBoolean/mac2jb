#!/var/jb/usr/bin/python3
"""Read one bounded Type-C transport and XDCI scalar-state snapshot.

Only exact allowlisted CFBoolean/CFNumber fields are read. Numeric enum values
are reported without interpretation. No identifiers, strings, data blobs,
paths, or raw property dictionaries leave the iPad. This opens no user client,
sends no USB request/command, and makes no registry or file write.
"""

import ctypes
import os
import signal
import time


CLASSES = (
    "AppleTCControllerType10", "IOPortTransportStateUSB2",
    "IOPortTransportStateUSB3", "AppleT8112USBXDCI",
)
FIELDS = {
    "AppleTCControllerType10": (
        ("ConnectionActive", "bool", 0),
        ("IOAccessoryUSBActive", "bool", 0),
        ("IOAccessoryUSBSuperSpeedActive", "bool", 0),
        ("IOAccessoryUSBPower", "bool", 0),
        ("PlugOrientation", "integer", 255),
        ("IOAccessoryUSBConnectType", "integer", 255),
    ),
    "IOPortTransportStateUSB2": (
        ("Active", "bool", 0), ("DataRole", "integer", 255),
        ("DataRate", "integer", 4294967295),
        ("TRM_State", "integer", 65535),
        ("TRM_TransportRestricted", "bool", 0),
    ),
    "IOPortTransportStateUSB3": (
        ("Active", "bool", 0), ("DataRole", "integer", 255),
        ("DataRate", "integer", 4294967295),
        ("TRM_State", "integer", 65535),
        ("TRM_TransportRestricted", "bool", 0),
    ),
    "AppleT8112USBXDCI": (
        ("OnBus", "bool", 0),
        ("SelectedConfiguration", "integer", 255),
    ),
}
POWER_FIELDS = ("CurrentPowerState", "ChildProxyPowerState")
STAGE = "setup"
REASONS = {
    "root required": "privilege", "matching unavailable": "matching",
    "service query failed": "query", "service absent": "absent",
    "service cardinality changed": "cardinality", "match limit": "match-limit",
    "class identity changed": "class-identity",
    "properties unavailable": "properties",
    "CurrentState unavailable": "current-state",
    "snapshot deadline": "deadline", "snapshot timed out": "deadline",
    "output too large": "output-limit",
}


def alarm(_signal, _frame):
    raise TimeoutError("snapshot timed out")


def main():
    global STAGE
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
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetValue.argtypes = (
        ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFStringCreateWithCString.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def member(dictionary, name):
        key = cf.CFStringCreateWithCString(None, name.encode("ascii"), 0x08000100)
        if not key:
            return None
        try:
            return cf.CFDictionaryGetValue(dictionary, key)
        finally:
            cf.CFRelease(key)

    def scalar(dictionary, name, kind, maximum):
        value = member(dictionary, name)
        if not value:
            return "missing"
        if kind == "bool":
            if cf.CFGetTypeID(value) != cf.CFBooleanGetTypeID():
                return "other"
            return "yes" if cf.CFBooleanGetValue(value) else "no"
        if cf.CFGetTypeID(value) != cf.CFNumberGetTypeID():
            return "other"
        number = ctypes.c_int64()
        if not cf.CFNumberGetValue(value, 4, ctypes.byref(number)):
            return "other"
        return str(number.value) if 0 <= number.value <= maximum else "out-of-range"

    deadline = time.monotonic() + 5
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(8)
    lines = ["U2_TYPEC_SCALARS count=4"]
    try:
        for index, class_name in enumerate(CLASSES):
            STAGE = str(index)
            if time.monotonic() >= deadline:
                raise TimeoutError("snapshot deadline")
            matching = io.IOServiceMatching(class_name.encode("ascii"))
            if not matching:
                raise ValueError("matching unavailable")
            iterator = ctypes.c_uint32()
            if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
                raise ValueError("service query failed")
            service = 0
            exact = seen = 0
            try:
                while True:
                    entry = io.IOIteratorNext(iterator.value)
                    if not entry:
                        break
                    try:
                        seen += 1
                        if seen > 32:
                            raise ValueError("match limit")
                        buffer = ctypes.create_string_buffer(128)
                        if io.IOObjectGetClass(entry, buffer) != 0:
                            raise ValueError("class identity changed")
                        if buffer.value == class_name.encode():
                            exact += 1
                            if exact == 1:
                                service = entry
                                entry = 0
                    finally:
                        if entry:
                            io.IOObjectRelease(entry)
            except BaseException:
                if service:
                    io.IOObjectRelease(service)
                raise
            finally:
                io.IOObjectRelease(iterator.value)
            if exact != 1:
                if service:
                    io.IOObjectRelease(service)
                raise ValueError("service absent" if exact == 0 else
                                 "service cardinality changed")
            try:
                properties = ctypes.c_void_p()
                if io.IORegistryEntryCreateCFProperties(service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
                    raise ValueError("properties unavailable")
                try:
                    state = properties.value
                    if class_name == "AppleT8112USBXDCI":
                        state = member(state, "CurrentState")
                        if not state or cf.CFGetTypeID(state) != cf.CFDictionaryGetTypeID():
                            raise ValueError("CurrentState unavailable")
                    lines.append("U2_TYPEC_SERVICE class=" + class_name)
                    for name, kind, maximum in FIELDS[class_name]:
                        lines.append("U2_TYPEC_VALUE class=%s key=%s value=%s" %
                                     (class_name, name, scalar(state, name, kind, maximum)))
                    if class_name == "AppleTCControllerType10":
                        power = member(properties.value, "IOPowerManagement")
                        if power and cf.CFGetTypeID(power) == cf.CFDictionaryGetTypeID():
                            for name in POWER_FIELDS:
                                value = scalar(power, name, "integer", 255)
                                lines.append("U2_TYPEC_POWER key=%s value=%s" %
                                             (name, value))
                        else:
                            for name in POWER_FIELDS:
                                lines.append("U2_TYPEC_POWER key=%s value=missing" % name)
                finally:
                    cf.CFRelease(properties)
            finally:
                io.IOObjectRelease(service)
    finally:
        signal.alarm(0)
    lines.append("U2_TYPEC_SCALARS done")
    output = "\n".join(lines) + "\n"
    if len(output.encode("ascii")) > 4096:
        raise ValueError("output too large")
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError) as error:
        print("U2_TYPEC_SCALARS rejected stage=" + STAGE + " reason=" +
              REASONS.get(str(error), "internal"))
        raise SystemExit(1)
