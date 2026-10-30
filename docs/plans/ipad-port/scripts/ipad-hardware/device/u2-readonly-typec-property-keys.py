#!/var/jb/usr/bin/python3
"""List bounded Type-C transport and XDCI property names/types only.

Matches six exact IOService classes, requiring one instance of each. Reads
only property dictionaries via IOKit/CoreFoundation. Emits no values, IDs,
service names, paths, serials, or data; performs no user-client open, USB
request, controller command, registry write, or file write.
"""

import ctypes
import os
import re
import signal
import time


CLASSES = (
    "AppleTCControllerType10", "IOAccessoryUSBConnectShim",
    "IOPortTransportStateUSB2", "IOPortTransportStateUSB3",
    "AppleT8112TypeCPhy", "AppleT8112USBXDCI",
)
KEY = re.compile(r"[A-Za-z0-9_. /-]{1,100}\Z")
INTEREST = re.compile(r"attach|connect|role|mode|state|orientation|cc|vbus|power|data|usb|phy|link|enable|active|present|partner|port|transport", re.I)
PRIVATE = re.compile(r"serial|unique|uuid|address|identifier|token|path|location|vendor|product", re.I)
MAX_PROPERTIES = 256
MAX_KEYS = 48
MAX_SUBKEYS = 16
MAX_CLASS_MATCHES = 32
UTF8 = 0x08000100
STAGE = "setup"
REASONS = {
    "root required": "privilege", "class matching unavailable": "matching",
    "class query failed": "query", "required class absent": "absent",
    "class cardinality changed": "cardinality",
    "class match limit": "match-limit",
    "class identity changed": "class-identity",
    "properties unavailable": "properties", "too many properties": "property-limit",
    "too many selected keys": "key-limit",
    "Type-C scan deadline": "deadline", "Type-C scan timed out": "deadline",
    "output too large": "output-limit",
}


def alarm(_signal, _frame):
    raise TimeoutError("Type-C scan timed out")


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
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetKeysAndValues.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p))
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
        return name if KEY.fullmatch(name) and not PRIVATE.search(name) else None

    def kind_of(value):
        kind = cf.CFGetTypeID(value)
        for label, getter in (("bool", cf.CFBooleanGetTypeID),
                              ("integer", cf.CFNumberGetTypeID),
                              ("string", cf.CFStringGetTypeID),
                              ("dictionary", cf.CFDictionaryGetTypeID),
                              ("data", cf.CFDataGetTypeID),
                              ("array", cf.CFArrayGetTypeID)):
            if kind == getter():
                return label
        return "other"

    def keys_of(dictionary, limit):
        count = cf.CFDictionaryGetCount(dictionary)
        if count < 0 or count > MAX_PROPERTIES:
            raise ValueError("too many properties")
        keys = (ctypes.c_void_p * count)()
        values = (ctypes.c_void_p * count)()
        cf.CFDictionaryGetKeysAndValues(dictionary, keys, values)
        selected = []
        for key, value in zip(keys, values):
            name = name_of(key)
            if name and INTEREST.search(name):
                selected.append((name, kind_of(value), value))
        if len(selected) > limit:
            raise ValueError("too many selected keys")
        return sorted(selected, key=lambda item: item[0])

    deadline = time.monotonic() + 5
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(8)
    lines = []
    try:
        for stage, class_name in enumerate(CLASSES):
            STAGE = str(stage)
            if time.monotonic() >= deadline:
                raise TimeoutError("Type-C scan deadline")
            matching = io.IOServiceMatching(class_name.encode("ascii"))
            if not matching:
                raise ValueError("class matching unavailable")
            iterator = ctypes.c_uint32()
            if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
                raise ValueError("class query failed")
            service = 0
            exact = seen = 0
            try:
                while True:
                    entry = io.IOIteratorNext(iterator.value)
                    if not entry:
                        break
                    try:
                        seen += 1
                        if seen > MAX_CLASS_MATCHES:
                            raise ValueError("class match limit")
                        class_buffer = ctypes.create_string_buffer(128)
                        if io.IOObjectGetClass(entry, class_buffer) != 0:
                            raise ValueError("class identity changed")
                        if class_buffer.value == class_name.encode():
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
                raise ValueError("required class absent" if exact == 0 else
                                 "class cardinality changed")
            try:
                class_buffer = ctypes.create_string_buffer(128)
                if io.IOObjectGetClass(service, class_buffer) != 0 or class_buffer.value != class_name.encode():
                    raise ValueError("class identity changed")
                properties = ctypes.c_void_p()
                if io.IORegistryEntryCreateCFProperties(service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
                    raise ValueError("properties unavailable")
                try:
                    selected = keys_of(properties, MAX_KEYS)
                    lines.append("U2_TYPEC_SERVICE class=%s keys=%d" %
                                 (class_name, len(selected)))
                    for name, kind, value in selected:
                        lines.append("U2_TYPEC_KEY class=%s name=%s type=%s" %
                                     (class_name, name, kind))
                        if kind == "dictionary":
                            for subname, subkind, _ in keys_of(value, MAX_SUBKEYS):
                                lines.append("U2_TYPEC_SUBKEY class=%s parent=%s name=%s type=%s" %
                                             (class_name, name, subname, subkind))
                finally:
                    cf.CFRelease(properties)
            finally:
                io.IOObjectRelease(service)
    finally:
        signal.alarm(0)
    output = "U2_TYPEC_SCAN count=6\n" + "\n".join(lines) + "\nU2_TYPEC_SCAN done\n"
    if len(output.encode("ascii")) > 16384:
        raise ValueError("output too large")
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError) as error:
        print("U2_TYPEC_SCAN rejected stage=" + STAGE + " reason=" +
              REASONS.get(str(error), "internal"))
        raise SystemExit(1)
