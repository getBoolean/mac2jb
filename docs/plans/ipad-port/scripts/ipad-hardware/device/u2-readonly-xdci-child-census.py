#!/var/jb/usr/bin/python3
"""Bounded read-only IOService child census of the sole XDCI controller.

Only class-to-class provider/client edges, two live description numbers, and
independent CurrentState scalars leave the device. No IDs, names, paths,
serials, nested values, file writes, user clients, or controller commands.
"""

import ctypes
import os
import re
import signal
import time


MAX_DEPTH = 5
MAX_NODES = 96
MAX_EDGES = 48
MAX_SECONDS = 5
CLASS = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}\Z")
STATES = {"Disconnected": "disconnected", "Attached": "attached",
          "Powered": "powered", "Default": "default", "Addressed": "addressed",
          "Configured": "configured", "Suspended": "suspended"}
UTF8 = 0x08000100


def timed_out(_signum, _frame):
    raise TimeoutError("deadline")


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectGetClass.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
    io.IOObjectGetClass.restype = ctypes.c_int32
    io.IORegistryEntryGetChildIterator.argtypes = (ctypes.c_uint32, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetChildIterator.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFNumberGetValue.argtypes = (ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                             ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringGetCString.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def class_of(entry):
        buffer = ctypes.create_string_buffer(128)
        if io.IOObjectGetClass(entry, buffer) != 0:
            raise ValueError("class unavailable")
        try:
            name = buffer.value.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("class invalid") from None
        if not CLASS.fullmatch(name):
            raise ValueError("class invalid")
        return name

    def member(dictionary, name):
        key = cf.CFStringCreateWithCString(None, name.encode("ascii"), UTF8)
        if not key:
            raise ValueError("key unavailable")
        try:
            return cf.CFDictionaryGetValue(dictionary, key)
        finally:
            cf.CFRelease(key)

    def number(dictionary, key, maximum):
        value = member(dictionary, key)
        if not value or cf.CFGetTypeID(value) != cf.CFNumberGetTypeID():
            raise ValueError("number unavailable")
        result = ctypes.c_int64()
        if not cf.CFNumberGetValue(value, 4, ctypes.byref(result)) or not 0 <= result.value <= maximum:
            raise ValueError("number invalid")
        return result.value

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(8)
    deadline = time.monotonic() + MAX_SECONDS
    matching = io.IOServiceMatching(b"IOUSBDeviceController")
    if not matching:
        raise ValueError("matching unavailable")
    iterator = ctypes.c_uint32()
    if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
        raise ValueError("query failed")
    try:
        root = io.IOIteratorNext(iterator.value)
        if not root:
            raise ValueError("controller absent")
        extra = io.IOIteratorNext(iterator.value)
        if extra:
            io.IOObjectRelease(extra)
            io.IOObjectRelease(root)
            raise ValueError("controller cardinality")
    finally:
        io.IOObjectRelease(iterator.value)
    try:
        root_class = class_of(root)
    except BaseException:
        io.IOObjectRelease(root)
        signal.alarm(0)
        raise
    # The controller class is device-specific; it is recorded, not required.

    queue = [(root, root_class, 0)]
    edges = {}
    count = 1
    try:
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(root, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            raise ValueError("properties unavailable")
        try:
            description = member(properties, "DeviceDescription")
            state = member(properties, "CurrentState")
            if (not description or cf.CFGetTypeID(description) != cf.CFDictionaryGetTypeID() or
                    not state or cf.CFGetTypeID(state) != cf.CFDictionaryGetTypeID()):
                raise ValueError("controller dictionaries unavailable")
            bcd = number(description, "BcdUSBVersion", 65535)
            mps = number(description, "MPS0", 255)
            onbus_value = member(state, "OnBus")
            if not onbus_value or cf.CFGetTypeID(onbus_value) != cf.CFBooleanGetTypeID():
                raise ValueError("OnBus unavailable")
            onbus = "yes" if cf.CFBooleanGetValue(onbus_value) else "no"
            configuration = number(state, "SelectedConfiguration", 255)
            state_value = member(state, "DeviceState")
            if not state_value or cf.CFGetTypeID(state_value) != cf.CFStringGetTypeID():
                raise ValueError("DeviceState unavailable")
            buffer = ctypes.create_string_buffer(64)
            if not cf.CFStringGetCString(state_value, buffer, len(buffer), UTF8):
                raise ValueError("DeviceState invalid")
            device_state = STATES.get(buffer.value.decode("ascii", "ignore"), "other")
        finally:
            cf.CFRelease(properties)

        position = 0
        while position < len(queue):
            if time.monotonic() >= deadline:
                raise TimeoutError("deadline")
            entry, parent_class, depth = queue[position]
            position += 1
            children = ctypes.c_uint32()
            if io.IORegistryEntryGetChildIterator(entry, b"IOService", ctypes.byref(children)) != 0:
                raise ValueError("children unavailable")
            try:
                while True:
                    child = io.IOIteratorNext(children.value)
                    if not child:
                        break
                    try:
                        count += 1
                        if count > MAX_NODES or depth >= MAX_DEPTH or time.monotonic() >= deadline:
                            raise ValueError("traversal limit")
                        child_class = class_of(child)
                        edge = (depth + 1, parent_class, child_class)
                        edges[edge] = edges.get(edge, 0) + 1
                        if len(edges) > MAX_EDGES:
                            raise ValueError("edge limit")
                        queue.append((child, child_class, depth + 1))
                        child = 0
                    finally:
                        if child:
                            io.IOObjectRelease(child)
            finally:
                io.IOObjectRelease(children.value)
    finally:
        for entry, _, _ in queue:
            io.IOObjectRelease(entry)
        signal.alarm(0)

    lines = ["U2_XDCI_CENSUS nodes=%d edges=%d" % (count, len(edges)),
             "U2_XDCI_DESCRIPTION BcdUSBVersion=%d MPS0=%d" % (bcd, mps),
             "U2_XDCI_STATE DeviceState=%s OnBus=%s SelectedConfiguration=%d" %
             (device_state, onbus, configuration)]
    for (depth, provider, client), multiplicity in sorted(edges.items()):
        lines.append("U2_XDCI_EDGE depth=%d provider=%s client=%s count=%d" %
                     (depth, provider, client, multiplicity))
    lines.append("U2_XDCI_CENSUS done")
    output = "\n".join(lines) + "\n"
    if len(output) > 8192:
        raise ValueError("output limit")
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError):
        print("U2_XDCI_CENSUS rejected")
        raise SystemExit(1)
