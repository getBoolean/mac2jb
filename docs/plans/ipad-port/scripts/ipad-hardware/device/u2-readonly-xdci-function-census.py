#!/var/jb/usr/bin/python3
"""Bounded read-only per-node census of the sole XDCI controller subtree.

Effect: reads IORegistry only. For each IOService node under the controller it
emits depth, parent index, class, IOKit busy state, the interface function name
(on IOUSBDeviceInterface nodes) and the creating process name (on nodes with
IOUserClientCreator, PID stripped). No IDs, serials, paths, file writes, user
clients, or controller commands.
"""

import ctypes
import os
import re
import signal
import time


MAX_DEPTH = 6
MAX_NODES = 128
MAX_SECONDS = 6
CLASS = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}\Z")
FUNCTION = re.compile(r"[A-Za-z0-9_+ -]{1,64}\Z")
PROCESS = re.compile(r"[A-Za-z0-9._-]{1,48}\Z")
CREATOR = re.compile(r"pid -?[0-9]+, (.*)\Z")
FUNCTION_KEYS = ("USBDeviceFunction", "kUSBDeviceFunction", "InterfaceName")
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
    io.IOServiceGetBusyState.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetBusyState.restype = ctypes.c_int32
    io.IORegistryEntryGetChildIterator.argtypes = (ctypes.c_uint32, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetChildIterator.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperty.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                                   ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
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
        name = buffer.value.decode("ascii", "strict")
        if not CLASS.fullmatch(name):
            raise ValueError("class invalid")
        return name

    def string_property(entry, name):
        key = cf.CFStringCreateWithCString(None, name.encode("ascii"), UTF8)
        if not key:
            raise ValueError("key unavailable")
        try:
            value = io.IORegistryEntryCreateCFProperty(entry, key, None, 0)
        finally:
            cf.CFRelease(key)
        if not value:
            return None
        try:
            if cf.CFGetTypeID(value) != cf.CFStringGetTypeID():
                return None
            buffer = ctypes.create_string_buffer(256)
            if not cf.CFStringGetCString(value, buffer, len(buffer), UTF8):
                return None
            return buffer.value.decode("utf-8", "replace")
        finally:
            cf.CFRelease(value)

    def busy_of(entry):
        busy = ctypes.c_uint32()
        if io.IOServiceGetBusyState(entry, ctypes.byref(busy)) != 0:
            return "unknown"
        return str(min(busy.value, 99))

    def describe(entry, cls):
        fields = []
        if cls == "IOUSBDeviceInterface":
            function = "absent"
            for key in FUNCTION_KEYS:
                value = string_property(entry, key)
                if value is not None:
                    function = value.replace(" ", "_") if FUNCTION.fullmatch(value) else "invalid"
                    break
            fields.append("function=" + function)
        creator = string_property(entry, "IOUserClientCreator")
        if creator is not None:
            match = CREATOR.fullmatch(creator)
            name = match[1] if match else ""
            fields.append("creator=" + (name if PROCESS.fullmatch(name) else "invalid"))
        return fields

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(10)
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

    nodes = []  # (entry, index, parent, depth, class)
    lines = []
    try:
        nodes.append((root, 0, -1, 0, ""))
        root_class = class_of(root)
        if root_class != "AppleT8112USBXDCI":
            raise ValueError("controller class")
        nodes[0] = (root, 0, -1, 0, root_class)
        position = 0
        while position < len(nodes):
            if time.monotonic() >= deadline:
                raise TimeoutError("deadline")
            entry, index, parent, depth, cls = nodes[position]
            position += 1
            fields = ["i=%d" % index, "parent=%d" % parent, "depth=%d" % depth,
                      "class=" + cls, "busy=" + busy_of(entry)] + describe(entry, cls)
            lines.append("U2_XDCI_NODE " + " ".join(fields))
            if depth >= MAX_DEPTH:
                continue
            children = ctypes.c_uint32()
            if io.IORegistryEntryGetChildIterator(entry, b"IOService", ctypes.byref(children)) != 0:
                raise ValueError("children unavailable")
            try:
                while True:
                    child = io.IOIteratorNext(children.value)
                    if not child:
                        break
                    if len(nodes) >= MAX_NODES:
                        io.IOObjectRelease(child)
                        raise ValueError("node limit")
                    try:
                        child_class = class_of(child)
                    except BaseException:
                        io.IOObjectRelease(child)
                        raise
                    nodes.append((child, len(nodes), index, depth + 1, child_class))
            finally:
                io.IOObjectRelease(children.value)
    finally:
        for entry, _, _, _, _ in nodes:
            io.IOObjectRelease(entry)
        signal.alarm(0)

    output = ("U2_XDCI_FUNCTIONS nodes=%d\n" % len(lines) + "\n".join(lines) +
              "\nU2_XDCI_FUNCTIONS done\n")
    if len(output) > 16384:
        raise ValueError("output limit")
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, TypeError, UnicodeError):
        print("U2_XDCI_FUNCTIONS rejected")
        raise SystemExit(1)
