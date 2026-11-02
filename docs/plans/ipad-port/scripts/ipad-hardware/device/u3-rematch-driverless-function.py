#!/var/jb/usr/bin/python3
"""Report, and at most probe, a driverless audio USB function nub (no publication).

Effect: `--inspect` reads IORegistry only. It finds the sole IOUSBDeviceController,
lists every `IOUSBDeviceInterface` child with its function name, its IOService
child count and child classes, and marks which audio nubs have no driver.
`--probe FUNCTION` additionally calls `IOServiceRequestProbe(nub, 0)` on exactly
one nub, which reaches `IOService::requestProbe` on that nub and nothing else;
the generic IOService implementation returns kIOReturnUnsupported, so the
expected outcome is a no-op. It refuses unless the controller is configured and
on bus, the name is one of the five audio functions, exactly one nub carries
that name, that nub conforms to IOUSBDeviceInterface, is not busy, and has no
IOService child. It never probes the controller or any other node, never opens a
user client, never calls the controller, and never reads or writes a journal or
any file. No IDs, serials, paths or property values leave the device.
"""

import ctypes
import os
import re
import signal
import sys
import time


MAX_NUBS = 32
MAX_CHILDREN = 4
MAX_SECONDS = 6
SETTLE_SECONDS = 3
CLASS = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}\Z")
NAME = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
# The audio functions and the kernel driver each one carries when healthy. Only
# these may be probed: every other function on this controller is either
# user-space owned (restart its owner instead) or host-dependent.
AUDIO_DRIVERS = {
    "USBAudio2Control": "AppleUSBDeviceAudioController",
    "USBAudio2StreamIN": "AppleUSBDeviceAudioController",
    "USBAudio2StreamOUT": "AppleUSBDeviceAudioController",
    "USBAudioControl": "AppleUSBMike",
    "USBAudioStreaming": "AppleUSBMike",
}
FUNCTION_KEYS = ("USBDeviceFunction", "kUSBDeviceFunction", "InterfaceName")
STATES = {"Disconnected": "disconnected", "Attached": "attached",
          "Powered": "powered", "Default": "default", "Addressed": "addressed",
          "Configured": "configured", "Suspended": "suspended"}
RETURNS = {
    0x00000000: "success",
    0xE00002BC: "error",
    0xE00002C0: "no-device",
    0xE00002C1: "not-privileged",
    0xE00002C2: "bad-argument",
    0xE00002C7: "unsupported",
    0xE00002E2: "not-permitted",
    0xE00002F0: "not-found",
    0xFFFFFEED: "mig-bad-id",
}
UTF8 = 0x08000100


def timed_out(_signum, _frame):
    raise TimeoutError("deadline")


def ioreturn_name(value):
    """Name a kern_return_t the probe can return, without hiding the number."""
    return RETURNS.get(value & 0xFFFFFFFF, "other")


def require_configured(state):
    """Refuse to act unless the controller is configured and on bus.

    A probe is only ever attempted on a healthy controller. While the controller
    is off bus a re-publication is the remedy and the healer owns it; adding a
    family-interpreted call to that window could only confuse the diagnosis.
    """
    device_state, onbus, configuration = state
    if device_state != "configured" or onbus != "yes" or configuration <= 0:
        raise ValueError("controller not configured")
    return state


def classify(nubs):
    """Describe each (function, child classes) nub: served, audio, probe-eligible."""
    records = []
    for function, children in nubs:
        if function != "absent" and not NAME.fullmatch(function):
            raise ValueError("function name invalid")
        for child in children:
            if not CLASS.fullmatch(child):
                raise ValueError("child class invalid")
        expected = AUDIO_DRIVERS.get(function)
        served = len(children) > 0
        records.append({"function": function, "children": tuple(children),
                        "served": served, "audio": expected is not None,
                        "expected": expected,
                        "eligible": expected is not None and not served})
    return tuple(records)


def summary(records):
    audio = [record for record in records if record["audio"]]
    return {"functions": len(records), "audio": len(audio),
            "driverless_audio": len([r for r in audio if not r["served"]]),
            "served_audio": len([r for r in audio if r["served"]]),
            "other_driverless": len([r for r in records
                                     if not r["audio"] and not r["served"]])}


def target(records, requested):
    """Return the single nub that may be probed, or refuse with the reason."""
    if not NAME.fullmatch(requested or ""):
        raise ValueError("function name invalid")
    if requested not in AUDIO_DRIVERS:
        raise ValueError("not an audio function")
    matches = [record for record in records if record["function"] == requested]
    if not matches:
        raise ValueError("function absent")
    if len(matches) > 1:
        raise ValueError("function ambiguous")
    if matches[0]["served"]:
        raise ValueError("function already served")
    return matches[0]


def render_inspect(records, state):
    counts = summary(records)
    lines = ["U3_REMATCH inspect functions=%d audio=%d driverless-audio=%d "
             "served-audio=%d other-driverless=%d state=%s/%s/%d" %
             (counts["functions"], counts["audio"], counts["driverless_audio"],
              counts["served_audio"], counts["other_driverless"],
              state[0], state[1], state[2])]
    for record in records:
        lines.append("U3_REMATCH_NUB function=%s served=%s audio=%s expected=%s "
                     "children=%d classes=%s" %
                     (record["function"], "yes" if record["served"] else "no",
                      "yes" if record["audio"] else "no",
                      record["expected"] or "none", len(record["children"]),
                      "+".join(record["children"]) or "none"))
    lines.append("U3_REMATCH done")
    return "\n".join(lines) + "\n"


def render_probe(record, result, children_after, state):
    appeared = tuple(children_after)
    return ("U3_REMATCH probe function=%s expected=%s options=0 result=0x%08x "
            "ret=%s children-before=0 children-after=%d classes=%s rematched=%s "
            "state=%s/%s/%d\nU3_REMATCH done\n" %
            (record["function"], record["expected"] or "none",
             result & 0xFFFFFFFF, ioreturn_name(result), len(appeared),
             "+".join(appeared) or "none",
             "yes" if record["expected"] in appeared else "no",
             state[0], state[1], state[2]))


def main(mode, requested):
    if os.geteuid() != 0:
        raise ValueError("root required")
    if mode not in ("--inspect", "--probe") or (mode == "--probe") != bool(requested):
        raise ValueError("usage: --inspect | --probe FUNCTION")
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
    io.IOObjectConformsTo.argtypes = (ctypes.c_uint32, ctypes.c_char_p)
    io.IOObjectConformsTo.restype = ctypes.c_bool
    io.IOServiceGetBusyState.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetBusyState.restype = ctypes.c_int32
    io.IOServiceRequestProbe.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    io.IOServiceRequestProbe.restype = ctypes.c_int32
    io.IORegistryEntryGetChildIterator.argtypes = (ctypes.c_uint32, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryGetChildIterator.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperty.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                                   ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
    io.IORegistryEntryCreateCFProperties.argtypes = (ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
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
        name = buffer.value.decode("ascii", "strict")
        if not CLASS.fullmatch(name):
            raise ValueError("class invalid")
        return name

    def key_of(name):
        key = cf.CFStringCreateWithCString(None, name.encode("ascii"), UTF8)
        if not key:
            raise ValueError("key unavailable")
        return key

    def string_property(entry, name):
        key = key_of(name)
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
            return buffer.value.decode("ascii", "replace")
        finally:
            cf.CFRelease(value)

    def member(dictionary, name):
        key = key_of(name)
        try:
            return cf.CFDictionaryGetValue(dictionary, key)
        finally:
            cf.CFRelease(key)

    def function_of(entry):
        for key in FUNCTION_KEYS:
            value = string_property(entry, key)
            if value is not None:
                return value.replace(" ", "_") if NAME.fullmatch(value) else "invalid"
        return "absent"

    def children_of(entry):
        classes = []
        children = ctypes.c_uint32()
        if io.IORegistryEntryGetChildIterator(entry, b"IOService", ctypes.byref(children)) != 0:
            raise ValueError("children unavailable")
        try:
            while True:
                child = io.IOIteratorNext(children.value)
                if not child:
                    break
                try:
                    if len(classes) >= MAX_CHILDREN:
                        raise ValueError("child limit")
                    classes.append(class_of(child))
                finally:
                    io.IOObjectRelease(child)
        finally:
            io.IOObjectRelease(children.value)
        return tuple(classes)

    def controller_state(entry):
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(entry, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            raise ValueError("properties unavailable")
        try:
            state = member(properties, "CurrentState")
            if not state or cf.CFGetTypeID(state) != cf.CFDictionaryGetTypeID():
                raise ValueError("CurrentState unavailable")
            text = member(state, "DeviceState")
            onbus = member(state, "OnBus")
            configuration = member(state, "SelectedConfiguration")
            if (not text or cf.CFGetTypeID(text) != cf.CFStringGetTypeID() or
                    not onbus or cf.CFGetTypeID(onbus) != cf.CFBooleanGetTypeID() or
                    not configuration or cf.CFGetTypeID(configuration) != cf.CFNumberGetTypeID()):
                raise ValueError("state keys unavailable")
            buffer = ctypes.create_string_buffer(64)
            if not cf.CFStringGetCString(text, buffer, len(buffer), UTF8):
                raise ValueError("DeviceState invalid")
            selected = ctypes.c_int64()
            if not cf.CFNumberGetValue(configuration, 4, ctypes.byref(selected)) or not 0 <= selected.value <= 255:
                raise ValueError("SelectedConfiguration invalid")
            return (STATES.get(buffer.value.decode("ascii", "ignore"), "other"),
                    "yes" if cf.CFBooleanGetValue(onbus) else "no", selected.value)
        finally:
            cf.CFRelease(properties)

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(12)
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

    nubs = []  # (entry, function)
    try:
        state = require_configured(controller_state(root))
        children = ctypes.c_uint32()
        if io.IORegistryEntryGetChildIterator(root, b"IOService", ctypes.byref(children)) != 0:
            raise ValueError("children unavailable")
        try:
            while True:
                child = io.IOIteratorNext(children.value)
                if not child:
                    break
                keep = False
                try:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("deadline")
                    if io.IOObjectConformsTo(child, b"IOUSBDeviceInterface"):
                        if len(nubs) >= MAX_NUBS:
                            raise ValueError("nub limit")
                        nubs.append((child, function_of(child)))
                        keep = True
                finally:
                    if not keep:
                        io.IOObjectRelease(child)
        finally:
            io.IOObjectRelease(children.value)
        records = classify([(function, children_of(entry)) for entry, function in nubs])
        if mode == "--inspect":
            output = render_inspect(records, state)
        else:
            record = target(records, requested)
            chosen = [entry for entry, function in nubs if function == record["function"]]
            if len(chosen) != 1:
                raise ValueError("function ambiguous")
            entry = chosen[0]
            # Belt and braces: the one node that must never be probed is the
            # controller, because a family rescan there is what recreates every
            # nub. The nub was found as its child, so this cannot hold, and it
            # is checked anyway before the only call that is not a read.
            if entry == root or io.IOObjectConformsTo(entry, b"IOUSBDeviceController"):
                raise ValueError("refusing to probe the controller")
            if not io.IOObjectConformsTo(entry, b"IOUSBDeviceInterface"):
                raise ValueError("not a function nub")
            busy = ctypes.c_uint32()
            if io.IOServiceGetBusyState(entry, ctypes.byref(busy)) != 0 or busy.value != 0:
                raise ValueError("nub busy")
            if children_of(entry):
                raise ValueError("function already served")
            result = io.IOServiceRequestProbe(entry, 0)
            settle = time.monotonic() + SETTLE_SECONDS
            after = children_of(entry)
            while not after and time.monotonic() < settle:
                time.sleep(0.5)
                after = children_of(entry)
            output = render_probe(record, result, after, controller_state(root))
    finally:
        for entry, _ in nubs:
            io.IOObjectRelease(entry)
        io.IOObjectRelease(root)
        signal.alarm(0)

    if len(output) > 4096:
        raise ValueError("output limit")
    print(output, end="")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) > 1 else "",
             sys.argv[2] if len(sys.argv) == 3 else "")
    except (OSError, ValueError, TimeoutError, TypeError, UnicodeError):
        print("U3_REMATCH rejected")
        raise SystemExit(1)
