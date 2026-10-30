#!/var/jb/usr/bin/python3
"""Clear a forced-off USB controller state once, if exact guards hold.

The Mac streams this source over pinned root Wi-Fi SSH. It requires the exact
backed-up v7 journal and its controller identity, checks the controller is
disconnected/off bus with selected configuration zero but software link L0,
then calls Apple's IOUSBDeviceControllerForceOffBus(controller, false) once.
It never calls SetDescription, GoOffAndOnBus, ForceOffBus(true), restart, or
any file writer. A successful API return does not prove USB recovery; the Mac
must independently observe and compare external functions. Do not rerun.
"""

import base64
import ctypes
import hashlib
import json
import os
import stat


STATE = "/var/jb/var/lib/mac2jb-u2-native"
JOURNAL_SHA = "0f265fd17847a9db1a1bc6814e39e7da94fd1eaef6e736811e3d618af1bbb02e"
IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"


def journal_identity():
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("unsafe state directory")
        fd = os.open("restore-journal.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                    not 0 < info.st_size <= 2_000_000):
                raise ValueError("unsafe journal")
            data = bytearray()
            while len(data) < info.st_size:
                chunk = os.read(fd, info.st_size - len(data))
                if not chunk:
                    raise ValueError("short journal")
                data.extend(chunk)
            if hashlib.sha256(data).hexdigest() != JOURNAL_SHA:
                raise ValueError("journal changed")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    envelope = json.loads(data)
    payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
    if payload["phase"] != "awaitingVerification":
        raise ValueError("journal phase changed")
    identity = payload["recipe"]["controllerIdentity"]
    if not isinstance(identity, str) or not identity.isdecimal():
        raise ValueError("controller identity invalid")
    return int(identity)


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    expected_id = journal_identity()
    io = ctypes.CDLL(IOKIT)
    cf = ctypes.CDLL(CORE)
    io.IOUSBDeviceControllerCreate.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    io.IOUSBDeviceControllerCreate.restype = ctypes.c_int32
    io.IOUSBDeviceControllerGetService.argtypes = (ctypes.c_void_p,)
    io.IOUSBDeviceControllerGetService.restype = ctypes.c_uint32
    io.IORegistryEntryGetRegistryEntryID.argtypes = (ctypes.c_uint32,
                                                     ctypes.POINTER(ctypes.c_uint64))
    io.IORegistryEntryGetRegistryEntryID.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    io.IOUSBDeviceControllerForceOffBus.argtypes = (ctypes.c_void_p, ctypes.c_int)
    io.IOUSBDeviceControllerForceOffBus.restype = ctypes.c_int32
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                               ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = (ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def member(dictionary, key):
        name = cf.CFStringCreateWithCString(None, key, 0x08000100)
        if not name:
            raise ValueError("key unavailable")
        try:
            return cf.CFDictionaryGetValue(dictionary, name)
        finally:
            cf.CFRelease(name)

    controller = ctypes.c_void_p()
    if io.IOUSBDeviceControllerCreate(None, ctypes.byref(controller)) != 0 or not controller.value:
        raise ValueError("controller unavailable")
    try:
        service = io.IOUSBDeviceControllerGetService(controller)
        actual_id = ctypes.c_uint64()
        if (not service or io.IORegistryEntryGetRegistryEntryID(
                service, ctypes.byref(actual_id)) != 0 or actual_id.value != expected_id):
            raise ValueError("controller identity changed")
        properties = ctypes.c_void_p()
        if io.IORegistryEntryCreateCFProperties(
                service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
            raise ValueError("controller state unavailable")
        try:
            state = member(properties, b"CurrentState")
            if not state or cf.CFGetTypeID(state) != cf.CFDictionaryGetTypeID():
                raise ValueError("invalid current state")
            device_state = member(state, b"DeviceState")
            on_bus = member(state, b"OnBus")
            selected = member(state, b"SelectedConfiguration")
            link = member(state, b"SoftwareLinkState")
            if (not device_state or cf.CFGetTypeID(device_state) != cf.CFStringGetTypeID() or
                    not on_bus or cf.CFGetTypeID(on_bus) != cf.CFBooleanGetTypeID() or
                    not selected or cf.CFGetTypeID(selected) != cf.CFNumberGetTypeID() or
                    not link or cf.CFGetTypeID(link) != cf.CFStringGetTypeID()):
                raise ValueError("state type changed")
            selected_value = ctypes.c_int32()
            device_text = ctypes.create_string_buffer(40)
            link_text = ctypes.create_string_buffer(40)
            if (not cf.CFNumberGetValue(selected, 3, ctypes.byref(selected_value)) or
                    not cf.CFStringGetCString(device_state, device_text, 40, 0x08000100) or
                    not cf.CFStringGetCString(link, link_text, 40, 0x08000100) or
                    device_text.value != b"Disconnected" or
                    cf.CFBooleanGetValue(on_bus) or selected_value.value != 0 or
                    link_text.value != b"L0 (Normal)"):
                raise ValueError("controller no longer in expected state")
        finally:
            cf.CFRelease(properties)
        status = io.IOUSBDeviceControllerForceOffBus(controller, 0)
        print("U2_FORCEOFF_RELEASE api=" + ("success" if status == 0 else "rejected"))
        if status != 0:
            raise ValueError("force-off release rejected")
    finally:
        cf.CFRelease(controller)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print("U2_FORCEOFF_RELEASE rejected; no retry")
        raise SystemExit(1)
