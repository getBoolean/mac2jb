#!/var/jb/usr/bin/python3
"""Exact-target USB description constructor for the rootless watchdog.

The caller supplies a privately captured binary-plist live description and
the controller registry ID. This module reconstructs an opaque description
from the target's defaults, checks that its in-memory dictionary equals the
saved live dictionary, and checks the controller identity. Only publish() may
call SetDescription and an optional bounded off/on-bus cycle. It must be used
only after the watchdog has fsynced its restore journal. It never edits the
stock configuration plist or any other system file.
"""

import ctypes
import plistlib


IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
CORE = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
MISSING_FIELDS = {"uniqueDeviceID", "serialNumber", "BcdUSBVersion", "MPS0"}


class ControllerError(Exception):
    pass


def _functions():
    io = ctypes.CDLL(IOKIT)
    cf = ctypes.CDLL(CORE)

    def api(library, name, arguments, result):
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
        return function

    return {
        "create_controller": api(io, "IOUSBDeviceControllerCreate",
                                 (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)),
                                 ctypes.c_int32),
        "create_default": api(io, "IOUSBDeviceDescriptionCreateFromDefaultsAndController",
                              (ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p),
        "get_info": api(io, "_IOUSBDeviceDescriptionGetInfo", (ctypes.c_void_p,),
                        ctypes.c_void_p),
        "get_service": api(io, "IOUSBDeviceControllerGetService", (ctypes.c_void_p,),
                           ctypes.c_uint32),
        "registry_id": api(io, "IORegistryEntryGetRegistryEntryID",
                           (ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64)),
                           ctypes.c_int32),
        "set_description": api(io, "IOUSBDeviceControllerSetDescription",
                               (ctypes.c_void_p, ctypes.c_void_p), ctypes.c_int32),
        "cycle_bus": api(io, "IOUSBDeviceControllerGoOffAndOnBus",
                         (ctypes.c_void_p, ctypes.c_uint32), ctypes.c_int32),
        "cf_data": api(cf, "CFDataCreate",
                       (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long),
                       ctypes.c_void_p),
        "parse_plist": api(cf, "CFPropertyListCreateWithData",
                           (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)),
                           ctypes.c_void_p),
        "serialize_plist": api(cf, "CFPropertyListCreateData",
                               (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long,
                                ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)),
                               ctypes.c_void_p),
        "data_length": api(cf, "CFDataGetLength", (ctypes.c_void_p,), ctypes.c_long),
        "data_pointer": api(cf, "CFDataGetBytePtr", (ctypes.c_void_p,), ctypes.c_void_p),
        "dict_value": api(cf, "CFDictionaryGetValue",
                          (ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p),
        "dict_set": api(cf, "CFDictionarySetValue",
                        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p), None),
        "string": api(cf, "CFStringCreateWithCString",
                      (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32),
                      ctypes.c_void_p),
        "equal": api(cf, "CFEqual", (ctypes.c_void_p, ctypes.c_void_p), ctypes.c_bool),
        "type_id": api(cf, "CFGetTypeID", (ctypes.c_void_p,), ctypes.c_ulong),
        "dict_type": api(cf, "CFDictionaryGetTypeID", (), ctypes.c_ulong),
        "release": api(cf, "CFRelease", (ctypes.c_void_p,), None),
        "true": ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue"),
    }


def _plist_dict(raw):
    if not 8 <= len(raw) <= 1024 * 1024 or not raw.startswith(b"bplist00"):
        raise ControllerError("invalid description bytes")
    try:
        value = plistlib.loads(raw)
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise ControllerError("invalid description plist") from error
    if not isinstance(value, dict) or len(value) != 16:
        raise ControllerError("unexpected description fields")
    return value


def _serialize(api, value):
    error = ctypes.c_void_p()
    data = api["serialize_plist"](None, value, 200, 0, ctypes.byref(error))
    if error.value:
        api["release"](error)
    if not data:
        raise ControllerError("description serialization failed")
    try:
        size = api["data_length"](data)
        address = api["data_pointer"](data)
        if not 8 <= size <= 1024 * 1024 or not address:
            raise ControllerError("description serialization size")
        return plistlib.loads(ctypes.string_at(address, size))
    finally:
        api["release"](data)


def reconstruct_or_publish(live_plist, expected_registry_id, publish=False, cycle_bus=False):
    """Return a fixed category; raise before mutation on any identity mismatch."""
    if cycle_bus and not publish:
        raise ControllerError("invalid cycle request")
    if type(expected_registry_id) is not int or expected_registry_id <= 0:
        raise ControllerError("invalid controller identity")
    expected = _plist_dict(live_plist)
    api = _functions()
    input_buffer = ctypes.create_string_buffer(live_plist)
    data = api["cf_data"](None, input_buffer, len(live_plist))
    if not data:
        raise ControllerError("description allocation failed")
    error = ctypes.c_void_p()
    decoded = api["parse_plist"](None, data, 0, None, ctypes.byref(error))
    api["release"](data)
    if error.value:
        api["release"](error)
    if not decoded or api["type_id"](decoded) != api["dict_type"]():
        if decoded:
            api["release"](decoded)
        raise ControllerError("description decoding failed")
    try:
        controller = ctypes.c_void_p()
        if api["create_controller"](None, ctypes.byref(controller)) != 0 or not controller.value:
            raise ControllerError("controller unavailable")
        try:
            service = api["get_service"](controller)
            actual_id = ctypes.c_uint64()
            if (not service or api["registry_id"](service, ctypes.byref(actual_id)) != 0 or
                    actual_id.value != expected_registry_id):
                raise ControllerError("controller identity changed")
            description = api["create_default"](None, controller)
            if not description:
                raise ControllerError("default description unavailable")
            try:
                info = api["get_info"](description)
                if not info or api["type_id"](info) != api["dict_type"]():
                    raise ControllerError("description info unavailable")
                current = _serialize(api, info)
                if (not isinstance(current, dict) or len(current) != 12 or
                        set(expected) - set(current) != MISSING_FIELDS or
                        any(key not in expected or expected[key] != value
                            for key, value in current.items())):
                    raise ControllerError("default description mismatch")
                for name in sorted(MISSING_FIELDS):
                    key = api["string"](None, name.encode("ascii"), 0x08000100)
                    if not key:
                        raise ControllerError("field allocation failed")
                    try:
                        value = api["dict_value"](decoded, key)
                        if not value:
                            raise ControllerError("missing restore field")
                        api["dict_set"](info, key, value)
                    finally:
                        api["release"](key)
                if not api["equal"](info, decoded):
                    raise ControllerError("reconstructed description mismatch")
                if not publish:
                    return "in-memory-equal"
                flag = api["string"](None, b"AllowMultipleCreates", 0x08000100)
                if not flag:
                    raise ControllerError("flag allocation failed")
                try:
                    api["dict_set"](info, flag, api["true"])
                finally:
                    api["release"](flag)
                if api["set_description"](controller, description) != 0:
                    raise ControllerError("set description failed")
                if cycle_bus and api["cycle_bus"](controller, 1000) != 0:
                    raise ControllerError("bus cycle failed")
                return "published"
            finally:
                api["release"](description)
        finally:
            api["release"](controller)
    finally:
        api["release"](decoded)
