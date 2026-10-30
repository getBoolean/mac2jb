#!/var/jb/usr/bin/python3
"""Compare a default-created USB description with live registry properties.

The script creates one controller and one default description, reads its
private info dictionary through the one-argument getter used by an iOS USB
configuration implementation, and compares it in memory with the controller's
existing live/default registry dictionaries. It reports only counts and an
equality category. It invokes no SetDescription, SendCommand, bus-cycle,
registry-write, file-write, or USB request operation.
"""

import ctypes
import os
import plistlib


def main():
    if os.geteuid() != 0:
        return "U2_RELATION rejected"
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    create_controller = io.IOUSBDeviceControllerCreate
    create_controller.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    create_controller.restype = ctypes.c_int32
    create_default = io.IOUSBDeviceDescriptionCreateFromDefaultsAndController
    create_default.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    create_default.restype = ctypes.c_void_p
    get_info = io._IOUSBDeviceDescriptionGetInfo
    get_info.argtypes = (ctypes.c_void_p,)
    get_info.restype = ctypes.c_void_p
    get_controller_service = io.IOUSBDeviceControllerGetService
    get_controller_service.argtypes = (ctypes.c_void_p,)
    get_controller_service.restype = ctypes.c_uint32
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (
        ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    io.IOServiceGetMatchingServices.restype = ctypes.c_int32
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IORegistryEntryGetRegistryEntryID.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64))
    io.IORegistryEntryGetRegistryEntryID.restype = ctypes.c_int32
    io.IORegistryEntryCreateCFProperties.argtypes = (
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_uint32)
    io.IORegistryEntryCreateCFProperties.restype = ctypes.c_int32
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
    cf.CFDictionaryGetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionarySetValue.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p)
    cf.CFEqual.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cf.CFEqual.restype = ctypes.c_bool
    cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p,
                                              ctypes.c_uint32)
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = (ctypes.c_void_p,)
    cf.CFPropertyListCreateData.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
    cf.CFPropertyListCreateData.restype = ctypes.c_void_p
    cf.CFDataGetLength.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetBytePtr.argtypes = (ctypes.c_void_p,)
    cf.CFDataGetBytePtr.restype = ctypes.c_void_p

    def as_dict(value):
        error = ctypes.c_void_p()
        data = cf.CFPropertyListCreateData(None, value, 200, 0,
                                           ctypes.byref(error))
        if error.value:
            cf.CFRelease(error)
        if not data:
            return None
        try:
            size = cf.CFDataGetLength(data)
            if not 8 <= size <= 512 * 1024:
                return None
            address = cf.CFDataGetBytePtr(data)
            result = plistlib.loads(ctypes.string_at(address, size)) if address else None
            return result if isinstance(result, dict) else None
        finally:
            cf.CFRelease(data)

    controller = ctypes.c_void_p()
    if create_controller(None, ctypes.byref(controller)) != 0 or not controller.value:
        return "U2_RELATION controller=unavailable"
    try:
        description = create_default(None, controller)
        if not description:
            return "U2_RELATION description=absent"
        try:
            info = get_info(description)
            if not info or cf.CFGetTypeID(info) != cf.CFDictionaryGetTypeID():
                return "U2_RELATION info=unavailable"
            info_count = cf.CFDictionaryGetCount(info)
            if not 1 <= info_count <= 128:
                return "U2_RELATION info=unexpected-count"
            matching = io.IOServiceMatching(b"IOUSBDeviceController")
            if not matching:
                return "U2_RELATION registry=unavailable"
            iterator = ctypes.c_uint32()
            if io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)) != 0:
                return "U2_RELATION registry=unavailable"
            service = io.IOIteratorNext(iterator.value)
            if not service:
                io.IOObjectRelease(iterator.value)
                return "U2_RELATION registry=unavailable"
            try:
                extra = io.IOIteratorNext(iterator.value)
                if extra:
                    io.IOObjectRelease(extra)
                    return "U2_RELATION registry=ambiguous"
                properties = ctypes.c_void_p()
                if io.IORegistryEntryCreateCFProperties(
                        service, ctypes.byref(properties), None, 0) != 0 or not properties.value:
                    return "U2_RELATION registry=unavailable"
                try:
                    result = []
                    registry = []
                    registry_values = []
                    for name in (b"DefaultDeviceDescription", b"DeviceDescription"):
                        key = cf.CFStringCreateWithCString(None, name, 0x08000100)
                        if not key:
                            return "U2_RELATION registry=unavailable"
                        try:
                            value = cf.CFDictionaryGetValue(properties, key)
                        finally:
                            cf.CFRelease(key)
                        if not value or cf.CFGetTypeID(value) != cf.CFDictionaryGetTypeID():
                            return "U2_RELATION registry=unavailable"
                        result.append(cf.CFEqual(info, value))
                        registry.append(as_dict(value))
                        registry_values.append(value)
                    created = as_dict(info)
                    if created is None or any(item is None for item in registry):
                        return "U2_RELATION serialization=unavailable"
                    default, live = registry
                    relation = ("equal-default" if result[0] else
                                "equal-live" if result[1] else "different")
                    default_subset = all(key in created and created[key] == value
                                         for key, value in default.items())
                    live_subset = all(key in live and live[key] == value
                                      for key, value in created.items())
                    config = ("same" if created.get("ConfigurationDescriptors") ==
                              live.get("ConfigurationDescriptors") else
                              "absent" if "ConfigurationDescriptors" not in created else "different")
                    missing = set(live) - set(created)
                    expected_missing = {"uniqueDeviceID", "serialNumber", "BcdUSBVersion", "MPS0"}
                    missing_category = ("expected-four" if missing == expected_missing else "other")
                    reconstructed = dict(created)
                    reconstructed.update({key: live[key] for key in missing})
                    from_controller = get_controller_service(controller)
                    controller_id = ctypes.c_uint64()
                    registry_id = ctypes.c_uint64()
                    controller_match = (
                        "yes" if from_controller and
                        io.IORegistryEntryGetRegistryEntryID(
                            from_controller, ctypes.byref(controller_id)) == 0 and
                        io.IORegistryEntryGetRegistryEntryID(
                            service, ctypes.byref(registry_id)) == 0 and
                        controller_id.value == registry_id.value else "no")
                    in_memory = "skipped"
                    if (default_subset and live_subset and config == "same" and
                            missing_category == "expected-four"):
                        for name in sorted(missing):
                            key = cf.CFStringCreateWithCString(None, name.encode("utf-8"),
                                                                 0x08000100)
                            if not key:
                                return "U2_RELATION registry=unavailable"
                            try:
                                value = cf.CFDictionaryGetValue(registry_values[1], key)
                                if not value:
                                    return "U2_RELATION registry=unavailable"
                                cf.CFDictionarySetValue(info, key, value)
                            finally:
                                cf.CFRelease(key)
                        in_memory = ("equal-live" if cf.CFEqual(info, registry_values[1])
                                     else "different")
                    return ("U2_RELATION info=dict count=" + str(info_count) +
                            " relation=" + relation +
                            " default-subset=" + ("yes" if default_subset else "no") +
                            " live-subset=" + ("yes" if live_subset else "no") +
                            " configuration-list=" + config +
                            " missing=" + missing_category +
                            " reconstructed=" + ("equal-live" if reconstructed == live else "different") +
                            " in-memory-object=" + in_memory +
                            " controller-match=" + controller_match)
                finally:
                    cf.CFRelease(properties)
            finally:
                io.IOObjectRelease(service)
                io.IOObjectRelease(iterator.value)
        finally:
            cf.CFRelease(description)
    finally:
        cf.CFRelease(controller)


if __name__ == "__main__":
    try:
        print(main())
    except (AttributeError, OSError, plistlib.InvalidFileException, ValueError):
        print("U2_RELATION rejected")
