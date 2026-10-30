#include "USBRestoreControllerShim.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef const void *ControllerRef;
typedef const void *DescriptionRef;
typedef IOReturn (*CreateController)(CFAllocatorRef, ControllerRef *);
typedef DescriptionRef (*CreateDefault)(CFAllocatorRef, ControllerRef);
typedef DescriptionRef (*CreateFromController)(CFAllocatorRef, ControllerRef);
typedef CFMutableDictionaryRef (*GetInfo)(DescriptionRef);
typedef io_service_t (*GetService)(ControllerRef);
typedef IOReturn (*SetDescription)(ControllerRef, DescriptionRef);
typedef IOReturn (*GoOffAndOnBus)(ControllerRef, uint32_t);

static bool contains_equal_values(CFDictionaryRef source, CFDictionaryRef expected) {
    CFIndex count = CFDictionaryGetCount(source);
    if (count < 1 || count > 128) return false;
    const void *keys[128];
    const void *values[128];
    CFDictionaryGetKeysAndValues(source, keys, values);
    for (CFIndex index = 0; index < count; index++) {
        const void *other = CFDictionaryGetValue(expected, keys[index]);
        if (!other || !CFEqual(values[index], other)) return false;
    }
    return true;
}

MAC2JBUSBResult MAC2JBUSBCaptureControllerRegistryID(uint64_t *controllerRegistryID) {
    if (!controllerRegistryID) return MAC2JBUSBInvalidInput;
    *controllerRegistryID = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceController");
    if (!matching) return MAC2JBUSBControllerUnavailable;
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != kIOReturnSuccess)
        return MAC2JBUSBControllerUnavailable;
    MAC2JBUSBResult result = MAC2JBUSBControllerUnavailable;
    io_service_t service = IOIteratorNext(iterator);
    if (!service) goto done;
    io_service_t extra = IOIteratorNext(iterator);
    if (extra) {
        IOObjectRelease(extra);
        goto release_service;
    }
    if (IORegistryEntryGetRegistryEntryID(service, controllerRegistryID) == kIOReturnSuccess &&
        *controllerRegistryID != 0) result = MAC2JBUSBSuccess;
release_service:
    IOObjectRelease(service);
done:
    IOObjectRelease(iterator);
    return result;
}

MAC2JBUSBResult MAC2JBUSBCopyConfiguredState(
    uint64_t expectedControllerRegistryID, bool *configured
) {
    if (!configured || expectedControllerRegistryID == 0) return MAC2JBUSBInvalidInput;
    *configured = false;
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceController");
    if (!matching) return MAC2JBUSBControllerUnavailable;
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) !=
        kIOReturnSuccess) return MAC2JBUSBControllerUnavailable;
    MAC2JBUSBResult result = MAC2JBUSBControllerUnavailable;
    io_service_t service = IOIteratorNext(iterator);
    if (!service) goto done;
    io_service_t extra = IOIteratorNext(iterator);
    if (extra) {
        IOObjectRelease(extra);
        goto release_service;
    }
    uint64_t registryID = 0;
    if (IORegistryEntryGetRegistryEntryID(service, &registryID) != kIOReturnSuccess ||
        registryID != expectedControllerRegistryID) {
        result = MAC2JBUSBWrongController;
        goto release_service;
    }
    CFMutableDictionaryRef properties = NULL;
    if (IORegistryEntryCreateCFProperties(service, &properties,
                                          kCFAllocatorDefault, 0) != kIOReturnSuccess ||
        !properties) goto release_service;
    CFTypeRef current = CFDictionaryGetValue(properties, CFSTR("CurrentState"));
    if (!current || CFGetTypeID(current) != CFDictionaryGetTypeID()) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_properties;
    }
    CFDictionaryRef state = (CFDictionaryRef)current;
    CFTypeRef deviceState = CFDictionaryGetValue(state, CFSTR("DeviceState"));
    CFTypeRef onBus = CFDictionaryGetValue(state, CFSTR("OnBus"));
    CFTypeRef configuration = CFDictionaryGetValue(state, CFSTR("SelectedConfiguration"));
    if (!deviceState || CFGetTypeID(deviceState) != CFStringGetTypeID() ||
        !onBus || CFGetTypeID(onBus) != CFBooleanGetTypeID() ||
        !configuration || CFGetTypeID(configuration) != CFNumberGetTypeID()) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_properties;
    }
    int32_t configurationNumber = -1;
    if (!CFNumberGetValue((CFNumberRef)configuration, kCFNumberSInt32Type,
                          &configurationNumber) ||
        configurationNumber < 0 || configurationNumber > 255) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_properties;
    }
    *configured = CFEqual(deviceState, CFSTR("Configured")) &&
        CFBooleanGetValue((CFBooleanRef)onBus) && configurationNumber > 0;
    result = MAC2JBUSBSuccess;
release_properties:
    CFRelease(properties);
release_service:
    IOObjectRelease(service);
done:
    IOObjectRelease(iterator);
    return result;
}

MAC2JBUSBResult MAC2JBUSBCaptureLiveDescription(
    uint8_t **bytes, size_t *length, uint64_t *controllerRegistryID
) {
    if (!bytes || !length || !controllerRegistryID) return MAC2JBUSBInvalidInput;
    *bytes = NULL;
    *length = 0;
    *controllerRegistryID = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceController");
    if (!matching) return MAC2JBUSBControllerUnavailable;
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != kIOReturnSuccess)
        return MAC2JBUSBControllerUnavailable;
    MAC2JBUSBResult result = MAC2JBUSBControllerUnavailable;
    io_service_t service = IOIteratorNext(iterator);
    if (!service) goto done;
    io_service_t extra = IOIteratorNext(iterator);
    if (extra) {
        IOObjectRelease(extra);
        goto release_service;
    }
    uint64_t registryID = 0;
    if (IORegistryEntryGetRegistryEntryID(service, &registryID) != kIOReturnSuccess ||
        registryID == 0) goto release_service;
    CFMutableDictionaryRef properties = NULL;
    if (IORegistryEntryCreateCFProperties(service, &properties,
                                          kCFAllocatorDefault, 0) != kIOReturnSuccess ||
        !properties) goto release_service;
    CFTypeRef description = CFDictionaryGetValue(properties, CFSTR("DeviceDescription"));
    CFIndex fieldCount = description && CFGetTypeID(description) == CFDictionaryGetTypeID()
        ? CFDictionaryGetCount((CFDictionaryRef)description) : 0;
    if (fieldCount != 16 && fieldCount != 17) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_properties;
    }
    CFErrorRef error = NULL;
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, description,
                                             kCFPropertyListBinaryFormat_v1_0, 0, &error);
    if (error) CFRelease(error);
    if (!data) { result = MAC2JBUSBDescriptionMismatch; goto release_properties; }
    CFIndex size = CFDataGetLength(data);
    if (size < 8 || size > 512 * 1024) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_data;
    }
    uint8_t *copy = malloc((size_t)size);
    if (!copy) { result = MAC2JBUSBInvalidInput; goto release_data; }
    memcpy(copy, CFDataGetBytePtr(data), (size_t)size);
    *bytes = copy;
    *length = (size_t)size;
    *controllerRegistryID = registryID;
    result = MAC2JBUSBSuccess;
release_data:
    CFRelease(data);
release_properties:
    CFRelease(properties);
release_service:
    IOObjectRelease(service);
done:
    IOObjectRelease(iterator);
    return result;
}

void MAC2JBUSBFreeCapturedDescription(uint8_t *bytes) {
    free(bytes);
}

static MAC2JBUSBResult reconstruct_or_clone(
    const uint8_t *livePlist,
    size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    bool publish,
    bool cycleBus,
    bool cloneCurrent,
    int32_t *setReturn,
    int32_t *busReturn
) {
    if (setReturn) *setReturn = kIOReturnNotReady;
    if (busReturn) *busReturn = kIOReturnNotReady;
    if (!livePlist || livePlistLength < 8 || livePlistLength > 1024 * 1024 ||
        expectedControllerRegistryID == 0 || (cycleBus && !publish)) {
        return MAC2JBUSBInvalidInput;
    }

    MAC2JBUSBResult result = MAC2JBUSBInvalidInput;
    CFDataRef input = CFDataCreate(kCFAllocatorDefault, livePlist, (CFIndex)livePlistLength);
    if (!input) return result;
    CFErrorRef error = NULL;
    CFPropertyListRef decoded = CFPropertyListCreateWithData(
        kCFAllocatorDefault, input, kCFPropertyListImmutable, NULL, &error);
    CFRelease(input);
    if (error) CFRelease(error);
    if (!decoded) return result;
    if (CFGetTypeID(decoded) != CFDictionaryGetTypeID() ||
        CFDictionaryGetCount((CFDictionaryRef)decoded) != 16) goto finished;

    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    if (!handle) { result = MAC2JBUSBMissingAPI; goto finished; }
    CreateController createController = (CreateController)dlsym(handle, "IOUSBDeviceControllerCreate");
    CreateDefault createDefault = (CreateDefault)dlsym(handle, "IOUSBDeviceDescriptionCreateFromDefaultsAndController");
    CreateFromController createFromController = (CreateFromController)dlsym(
        handle, "IOUSBDeviceDescriptionCreateFromController");
    GetInfo getInfo = (GetInfo)dlsym(handle, "_IOUSBDeviceDescriptionGetInfo");
    GetService getService = (GetService)dlsym(handle, "IOUSBDeviceControllerGetService");
    SetDescription setDescription = (SetDescription)dlsym(handle, "IOUSBDeviceControllerSetDescription");
    GoOffAndOnBus goOffAndOnBus = (GoOffAndOnBus)dlsym(handle, "IOUSBDeviceControllerGoOffAndOnBus");
    if (!createController || !(cloneCurrent ? createFromController : createDefault) ||
        !getInfo || !getService ||
        (publish && !setDescription) || (cycleBus && !goOffAndOnBus)) {
        result = MAC2JBUSBMissingAPI;
        goto close_handle;
    }

    ControllerRef controller = NULL;
    if (createController(kCFAllocatorDefault, &controller) != kIOReturnSuccess || !controller) {
        result = MAC2JBUSBControllerUnavailable;
        goto close_handle;
    }
    io_service_t service = getService(controller);
    uint64_t actualRegistryID = 0;
    if (service == IO_OBJECT_NULL ||
        IORegistryEntryGetRegistryEntryID(service, &actualRegistryID) != kIOReturnSuccess ||
        actualRegistryID != expectedControllerRegistryID) {
        result = MAC2JBUSBWrongController;
        goto release_controller;
    }

    DescriptionRef description = cloneCurrent
        ? createFromController(kCFAllocatorDefault, controller)
        : createDefault(kCFAllocatorDefault, controller);
    if (!description) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_controller;
    }
    CFMutableDictionaryRef info = getInfo(description);
    CFDictionaryRef expected = (CFDictionaryRef)decoded;
    if (!info || CFGetTypeID(info) != CFDictionaryGetTypeID()) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_description;
    }
    if (cloneCurrent) {
        CFIndex count = CFDictionaryGetCount(info);
        if (count != 16 && count != 17) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        CFTypeRef flag = CFDictionaryGetValue(info, CFSTR("AllowMultipleCreates"));
        if ((count == 16 && flag) || (count == 17 && flag != kCFBooleanTrue)) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        const void *keys[17];
        const void *values[17];
        CFDictionaryGetKeysAndValues(info, keys, values);
        for (CFIndex index = 0; index < count; index++) {
            if (CFEqual(keys[index], CFSTR("AllowMultipleCreates"))) continue;
            CFTypeRef saved = CFDictionaryGetValue(expected, keys[index]);
            if (!saved ||
                (!CFEqual(values[index], saved) &&
                 !CFEqual(keys[index], CFSTR("BcdUSBVersion")) &&
                 !CFEqual(keys[index], CFSTR("MPS0")))) {
                result = MAC2JBUSBDescriptionMismatch;
                goto release_description;
            }
        }
        if (count - (flag ? 1 : 0) != CFDictionaryGetCount(expected)) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        CFTypeRef bcd = CFDictionaryGetValue(expected, CFSTR("BcdUSBVersion"));
        CFTypeRef mps = CFDictionaryGetValue(expected, CFSTR("MPS0"));
        if (!bcd || !mps) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        // The failed trials changed these two registry values. Change only
        // the clone's mutable dictionary; do not touch live IOKit state here.
        CFDictionarySetValue(info, CFSTR("BcdUSBVersion"), bcd);
        CFDictionarySetValue(info, CFSTR("MPS0"), mps);
        CFDictionaryRemoveValue(info, CFSTR("AllowMultipleCreates"));
    } else {
        if (CFDictionaryGetCount(info) != 12 ||
            !contains_equal_values(info, expected)) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        const CFStringRef missing[] = {
            CFSTR("uniqueDeviceID"), CFSTR("serialNumber"),
            CFSTR("BcdUSBVersion"), CFSTR("MPS0")
        };
        for (size_t index = 0; index < sizeof(missing) / sizeof(missing[0]); index++) {
            const void *value = CFDictionaryGetValue(expected, missing[index]);
            if (!value || CFDictionaryContainsKey(info, missing[index])) {
                result = MAC2JBUSBDescriptionMismatch;
                goto release_description;
            }
            CFDictionarySetValue(info, missing[index], value);
        }
    }
    if (!CFEqual(info, expected)) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_description;
    }
    result = MAC2JBUSBSuccess;
    if (publish) {
        CFDictionarySetValue(info, CFSTR("AllowMultipleCreates"), kCFBooleanTrue);
        IOReturn setStatus = setDescription(controller, description);
        if (setReturn) *setReturn = setStatus;
        if (setStatus != kIOReturnSuccess) {
            result = MAC2JBUSBSetFailed;
            goto release_description;
        }
        if (cycleBus) {
            IOReturn busStatus = goOffAndOnBus(controller, 1000);
            if (busReturn) *busReturn = busStatus;
            if (busStatus != kIOReturnSuccess) result = MAC2JBUSBBusCycleFailed;
        }
    }

release_description:
    CFRelease(description);
release_controller:
    CFRelease(controller);
close_handle:
    dlclose(handle);
finished:
    CFRelease(decoded);
    return result;
}

MAC2JBUSBResult MAC2JBUSBReconstructOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID, bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
) {
    return reconstruct_or_clone(livePlist, livePlistLength,
                                expectedControllerRegistryID, publish, cycleBus,
                                false, setReturn, busReturn);
}

MAC2JBUSBResult MAC2JBUSBCloneOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID, bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
) {
    return reconstruct_or_clone(livePlist, livePlistLength,
                                expectedControllerRegistryID, publish, cycleBus,
                                true, setReturn, busReturn);
}
