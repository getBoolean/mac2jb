#include "USBRestoreControllerShim.h"
#include "USBFunctionName.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <stdio.h>
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

// Append one function name last in the given configuration's Interfaces array
// and change nothing else. Last position keeps every existing interface number
// stable. The name must not already appear in any configuration.
static bool append_function(CFMutableDictionaryRef info, CFStringRef name,
                            int32_t configurationNumber) {
    if (!info || !name || configurationNumber < 1 || configurationNumber > 255) return false;
    CFIndex target = (CFIndex)configurationNumber - 1;
    CFTypeRef value = CFDictionaryGetValue(info, CFSTR("ConfigurationDescriptors"));
    if (!value || CFGetTypeID(value) != CFArrayGetTypeID()) return false;
    CFArrayRef configurations = (CFArrayRef)value;
    CFIndex count = CFArrayGetCount(configurations);
    if (target >= count) return false;
    for (CFIndex index = 0; index < count; index++) {
        CFTypeRef entry = CFArrayGetValueAtIndex(configurations, index);
        if (!entry || CFGetTypeID(entry) != CFDictionaryGetTypeID()) return false;
        CFTypeRef names = CFDictionaryGetValue((CFDictionaryRef)entry, CFSTR("Interfaces"));
        // Only the configuration being appended to must carry an interface
        // list. Whether every stock configuration carries one is unknown, and
        // refusing the whole request over an unrelated configuration's shape
        // would read as "this device rejects the function" on the first trial.
        if (!names && index != target) continue;
        if (!names || CFGetTypeID(names) != CFArrayGetTypeID()) return false;
        CFIndex nameCount = CFArrayGetCount((CFArrayRef)names);
        for (CFIndex slot = 0; slot < nameCount; slot++) {
            CFTypeRef existing = CFArrayGetValueAtIndex((CFArrayRef)names, slot);
            if (!existing || CFGetTypeID(existing) != CFStringGetTypeID()) return false;
            if (CFEqual(existing, name)) return false;
        }
    }
    CFDictionaryRef configuration = (CFDictionaryRef)CFArrayGetValueAtIndex(configurations, target);
    CFArrayRef names = (CFArrayRef)CFDictionaryGetValue(configuration, CFSTR("Interfaces"));
    // _IOUSBDeviceDescriptionGetInfo may hand back immutable containers, so
    // copy the target configuration and its interface array before mutating.
    CFMutableArrayRef newNames = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, names);
    CFMutableDictionaryRef newConfiguration = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, configuration);
    CFMutableArrayRef newConfigurations = CFArrayCreateMutableCopy(
        kCFAllocatorDefault, 0, configurations);
    bool appended = newNames && newConfiguration && newConfigurations;
    if (appended) {
        CFArrayAppendValue(newNames, name);
        CFDictionarySetValue(newConfiguration, CFSTR("Interfaces"), newNames);
        CFArraySetValueAtIndex(newConfigurations, target, newConfiguration);
        CFDictionarySetValue(info, CFSTR("ConfigurationDescriptors"), newConfigurations);
    }
    if (newNames) CFRelease(newNames);
    if (newConfiguration) CFRelease(newConfiguration);
    if (newConfigurations) CFRelease(newConfigurations);
    return appended;
}

// Undo one append: drop the given name from the given configuration's
// Interfaces array and change nothing else. The name must be the last element,
// which is where append_function put it. Refusing any other position is what
// keeps a restore from quietly dropping an interface the stock device had.
static bool remove_appended_function(CFMutableDictionaryRef info, CFStringRef name,
                                     int32_t configurationNumber) {
    if (!info || !name || configurationNumber < 1 || configurationNumber > 255) return false;
    CFIndex target = (CFIndex)configurationNumber - 1;
    CFTypeRef value = CFDictionaryGetValue(info, CFSTR("ConfigurationDescriptors"));
    if (!value || CFGetTypeID(value) != CFArrayGetTypeID()) return false;
    CFArrayRef configurations = (CFArrayRef)value;
    if (target >= CFArrayGetCount(configurations)) return false;
    CFTypeRef entry = CFArrayGetValueAtIndex(configurations, target);
    if (!entry || CFGetTypeID(entry) != CFDictionaryGetTypeID()) return false;
    CFDictionaryRef configuration = (CFDictionaryRef)entry;
    CFTypeRef names = CFDictionaryGetValue(configuration, CFSTR("Interfaces"));
    if (!names || CFGetTypeID(names) != CFArrayGetTypeID()) return false;
    CFIndex nameCount = CFArrayGetCount((CFArrayRef)names);
    if (nameCount < 1) return false;
    CFTypeRef last = CFArrayGetValueAtIndex((CFArrayRef)names, nameCount - 1);
    if (!last || CFGetTypeID(last) != CFStringGetTypeID() || !CFEqual(last, name)) return false;
    // Same immutable-container handling as append_function.
    CFMutableArrayRef newNames = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0,
                                                          (CFArrayRef)names);
    CFMutableDictionaryRef newConfiguration = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, configuration);
    CFMutableArrayRef newConfigurations = CFArrayCreateMutableCopy(
        kCFAllocatorDefault, 0, configurations);
    bool removed = newNames && newConfiguration && newConfigurations;
    if (removed) {
        CFArrayRemoveValueAtIndex(newNames, nameCount - 1);
        CFDictionarySetValue(newConfiguration, CFSTR("Interfaces"), newNames);
        CFArraySetValueAtIndex(newConfigurations, target, newConfiguration);
        CFDictionarySetValue(info, CFSTR("ConfigurationDescriptors"), newConfigurations);
    }
    if (newNames) CFRelease(newNames);
    if (newConfiguration) CFRelease(newConfiguration);
    if (newConfigurations) CFRelease(newConfigurations);
    return removed;
}

// Replace the given configuration's Interfaces array with exactly one name:
// the appended function alone, every stock function removed from that
// configuration. This is the exclusive-HID shape (parent plan U4): the host
// selects this configuration and sees a single-interface keyboard, which a
// controller can bring on bus without the composite's extra interface and
// endpoint. Only the one configuration is touched; the device-level scalars
// and every other configuration are left exactly as the stock description had
// them, and the journaled original stays the restore target, so restoring the
// stripped stock functions is a plain republish of the original. The name must
// not already appear in any configuration, as for append_function.
static bool set_sole_function(CFMutableDictionaryRef info, CFStringRef name,
                              int32_t configurationNumber) {
    if (!info || !name || configurationNumber < 1 || configurationNumber > 255) return false;
    CFIndex target = (CFIndex)configurationNumber - 1;
    CFTypeRef value = CFDictionaryGetValue(info, CFSTR("ConfigurationDescriptors"));
    if (!value || CFGetTypeID(value) != CFArrayGetTypeID()) return false;
    CFArrayRef configurations = (CFArrayRef)value;
    CFIndex count = CFArrayGetCount(configurations);
    if (target >= count) return false;
    // Same whole-array validation and name-collision check as append_function:
    // the target configuration must carry an interface list, and the name must
    // not already be present in any configuration.
    for (CFIndex index = 0; index < count; index++) {
        CFTypeRef entry = CFArrayGetValueAtIndex(configurations, index);
        if (!entry || CFGetTypeID(entry) != CFDictionaryGetTypeID()) return false;
        CFTypeRef names = CFDictionaryGetValue((CFDictionaryRef)entry, CFSTR("Interfaces"));
        if (!names && index != target) continue;
        if (!names || CFGetTypeID(names) != CFArrayGetTypeID()) return false;
        CFIndex nameCount = CFArrayGetCount((CFArrayRef)names);
        for (CFIndex slot = 0; slot < nameCount; slot++) {
            CFTypeRef existing = CFArrayGetValueAtIndex((CFArrayRef)names, slot);
            if (!existing || CFGetTypeID(existing) != CFStringGetTypeID()) return false;
            if (CFEqual(existing, name)) return false;
        }
    }
    CFDictionaryRef configuration = (CFDictionaryRef)CFArrayGetValueAtIndex(configurations, target);
    CFMutableArrayRef soleName = CFArrayCreateMutable(kCFAllocatorDefault, 1,
                                                      &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef newConfiguration = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, configuration);
    CFMutableArrayRef newConfigurations = CFArrayCreateMutableCopy(
        kCFAllocatorDefault, 0, configurations);
    bool set = soleName && newConfiguration && newConfigurations;
    if (set) {
        CFArrayAppendValue(soleName, name);
        CFDictionarySetValue(newConfiguration, CFSTR("Interfaces"), soleName);
        CFArraySetValueAtIndex(newConfigurations, target, newConfiguration);
        CFDictionarySetValue(info, CFSTR("ConfigurationDescriptors"), newConfigurations);
    }
    if (soleName) CFRelease(soleName);
    if (newConfiguration) CFRelease(newConfiguration);
    if (newConfigurations) CFRelease(newConfigurations);
    return set;
}

// Shared body of the pure entry points: decode, apply the one edit, encode.
// The pure path and the clone path go through these same edit helpers, so
// there is one implementation of each edit. `mode` selects which.
enum mac2jb_edit_mode { MAC2JB_EDIT_APPEND = 0, MAC2JB_EDIT_REMOVE = 1, MAC2JB_EDIT_SOLE = 2 };

static MAC2JBUSBResult edit_description_data(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber, int mode,
    uint8_t **out, size_t *outLength
) {
    if (!out || !outLength) return MAC2JBUSBInvalidInput;
    *out = NULL;
    *outLength = 0;
    if (!plist || plistLength < 8 || plistLength > 1024 * 1024) return MAC2JBUSBInvalidInput;
    if (!mac2jb_usb_function_name_is_legal(functionName)) return MAC2JBUSBFunctionRejected;
    MAC2JBUSBResult result = MAC2JBUSBInvalidInput;
    CFDataRef input = CFDataCreate(kCFAllocatorDefault, plist, (CFIndex)plistLength);
    if (!input) return result;
    CFPropertyListRef decoded = CFPropertyListCreateWithData(
        kCFAllocatorDefault, input, kCFPropertyListMutableContainers, NULL, NULL);
    CFRelease(input);
    if (!decoded) return result;
    if (CFGetTypeID(decoded) != CFDictionaryGetTypeID()) goto finished;
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, functionName,
                                                 kCFStringEncodingUTF8);
    if (!name) goto finished;
    bool edited = mode == MAC2JB_EDIT_APPEND
        ? append_function((CFMutableDictionaryRef)decoded, name, configurationNumber)
        : mode == MAC2JB_EDIT_SOLE
        ? set_sole_function((CFMutableDictionaryRef)decoded, name, configurationNumber)
        : remove_appended_function((CFMutableDictionaryRef)decoded, name,
                                   configurationNumber);
    if (!edited) {
        result = MAC2JBUSBFunctionRejected;
        goto release_name;
    }
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, decoded,
                                              kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    if (!data) { result = MAC2JBUSBDescriptionMismatch; goto release_name; }
    CFIndex size = CFDataGetLength(data);
    uint8_t *copy = size > 0 ? malloc((size_t)size) : NULL;
    if (!copy) { result = MAC2JBUSBInvalidInput; goto release_data; }
    memcpy(copy, CFDataGetBytePtr(data), (size_t)size);
    *out = copy;
    *outLength = (size_t)size;
    result = MAC2JBUSBSuccess;
release_data:
    CFRelease(data);
release_name:
    CFRelease(name);
finished:
    CFRelease(decoded);
    return result;
}

MAC2JBUSBResult MAC2JBUSBAppendFunctionToDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber,
    uint8_t **out, size_t *outLength
) {
    return edit_description_data(plist, plistLength, functionName,
                                 configurationNumber, MAC2JB_EDIT_APPEND, out, outLength);
}

MAC2JBUSBResult MAC2JBUSBRemoveFunctionFromDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber,
    uint8_t **out, size_t *outLength
) {
    return edit_description_data(plist, plistLength, functionName,
                                 configurationNumber, MAC2JB_EDIT_REMOVE, out, outLength);
}

MAC2JBUSBResult MAC2JBUSBSetSoleFunctionInDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber,
    uint8_t **out, size_t *outLength
) {
    return edit_description_data(plist, plistLength, functionName,
                                 configurationNumber, MAC2JB_EDIT_SOLE, out, outLength);
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

MAC2JBUSBResult MAC2JBUSBCopySelectedConfiguration(
    uint64_t expectedControllerRegistryID, int32_t *configurationNumber
) {
    if (!configurationNumber || expectedControllerRegistryID == 0) return MAC2JBUSBInvalidInput;
    *configurationNumber = 0;
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
    // Copy only CurrentState: the whole property dictionary carries the
    // description and every configuration descriptor, and this runs inside the
    // broker, which launchd holds to a jetsam memory limit.
    CFTypeRef current = IORegistryEntryCreateCFProperty(
        service, CFSTR("CurrentState"), kCFAllocatorDefault, 0);
    if (!current) goto release_service;
    if (CFGetTypeID(current) != CFDictionaryGetTypeID()) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_current;
    }
    CFTypeRef configuration = CFDictionaryGetValue((CFDictionaryRef)current,
                                                   CFSTR("SelectedConfiguration"));
    int32_t selected = 0;
    if (!configuration || CFGetTypeID(configuration) != CFNumberGetTypeID() ||
        !CFNumberGetValue((CFNumberRef)configuration, kCFNumberSInt32Type, &selected) ||
        selected < 1 || selected > 255) {
        result = MAC2JBUSBDescriptionMismatch;
        goto release_current;
    }
    *configurationNumber = selected;
    result = MAC2JBUSBSuccess;
release_current:
    CFRelease(current);
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
    // Stock count comes from the device profile; the journal and Swift side
    // enforce it. Here only bound it (stock or stock + AllowMultipleCreates).
    if (fieldCount < 4 || fieldCount > 65) {
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

MAC2JBUSBResult MAC2JBUSBCopyUnservedFunctions(
    uint64_t expectedControllerRegistryID, char *names, size_t capacity
) {
    if (!names || capacity < 2 || expectedControllerRegistryID == 0) return MAC2JBUSBInvalidInput;
    names[0] = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceController");
    if (!matching) return MAC2JBUSBControllerUnavailable;
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != kIOReturnSuccess)
        return MAC2JBUSBControllerUnavailable;
    MAC2JBUSBResult result = MAC2JBUSBControllerUnavailable;
    io_service_t service = IOIteratorNext(iterator);
    io_service_t extra = service ? IOIteratorNext(iterator) : IO_OBJECT_NULL;
    IOObjectRelease(iterator);
    if (!service) return result;
    if (extra) {
        IOObjectRelease(extra);
        IOObjectRelease(service);
        return result;
    }
    uint64_t registryID = 0;
    if (IORegistryEntryGetRegistryEntryID(service, &registryID) != kIOReturnSuccess ||
        registryID != expectedControllerRegistryID) {
        IOObjectRelease(service);
        return MAC2JBUSBWrongController;
    }
    io_iterator_t children = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(service, kIOServicePlane, &children) != kIOReturnSuccess) {
        IOObjectRelease(service);
        return result;
    }
    size_t used = 0;
    result = MAC2JBUSBSuccess;
    io_registry_entry_t child;
    while ((child = IOIteratorNext(children))) {
        if (IOObjectConformsTo(child, "IOUSBDeviceInterface")) {
            io_iterator_t clients = IO_OBJECT_NULL;
            bool served = false;
            if (IORegistryEntryGetChildIterator(child, kIOServicePlane, &clients) == kIOReturnSuccess) {
                io_registry_entry_t client = IOIteratorNext(clients);
                served = client != IO_OBJECT_NULL;
                if (client) IOObjectRelease(client);
                IOObjectRelease(clients);
            }
            if (!served) {
                char function[96] = {0};
                CFTypeRef value = IORegistryEntryCreateCFProperty(
                    child, CFSTR("USBDeviceFunction"), kCFAllocatorDefault, 0);
                if (value && CFGetTypeID(value) == CFStringGetTypeID())
                    CFStringGetCString((CFStringRef)value, function, sizeof(function),
                                       kCFStringEncodingUTF8);
                if (value) CFRelease(value);
                size_t length = strlen(function);
                if (length == 0 || used + length + 2 > capacity) {
                    result = MAC2JBUSBDescriptionMismatch;
                } else {
                    if (used) names[used++] = ',';
                    memcpy(names + used, function, length);
                    used += length;
                    names[used] = 0;
                }
            }
        }
        IOObjectRelease(child);
    }
    IOObjectRelease(children);
    IOObjectRelease(service);
    return result;
}

static void copy_string_property(io_registry_entry_t entry, CFStringRef key, char *out, size_t size) {
    out[0] = 0;
    CFTypeRef value = IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0);
    if (value && CFGetTypeID(value) == CFStringGetTypeID())
        CFStringGetCString((CFStringRef)value, out, (CFIndex)size, kCFStringEncodingUTF8);
    if (value) CFRelease(value);
    for (char *c = out; *c; c++) if (*c == '\t' || *c == '\n') *c = ' ';
}

static bool append_line(char *lines, size_t capacity, size_t *used,
                        const char *a, const char *b, const char *c) {
    int n = snprintf(lines + *used, capacity - *used, "%s\t%s\t%s\n", a, b, c);
    if (n < 0 || (size_t)n >= capacity - *used) return false;
    *used += (size_t)n;
    return true;
}

MAC2JBUSBResult MAC2JBUSBCopyFunctionClients(
    uint64_t expectedControllerRegistryID, char *lines, size_t capacity
) {
    if (!lines || capacity < 2 || expectedControllerRegistryID == 0) return MAC2JBUSBInvalidInput;
    lines[0] = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceController");
    if (!matching) return MAC2JBUSBControllerUnavailable;
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != kIOReturnSuccess)
        return MAC2JBUSBControllerUnavailable;
    io_service_t service = IOIteratorNext(iterator);
    io_service_t extra = service ? IOIteratorNext(iterator) : IO_OBJECT_NULL;
    IOObjectRelease(iterator);
    if (!service) return MAC2JBUSBControllerUnavailable;
    if (extra) {
        IOObjectRelease(extra);
        IOObjectRelease(service);
        return MAC2JBUSBControllerUnavailable;
    }
    uint64_t registryID = 0;
    if (IORegistryEntryGetRegistryEntryID(service, &registryID) != kIOReturnSuccess ||
        registryID != expectedControllerRegistryID) {
        IOObjectRelease(service);
        return MAC2JBUSBWrongController;
    }
    io_iterator_t children = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(service, kIOServicePlane, &children) != kIOReturnSuccess) {
        IOObjectRelease(service);
        return MAC2JBUSBControllerUnavailable;
    }
    MAC2JBUSBResult result = MAC2JBUSBSuccess;
    size_t used = 0;
    io_registry_entry_t nub;
    while ((nub = IOIteratorNext(children))) {
        if (IOObjectConformsTo(nub, "IOUSBDeviceInterface")) {
            char function[96];
            copy_string_property(nub, CFSTR("USBDeviceFunction"), function, sizeof(function));
            io_iterator_t clients = IO_OBJECT_NULL;
            bool any = false;
            if (function[0] &&
                IORegistryEntryGetChildIterator(nub, kIOServicePlane, &clients) == kIOReturnSuccess) {
                io_registry_entry_t client;
                while ((client = IOIteratorNext(clients))) {
                    io_name_t cls;
                    char creator[128];
                    if (IOObjectGetClass(client, cls) != kIOReturnSuccess) cls[0] = 0;
                    copy_string_property(client, CFSTR("IOUserClientCreator"), creator, sizeof(creator));
                    if (!append_line(lines, capacity, &used, function, cls, creator))
                        result = MAC2JBUSBDescriptionMismatch;
                    any = true;
                    IOObjectRelease(client);
                }
                IOObjectRelease(clients);
            }
            if (function[0] && !any && !append_line(lines, capacity, &used, function, "", ""))
                result = MAC2JBUSBDescriptionMismatch;
        }
        IOObjectRelease(nub);
    }
    IOObjectRelease(children);
    IOObjectRelease(service);
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
    const char *functionName,
    int32_t configurationNumber,
    const char *expectedFunctionName,
    int32_t expectedConfigurationNumber,
    int32_t *setReturn,
    int32_t *busReturn
) {
    if (setReturn) *setReturn = kIOReturnNotReady;
    if (busReturn) *busReturn = kIOReturnNotReady;
    if (!livePlist || livePlistLength < 8 || livePlistLength > 1024 * 1024 ||
        expectedControllerRegistryID == 0 || (cycleBus && !publish)) {
        return MAC2JBUSBInvalidInput;
    }
    // Refuse a malformed added name before any controller user client opens.
    if (functionName && !mac2jb_usb_function_name_is_legal(functionName)) return MAC2JBUSBFunctionRejected;
    if (expectedFunctionName && !mac2jb_usb_function_name_is_legal(expectedFunctionName))
        return MAC2JBUSBFunctionRejected;

    MAC2JBUSBResult result = MAC2JBUSBInvalidInput;
    CFDataRef input = CFDataCreate(kCFAllocatorDefault, livePlist, (CFIndex)livePlistLength);
    if (!input) return result;
    CFErrorRef error = NULL;
    CFPropertyListRef decoded = CFPropertyListCreateWithData(
        kCFAllocatorDefault, input, kCFPropertyListImmutable, NULL, &error);
    CFRelease(input);
    if (error) CFRelease(error);
    if (!decoded) return result;
    // The journaled original defines the stock field count for this device.
    if (CFGetTypeID(decoded) != CFDictionaryGetTypeID()) goto finished;
    CFIndex originalCount = CFDictionaryGetCount((CFDictionaryRef)decoded);
    if (originalCount < 4 || originalCount > 64) goto finished;

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
        // A successful additive publication leaves the appended function on the
        // live description, so a clone of it can never equal the journaled
        // original. A restore therefore states the one function it appended and
        // exactly that name comes off, last in that configuration, before the
        // comparison below. Without this an additive publication would be
        // unrestorable, which reads on the device like the gadget stack
        // refusing to come back rather than this shim refusing to ask.
        if (expectedFunctionName) {
            CFStringRef appendedName = CFStringCreateWithCString(
                kCFAllocatorDefault, expectedFunctionName, kCFStringEncodingUTF8);
            bool removed = appendedName && remove_appended_function(
                info, appendedName, expectedConfigurationNumber);
            if (appendedName) CFRelease(appendedName);
            if (!removed) {
                result = MAC2JBUSBFunctionRejected;
                goto release_description;
            }
        }
        CFIndex count = CFDictionaryGetCount(info);
        if (count != originalCount && count != originalCount + 1) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        CFTypeRef flag = CFDictionaryGetValue(info, CFSTR("AllowMultipleCreates"));
        if ((count == originalCount && flag) ||
            (count == originalCount + 1 && flag != kCFBooleanTrue)) {
            result = MAC2JBUSBDescriptionMismatch;
            goto release_description;
        }
        const void *keys[65];
        const void *values[65];
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
    // Only now, with the clone proven byte-equal to the journaled original,
    // may the one added function go in: an additive publication must still
    // start from exactly what restore will put back.
    if (functionName) {
        CFStringRef added = CFStringCreateWithCString(kCFAllocatorDefault, functionName,
                                                      kCFStringEncodingUTF8);
        bool appended = added && append_function(info, added, configurationNumber);
        if (added) CFRelease(added);
        if (!appended) {
            result = MAC2JBUSBFunctionRejected;
            goto release_description;
        }
    }
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

MAC2JBUSBResult MAC2JBUSBCycleControllerBus(
    uint64_t expectedControllerRegistryID, int32_t *busReturn
) {
    if (busReturn) *busReturn = kIOReturnNotReady;
    if (!busReturn || expectedControllerRegistryID == 0) return MAC2JBUSBInvalidInput;
    // Same dynamic resolution as the publication path: none of these symbols is
    // declared in any SDK header, so a build cannot depend on them existing.
    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    if (!handle) return MAC2JBUSBMissingAPI;
    MAC2JBUSBResult result = MAC2JBUSBMissingAPI;
    CreateController createController = (CreateController)dlsym(handle, "IOUSBDeviceControllerCreate");
    GetService getService = (GetService)dlsym(handle, "IOUSBDeviceControllerGetService");
    GoOffAndOnBus goOffAndOnBus = (GoOffAndOnBus)dlsym(handle, "IOUSBDeviceControllerGoOffAndOnBus");
    if (!createController || !getService || !goOffAndOnBus) goto close_handle;
    ControllerRef controller = NULL;
    if (createController(kCFAllocatorDefault, &controller) != kIOReturnSuccess || !controller) {
        result = MAC2JBUSBControllerUnavailable;
        goto close_handle;
    }
    // The registry id is checked exactly as every other entry checks it: the
    // sole controller this trial journaled, or nothing is touched.
    io_service_t service = getService(controller);
    uint64_t actualRegistryID = 0;
    if (service == IO_OBJECT_NULL ||
        IORegistryEntryGetRegistryEntryID(service, &actualRegistryID) != kIOReturnSuccess ||
        actualRegistryID != expectedControllerRegistryID) {
        result = MAC2JBUSBWrongController;
        goto release_controller;
    }
    // Same bound the publication path passes. Recorded verbatim: a nonzero
    // return is the observation, not something to interpret or retry.
    IOReturn busStatus = goOffAndOnBus(controller, 1000);
    *busReturn = busStatus;
    result = busStatus == kIOReturnSuccess ? MAC2JBUSBSuccess : MAC2JBUSBBusCycleFailed;
release_controller:
    CFRelease(controller);
close_handle:
    dlclose(handle);
    return result;
}

MAC2JBUSBResult MAC2JBUSBReconstructOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID, bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
) {
    return reconstruct_or_clone(livePlist, livePlistLength,
                                expectedControllerRegistryID, publish, cycleBus,
                                false, NULL, 0, NULL, 0, setReturn, busReturn);
}

MAC2JBUSBResult MAC2JBUSBCloneOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    const char *expectedFunctionName, int32_t expectedConfigurationNumber,
    bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
) {
    return reconstruct_or_clone(livePlist, livePlistLength,
                                expectedControllerRegistryID, publish, cycleBus,
                                true, NULL, 0,
                                expectedFunctionName, expectedConfigurationNumber,
                                setReturn, busReturn);
}

MAC2JBUSBResult MAC2JBUSBCloneAppendFunctionOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    const char *functionName, int32_t configurationNumber,
    bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
) {
    if (!functionName) return MAC2JBUSBInvalidInput;
    return reconstruct_or_clone(livePlist, livePlistLength,
                                expectedControllerRegistryID, publish, cycleBus,
                                true, functionName, configurationNumber,
                                NULL, 0, setReturn, busReturn);
}

MAC2JBUSBResult MAC2JBUSBCloneRepublishAppendedFunctionOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    const char *functionName, int32_t configurationNumber,
    bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
) {
    if (!functionName) return MAC2JBUSBInvalidInput;
    // The healer meets two live shapes and must handle both, because an earlier
    // round may already have restored the stock description: strip-then-append
    // when the name is still there, plain append when it is not.
    //
    // Trying the stripping form first is safe because every refusal it can
    // raise - including the name not being last in that configuration - is
    // decided while comparing the in-process clone, before any SetDescription.
    // So a rejected first attempt has written neither the controller nor the
    // bus, and the retry is the only call that publishes.
    MAC2JBUSBResult result = reconstruct_or_clone(
        livePlist, livePlistLength, expectedControllerRegistryID, publish,
        cycleBus, true, functionName, configurationNumber,
        functionName, configurationNumber, setReturn, busReturn);
    if (result != MAC2JBUSBFunctionRejected) return result;
    return reconstruct_or_clone(livePlist, livePlistLength,
                                expectedControllerRegistryID, publish, cycleBus,
                                true, functionName, configurationNumber,
                                NULL, 0, setReturn, busReturn);
}
