/*
 * Mac-only external USB configuration descriptor capture for the one iPad.
 *
 * Apple's IOUSBLib.h documents GetNumberOfConfigurations and
 * GetConfigurationDescriptorPtr as usable without opening the device. This
 * program obtains a plugin interface, calls only those read-only methods,
 * copies and validates the returned raw descriptor bytes, and releases the
 * interface. It NEVER calls USBDeviceOpen, SetConfiguration, ResetDevice,
 * DeviceRequest, or any mutation method. It makes no iPad file change.
 * Successful stdout is private binary evidence for the host wrapper; no
 * serial string or raw descriptor is printed in ordinary terminal output.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <libkern/OSByteOrder.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_CONFIGS = 8, MAX_CONFIG_BYTES = 16384 };

struct Captured {
    uint8_t *bytes;
    uint16_t length;
};

static bool exact_ipad(io_service_t service) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        service, CFSTR("USB Product Name"), kCFAllocatorDefault, 0);
    if (!value) return false;
    bool match = CFGetTypeID(value) == CFStringGetTypeID() &&
                 CFEqual(value, CFSTR("iPad"));
    CFRelease(value);
    return match;
}

static bool valid_descriptors(const uint8_t *bytes, uint16_t length) {
    if (!bytes || length < 9 || bytes[0] < 9 || bytes[1] != 2) return false;
    uint16_t offset = 0;
    while (offset < length) {
        if (length - offset < 2 || bytes[offset] < 2 ||
            bytes[offset] > length - offset) return false;
        offset += bytes[offset];
    }
    return offset == length;
}

int main(void) {
    int result = 1;
    io_iterator_t iterator = IO_OBJECT_NULL;
    io_service_t target = IO_OBJECT_NULL;
    IOCFPlugInInterface **plugin = NULL;
    IOUSBDeviceInterface **device = NULL;
    struct Captured configs[MAX_CONFIGS] = {0};
    uint8_t count = 0;

    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBHostDevice");
    if (!matching ||
        IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator)
            != kIOReturnSuccess) goto done;
    for (io_service_t service = IOIteratorNext(iterator);
         service != IO_OBJECT_NULL; service = IOIteratorNext(iterator)) {
        if (exact_ipad(service)) {
            if (target != IO_OBJECT_NULL) {
                IOObjectRelease(service);
                goto done;
            }
            target = service;
        } else {
            IOObjectRelease(service);
        }
    }
    if (target == IO_OBJECT_NULL) goto done;
    SInt32 score = 0;
    if (IOCreatePlugInInterfaceForService(target, kIOUSBDeviceUserClientTypeID,
                                          kIOCFPlugInInterfaceID, &plugin,
                                          &score) != kIOReturnSuccess ||
        !plugin) goto done;
    if ((*plugin)->QueryInterface(plugin,
            CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID100),
            (LPVOID *)&device) != S_OK || !device) goto done;
    if ((*device)->GetNumberOfConfigurations(device, &count)
            != kIOReturnSuccess || count < 1 || count > MAX_CONFIGS) goto done;
    for (uint8_t index = 0; index < count; index++) {
        IOUSBConfigurationDescriptorPtr descriptor = NULL;
        if ((*device)->GetConfigurationDescriptorPtr(device, index, &descriptor)
                != kIOReturnSuccess || !descriptor) goto done;
        uint16_t length = OSSwapLittleToHostInt16(descriptor->wTotalLength);
        if (length > MAX_CONFIG_BYTES ||
            !valid_descriptors((const uint8_t *)descriptor, length)) goto done;
        configs[index].bytes = malloc(length);
        if (!configs[index].bytes) goto done;
        memcpy(configs[index].bytes, descriptor, length);
        configs[index].length = length;
    }
    /* Validate everything before emitting a single byte of private evidence. */
    const uint8_t magic[8] = {'U','2','C','F','G','D','1',0};
    if (fwrite(magic, 1, sizeof(magic), stdout) != sizeof(magic) ||
        fwrite(&count, 1, 1, stdout) != 1) goto done;
    for (uint8_t index = 0; index < count; index++) {
        uint8_t length[2] = {
            (uint8_t)(configs[index].length & 0xff),
            (uint8_t)(configs[index].length >> 8)
        };
        if (fwrite(length, 1, 2, stdout) != 2 ||
            fwrite(configs[index].bytes, 1, configs[index].length, stdout)
                != configs[index].length) goto done;
    }
    result = fflush(stdout) == 0 ? 0 : 1;
done:
    for (size_t index = 0; index < MAX_CONFIGS; index++) free(configs[index].bytes);
    if (device) (*device)->Release(device);
    if (plugin) (*plugin)->Release(plugin);
    if (target != IO_OBJECT_NULL) IOObjectRelease(target);
    if (iterator != IO_OBJECT_NULL) IOObjectRelease(iterator);
    return result;
}
