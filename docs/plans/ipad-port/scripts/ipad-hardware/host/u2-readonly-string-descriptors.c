/*
 * Mac-only external USB string-descriptor reader for the one connected iPad.
 *
 * Apple's IOUSBLib.h documents DeviceRequestTO as usable without opening the
 * device. Every request here is standard device-to-host GET_DESCRIPTOR(STRING)
 * with a 500 ms no-data and 1000 ms completion timeout. This executable does
 * not call USBDeviceOpen, USBDeviceOpenSeize, SetConfiguration, ResetDevice,
 * or any write request. It never edits an iPad or Mac file. Successful stdout
 * is private binary evidence; the host wrapper prints only counts and hashes.
 * `--languages` makes one descriptor-zero request. `--strings` reads only
 * nonzero indices referenced by the five current configuration streams.
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

enum { MAX_CONFIGS = 5, MAX_CONFIG_BYTES = 16384, MAX_STRINGS = 64 };

struct StringValue {
    uint8_t bytes[255];
    uint8_t length;
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

static bool get_string(IOUSBDeviceInterface197 **device, uint8_t index,
                       uint16_t language, struct StringValue *output) {
    memset(output, 0, sizeof(*output));
    IOUSBDevRequestTO request = {
        .bmRequestType = 0x80, /* IN | standard | device */
        .bRequest = 6,        /* GET_DESCRIPTOR */
        .wValue = (uint16_t)(0x0300u | index), /* STRING descriptor */
        .wIndex = language,
        .wLength = sizeof(output->bytes),
        .pData = output->bytes,
        .noDataTimeout = 500,
        .completionTimeout = 1000,
    };
    if ((*device)->DeviceRequestTO(device, &request) != kIOReturnSuccess ||
        request.wLenDone < 2 || request.wLenDone > sizeof(output->bytes) ||
        output->bytes[1] != 3 || output->bytes[0] != request.wLenDone ||
        (request.wLenDone & 1) != 0) return false;
    output->length = (uint8_t)request.wLenDone;
    return true;
}

static bool add_index(bool indices[256], uint8_t index, unsigned *count) {
    if (!index || indices[index]) return true;
    if (*count >= MAX_STRINGS) return false;
    indices[index] = true;
    (*count)++;
    return true;
}

static bool scan_config(const uint8_t *raw, uint16_t length,
                        bool indices[256], unsigned *count) {
    if (length < 9 || raw[0] < 9 || raw[1] != 2 ||
        ((uint16_t)raw[2] | ((uint16_t)raw[3] << 8)) != length ||
        !add_index(indices, raw[6], count)) return false;
    uint16_t offset = 0;
    while (offset < length) {
        uint8_t size = raw[offset];
        if (size < 2 || size > length - offset) return false;
        const uint8_t *item = raw + offset;
        if (item[1] == 4 && size >= 9 &&
            !add_index(indices, item[8], count)) return false;
        if (item[1] == 11 && size >= 8 &&
            !add_index(indices, item[7], count)) return false;
        if (item[1] == 0x24 && size >= 4 && item[2] == 0x0f &&
            !add_index(indices, item[3], count)) return false;
        offset += size;
    }
    return offset == length;
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "--languages") != 0 &&
                      strcmp(argv[1], "--strings") != 0)) return 2;
    const bool languages_only = strcmp(argv[1], "--languages") == 0;
    int result = 1;
    io_iterator_t iterator = IO_OBJECT_NULL;
    io_service_t target = IO_OBJECT_NULL;
    IOCFPlugInInterface **plugin = NULL;
    IOUSBDeviceInterface197 **device = NULL;
    struct StringValue language_list;
    struct StringValue *strings = NULL;
    bool indices[256] = {false};
    unsigned index_count = 0;
    uint16_t language = 0;

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
                                          &score) != kIOReturnSuccess || !plugin) goto done;
    if ((*plugin)->QueryInterface(plugin,
            CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID197),
            (LPVOID *)&device) != S_OK || !device) goto done;
    if (!get_string(device, 0, 0, &language_list) || language_list.length < 4)
        goto done;
    language = (uint16_t)language_list.bytes[2] |
               ((uint16_t)language_list.bytes[3] << 8);
    if (!language) goto done;
    if (languages_only) {
        const uint8_t magic[8] = {'U','2','L','A','N','G','1',0};
        if (fwrite(magic, 1, 8, stdout) != 8 ||
            fwrite(language_list.bytes, 1, language_list.length, stdout)
                != language_list.length) goto done;
        result = fflush(stdout) == 0 ? 0 : 1;
        goto done;
    }
    uint8_t count = 0;
    if ((*device)->GetNumberOfConfigurations(device, &count) != kIOReturnSuccess ||
        count != MAX_CONFIGS) goto done;
    for (uint8_t index = 0; index < count; index++) {
        IOUSBConfigurationDescriptorPtr descriptor = NULL;
        if ((*device)->GetConfigurationDescriptorPtr(device, index, &descriptor)
                != kIOReturnSuccess || !descriptor) goto done;
        uint16_t length = OSSwapLittleToHostInt16(descriptor->wTotalLength);
        if (length > MAX_CONFIG_BYTES ||
            !scan_config((const uint8_t *)descriptor, length, indices,
                         &index_count)) goto done;
    }
    if (!index_count) goto done;
    strings = calloc(256, sizeof(*strings));
    if (!strings) goto done;
    for (unsigned index = 1; index < 256; index++) {
        if (indices[index] && !get_string(device, (uint8_t)index, language,
                                          &strings[index])) goto done;
    }
    const uint8_t magic[8] = {'U','2','S','T','R','1',0,0};
    const uint8_t header[3] = {(uint8_t)(language & 0xff),
                               (uint8_t)(language >> 8),
                               (uint8_t)index_count};
    if (fwrite(magic, 1, 8, stdout) != 8 ||
        fwrite(header, 1, 3, stdout) != 3) goto done;
    for (unsigned index = 1; index < 256; index++) {
        if (!indices[index]) continue;
        uint8_t pair[2] = {(uint8_t)index, strings[index].length};
        if (fwrite(pair, 1, 2, stdout) != 2 ||
            fwrite(strings[index].bytes, 1, strings[index].length, stdout)
                != strings[index].length) goto done;
    }
    result = fflush(stdout) == 0 ? 0 : 1;
done:
    free(strings);
    if (device) (*device)->Release(device);
    if (plugin) (*plugin)->Release(plugin);
    if (target != IO_OBJECT_NULL) IOObjectRelease(target);
    if (iterator != IO_OBJECT_NULL) IOObjectRelease(iterator);
    return result;
}
