// The device side of ipad2jb: the iPad's USB device controller (private
// IOUSBDeviceController API) and the Keyboard function's
// IOUSBDeviceInterfaceUserClient. Selector numbers and argument shapes follow
// vendor/libusbd/src/plat/macos/impl.c, which drives the same user client on
// macOS; they were confirmed on iPadOS 17.0.

#include "iokit.h"

#include <IOKit/IOKitLib.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

// --- USB device controller --------------------------------------------------

typedef struct __IOUSBDeviceController *ControllerRef;
typedef struct __IOUSBDeviceDescription *DescriptionRef;

static struct {
    ControllerRef controller;
    IOReturn (*create)(CFAllocatorRef, ControllerRef *);
    DescriptionRef (*description_from_controller)(CFAllocatorRef, ControllerRef);
    CFMutableDictionaryRef (*description_info)(DescriptionRef);
    io_service_t (*service)(ControllerRef);
    IOReturn (*set_description)(ControllerRef, DescriptionRef);
} usb;

static CFMutableDictionaryRef usb_live_description(void *context) {
    (void)context;
    DescriptionRef description = usb.description_from_controller(kCFAllocatorDefault, usb.controller);
    if (!description) return NULL;
    CFMutableDictionaryRef copy = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0,
                                                                usb.description_info(description));
    CFRelease(description);
    CFDictionaryRemoveValue(copy, CFSTR("AllowMultipleCreates"));
    return copy;
}

// The controller only accepts a replacement description that carries
// AllowMultipleCreates; this is the one place that adds it.
static bool usb_publish(void *context, CFDictionaryRef info) {
    (void)context;
    DescriptionRef description = usb.description_from_controller(kCFAllocatorDefault, usb.controller);
    if (!description) return false;
    CFMutableDictionaryRef target = usb.description_info(description);
    CFDictionaryRemoveAllValues(target);
    CFIndex count = CFDictionaryGetCount(info);
    const void *keys[count], *values[count];
    CFDictionaryGetKeysAndValues(info, keys, values);
    for (CFIndex i = 0; i < count; i++) CFDictionarySetValue(target, keys[i], values[i]);
    CFDictionarySetValue(target, CFSTR("AllowMultipleCreates"), kCFBooleanTrue);
    IOReturn status = usb.set_description(usb.controller, description);
    CFRelease(description);
    return status == kIOReturnSuccess;
}

static int usb_selected_configuration(void *context) {
    (void)context;
    CFTypeRef state = IORegistryEntryCreateCFProperty(usb.service(usb.controller), CFSTR("CurrentState"),
                                                      kCFAllocatorDefault, 0);
    int selected = 0;
    if (state && CFGetTypeID(state) == CFDictionaryGetTypeID()) {
        CFTypeRef number = CFDictionaryGetValue(state, CFSTR("SelectedConfiguration"));
        if (number && CFGetTypeID(number) == CFNumberGetTypeID())
            CFNumberGetValue(number, kCFNumberIntType, &selected);
    }
    if (state) CFRelease(state);
    return selected;
}

static bool usb_functions_registered(void *context, CFSetRef functions) {
    (void)context;
    CFMutableSetRef missing = CFSetCreateMutableCopy(kCFAllocatorDefault, 0, functions);
    io_iterator_t iterator;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBDeviceInterface"),
                                     &iterator) == kIOReturnSuccess) {
        io_service_t entry;
        while ((entry = IOIteratorNext(iterator))) {
            CFTypeRef name = IORegistryEntryCreateCFProperty(entry, CFSTR("USBDeviceFunction"),
                                                             kCFAllocatorDefault, 0);
            if (name) { CFSetRemoveValue(missing, name); CFRelease(name); }
            IOObjectRelease(entry);
        }
        IOObjectRelease(iterator);
    }
    bool complete = CFSetGetCount(missing) == 0;
    CFRelease(missing);
    return complete;
}

bool ipad2jb_iokit_usb(ipad2jb_usb *out) {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!iokit) return false;
    usb.create = dlsym(iokit, "IOUSBDeviceControllerCreate");
    usb.description_from_controller = dlsym(iokit, "IOUSBDeviceDescriptionCreateFromController");
    usb.description_info = dlsym(iokit, "_IOUSBDeviceDescriptionGetInfo");
    usb.service = dlsym(iokit, "IOUSBDeviceControllerGetService");
    usb.set_description = dlsym(iokit, "IOUSBDeviceControllerSetDescription");
    if (!usb.create || !usb.description_from_controller || !usb.description_info || !usb.service ||
        !usb.set_description || usb.create(kCFAllocatorDefault, &usb.controller) != kIOReturnSuccess ||
        !usb.controller)
        return false;
    *out = (ipad2jb_usb){ NULL, usb_live_description, usb_publish, usb_selected_configuration,
                          usb_functions_registered };
    return true;
}

// --- the Keyboard function ----------------------------------------------------

enum {
    KEYBOARD_USER_CLIENT_TYPE = 123,
    // IOUSBDeviceInterfaceUserClient selectors.
    SEL_OPEN = 0,
    SEL_SET_CLASS = 3,
    SEL_SET_SUBCLASS = 4,
    SEL_SET_PROTOCOL = 5,
    SEL_APPEND_STANDARD_DESCRIPTOR = 6,
    SEL_APPEND_CLASS_DESCRIPTOR = 7,
    SEL_REGISTER_CLASS_REQUESTS = 8,
    SEL_COMPLETE_CLASS_REQUEST = 9,
    SEL_CREATE_PIPE = 10,
    SEL_COMMIT = 11,
    SEL_WRITE_PIPE = 14,
    SEL_PIPE_MAX_PACKET = 17,
    SEL_CREATE_BUFFER = 18,
    // Second argument of the descriptor appends; libusbd passes 0x0F unexplained.
    DESCRIPTOR_APPEND_FLAGS = 0x0F,
    // Boot keyboard (HID class 3, subclass 1, protocol 1) with one interrupt-IN
    // endpoint of 8 bytes polled every 10 ms.
    HID_CLASS = 3, HID_BOOT_SUBCLASS = 1, HID_KEYBOARD_PROTOCOL = 1,
    TRANSFER_INTERRUPT = 3, DIRECTION_IN = 1, MAX_PACKET = 8, POLL_INTERVAL = 10,
    BUFFER_SIZE = 0x1000,
    WRITE_TIMEOUT_MS = 250,
};

// Boot-keyboard report descriptor: modifiers, reserved byte, 5 LED outputs, 6 keys.
static const uint8_t report_descriptor[] = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x03, 0x75, 0x01,
    0x05, 0x08, 0x19, 0x01, 0x29, 0x03, 0x91, 0x02, 0x95, 0x05, 0x75, 0x01, 0x91, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x05, 0x07, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x81, 0x00, 0xC0,
};

// HID descriptor: bcdHID 1.11, no country, one report descriptor of the size above.
static const uint8_t hid_descriptor[] = { 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22,
                                          sizeof(report_descriptor), 0x00 };

typedef struct {
    uint64_t address, size, token;
} user_buffer;

static struct {
    io_connect_t connection;
    uint64_t pipe;
    user_buffer reports;          // staged keyboard reports (main thread)
    user_buffer class_replies;    // class-request reply data (dispatch queue)
    IONotificationPortRef port;
} keyboard;

static kern_return_t call(uint32_t selector, const uint64_t *input, uint32_t input_count,
                          uint64_t *output, uint32_t output_count) {
    uint32_t count = output_count;
    return IOConnectCallScalarMethod(keyboard.connection, selector, input, input_count, output,
                                     output ? &count : NULL);
}

static io_service_t find_keyboard_function(void) {
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceInterface");
    CFMutableDictionaryRef property = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(property, CFSTR("USBDeviceFunction"), CFSTR("Keyboard"));
    CFDictionarySetValue(matching, CFSTR("IOPropertyMatch"), property);
    CFRelease(property);
    return IOServiceGetMatchingService(kIOMainPortDefault, matching);
}

// The kernel posts each class request (SET_PROTOCOL, SET_IDLE, SET_REPORT,
// ...) here and stalls it unless userspace completes it. The Switch 2 stops
// talking to a keyboard whose requests stall.
static void class_request(void *refcon, IOReturn result, void **arguments, uint32_t count) {
    (void)refcon; (void)result;
    if (count < 5) return;
    const uint64_t *argument = (const uint64_t *)arguments;
    uint8_t request_type = (argument[1] >> 24) & 0xFF, request = (argument[1] >> 16) & 0xFF;
    uint16_t length = argument[2] & 0xFFFF;
    uint64_t token = argument[4];
    size_t reply = ipad2jb_class_reply(request_type, request, length,
                                       (uint8_t *)(uintptr_t)keyboard.class_replies.address,
                                       (size_t)keyboard.class_replies.size);
    uint64_t complete[5] = { 1, reply, keyboard.class_replies.address, 0, token };
    call(SEL_COMPLETE_CLASS_REQUEST, complete, 5, NULL, 0);
}

static bool create_buffer(user_buffer *buffer) {
    uint64_t size[1] = { BUFFER_SIZE }, out[3];
    if (call(SEL_CREATE_BUFFER, size, 1, out, 3)) return false;
    *buffer = (user_buffer){ out[0], out[1], out[2] };
    return true;
}

static bool serve_class_requests(void) {
    keyboard.port = IONotificationPortCreate(kIOMainPortDefault);
    if (!keyboard.port) return false;
    IONotificationPortSetDispatchQueue(keyboard.port,
                                       dispatch_queue_create("ipad2jb.class-requests", DISPATCH_QUEUE_SERIAL));
    mach_port_t port = IONotificationPortGetMachPort(keyboard.port);
    uint64_t reference[kOSAsyncRef64Count] = { 0 };
    reference[kIOAsyncReservedIndex] = port;
    reference[kIOAsyncCalloutFuncIndex] = (uint64_t)(uintptr_t)class_request;
    uint64_t flags[3] = { 1, 0, 0 };   // libusbd's flags; the meaning of the others is unknown
    return IOConnectCallAsyncScalarMethod(keyboard.connection, SEL_REGISTER_CLASS_REQUESTS, port,
                                          reference, kOSAsyncRef64Count, flags, 3, NULL, NULL) == 0;
}

typedef struct {
    const char *name;
    uint32_t selector;
    uint64_t arguments[2];
    uint32_t argument_count;
    const uint8_t *descriptor;    // struct input for the descriptor appends
    size_t descriptor_length;
} interface_step;

static const interface_step interface_steps[] = {
    { "open", SEL_OPEN, { 0 }, 1, NULL, 0 },
    { "set class", SEL_SET_CLASS, { HID_CLASS, 0 }, 2, NULL, 0 },
    { "set subclass", SEL_SET_SUBCLASS, { HID_BOOT_SUBCLASS, 0 }, 2, NULL, 0 },
    { "set protocol", SEL_SET_PROTOCOL, { HID_KEYBOARD_PROTOCOL, 0 }, 2, NULL, 0 },
    { "HID descriptor", SEL_APPEND_STANDARD_DESCRIPTOR, { 0x21, DESCRIPTOR_APPEND_FLAGS }, 2,
      hid_descriptor, sizeof(hid_descriptor) },
    { "report descriptor", SEL_APPEND_CLASS_DESCRIPTOR, { 0x22, DESCRIPTOR_APPEND_FLAGS }, 2,
      report_descriptor, sizeof(report_descriptor) },
};

static bool keyboard_open(void *context, const char **failed_step) {
    (void)context;
    io_service_t function = IO_OBJECT_NULL;
    for (int wait = 0; wait < 100 && !function; wait++) {   // the function appears after publishing
        function = find_keyboard_function();
        if (!function) usleep(100 * 1000);
    }
    *failed_step = "find the Keyboard function";
    if (!function) return false;
    kern_return_t opened = IOServiceOpen(function, mach_task_self(), KEYBOARD_USER_CLIENT_TYPE,
                                         &keyboard.connection);
    IOObjectRelease(function);
    *failed_step = "open the Keyboard function";
    if (opened != kIOReturnSuccess) return false;

    for (size_t i = 0; i < sizeof(interface_steps) / sizeof(interface_steps[0]); i++) {
        const interface_step *step = &interface_steps[i];
        *failed_step = step->name;
        kern_return_t status = step->descriptor
            ? IOConnectCallMethod(keyboard.connection, step->selector, step->arguments, step->argument_count,
                                  step->descriptor, step->descriptor_length, NULL, NULL, NULL, NULL)
            : call(step->selector, step->arguments, step->argument_count, NULL, 0);
        if (status) return false;
    }
    uint64_t endpoint[6] = { TRANSFER_INTERRUPT, DIRECTION_IN, MAX_PACKET, POLL_INTERVAL, 0, 0 };
    *failed_step = "create the interrupt-IN pipe";
    if (call(SEL_CREATE_PIPE, endpoint, 6, &keyboard.pipe, 1)) return false;
    *failed_step = "create buffers";
    if (!create_buffer(&keyboard.reports) || !create_buffer(&keyboard.class_replies)) return false;
    *failed_step = "commit";
    if (call(SEL_COMMIT, NULL, 0, NULL, 0)) return false;
    *failed_step = "serve class requests";
    return serve_class_requests();
}

static bool keyboard_host_selected(void *context) {
    (void)context;
    uint64_t pipe[1] = { keyboard.pipe }, max_packet = 0;
    return call(SEL_PIPE_MAX_PACKET, pipe, 1, &max_packet, 1) == 0 && max_packet > 0;
}

static ipad2jb_send_result keyboard_send(void *context, const uint8_t report[IPAD2JB_REPORT_LENGTH]) {
    (void)context;
    memcpy((void *)(uintptr_t)keyboard.reports.address, report, IPAD2JB_REPORT_LENGTH);
    uint64_t write[4] = { keyboard.pipe, keyboard.reports.token, IPAD2JB_REPORT_LENGTH, WRITE_TIMEOUT_MS };
    uint64_t transferred = 0;
    kern_return_t status = call(SEL_WRITE_PIPE, write, 4, &transferred, 1);
    if (status == kIOReturnSuccess) return IPAD2JB_SEND_OK;
    return status == kIOReturnTimeout ? IPAD2JB_SEND_TIMEOUT : IPAD2JB_SEND_FAILED;
}

static void keyboard_close(void *context) {
    (void)context;
    if (keyboard.connection) IOServiceClose(keyboard.connection);
    keyboard.connection = IO_OBJECT_NULL;
}

void ipad2jb_iokit_keyboard(ipad2jb_keyboard *out) {
    *out = (ipad2jb_keyboard){ NULL, keyboard_open, keyboard_host_selected, keyboard_send, keyboard_close };
}
