// ipad2jb: make a jailbroken iPad type text as a USB keyboard on the host it is
// plugged into (tested: Nintendo Switch 2 and macOS), then restore normal USB.
//
//   sudo ipad2jb [TEXT]        TEXT defaults to "ipad2jb"; letters, digits, spaces.
//
// How it works (iPadOS 17, USB device controller via private IOKit APIs):
//  1. Save the live (stock) USB device description to STOCK_FILE.
//  2. Publish it with ConfigurationDescriptors replaced by one "Standard
//     Keyboard" configuration [AppleUSBMux, Keyboard]. The controller only
//     goes on bus once every function named in any configuration has
//     registered, so dropping the other stock configurations is what lets the
//     keyboard come up at all.
//  3. Open the Keyboard function's IOUSBDeviceInterfaceUserClient and make it a
//     boot keyboard: class 3/1/1, HID + report descriptors, an 8-byte
//     interrupt-IN endpoint, a buffer, commit.
//  4. Answer every class request (SET_PROTOCOL, SET_IDLE, SET_REPORT, ...) by
//     completing it with selector 9. Unanswered requests are stalled, and the
//     Switch then never polls the keyboard.
//  5. Wait for the host to poll, settle, type TEXT, and restore STOCK_FILE.
//     A run interrupted before step 5 is restored by the next run at startup.
//
// Needs root and the entitlements in ipad2jb.entitlements (ad-hoc signed).

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATE_DIR "/var/jb/var/lib/ipad2jb"
#define STOCK_FILE STATE_DIR "/stock-description.plist"
#define USER_CLIENT_TYPE 123

// --- private IOUSBDeviceController API (IOKit.framework) ---
typedef struct __IOUSBDeviceController *ControllerRef;
typedef struct __IOUSBDeviceDescription *DescriptionRef;
static IOReturn (*ControllerCreate)(CFAllocatorRef, ControllerRef *);
static DescriptionRef (*DescriptionFromController)(CFAllocatorRef, ControllerRef);
static CFMutableDictionaryRef (*DescriptionGetInfo)(DescriptionRef);
static io_service_t (*ControllerGetService)(ControllerRef);
static IOReturn (*ControllerSetDescription)(ControllerRef, DescriptionRef);

static volatile sig_atomic_t interrupted = 0;
static void on_signal(int sig) { (void)sig; interrupted = 1; }

static void say(const char *message) { printf("ipad2jb: %s\n", message); fflush(stdout); }

static void sleep_ms(unsigned ms) { usleep(ms * 1000); }

// --- controller and descriptions ---

static ControllerRef controller;

static int load_api(void) {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!iokit) return -1;
    ControllerCreate = dlsym(iokit, "IOUSBDeviceControllerCreate");
    DescriptionFromController = dlsym(iokit, "IOUSBDeviceDescriptionCreateFromController");
    DescriptionGetInfo = dlsym(iokit, "_IOUSBDeviceDescriptionGetInfo");
    ControllerGetService = dlsym(iokit, "IOUSBDeviceControllerGetService");
    ControllerSetDescription = dlsym(iokit, "IOUSBDeviceControllerSetDescription");
    if (!ControllerCreate || !DescriptionFromController || !DescriptionGetInfo ||
        !ControllerGetService || !ControllerSetDescription) return -1;
    return ControllerCreate(kCFAllocatorDefault, &controller) == kIOReturnSuccess && controller ? 0 : -1;
}

// A copy of the live description dictionary.
static CFMutableDictionaryRef live_description(void) {
    DescriptionRef description = DescriptionFromController(kCFAllocatorDefault, controller);
    if (!description) return NULL;
    CFMutableDictionaryRef copy = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0,
                                                                DescriptionGetInfo(description));
    CFRelease(description);
    return copy;
}

// Publish `info` as the controller's description.
static IOReturn publish(CFDictionaryRef info) {
    DescriptionRef description = DescriptionFromController(kCFAllocatorDefault, controller);
    if (!description) return kIOReturnError;
    CFMutableDictionaryRef target = DescriptionGetInfo(description);
    CFDictionaryRemoveAllValues(target);
    CFIndex count = CFDictionaryGetCount(info);
    const void *keys[count], *values[count];
    CFDictionaryGetKeysAndValues(info, keys, values);
    for (CFIndex i = 0; i < count; i++) CFDictionarySetValue(target, keys[i], values[i]);
    CFDictionarySetValue(target, CFSTR("AllowMultipleCreates"), kCFBooleanTrue);
    IOReturn status = ControllerSetDescription(controller, description);
    CFRelease(description);
    return status;
}

static CFTypeRef controller_property(CFStringRef key) {
    return IORegistryEntryCreateCFProperty(ControllerGetService(controller), key, kCFAllocatorDefault, 0);
}

// The host-selected configuration number and whether the controller is
// configured by a host.
static int selected_configuration(void) {
    CFDictionaryRef state = controller_property(CFSTR("CurrentState"));
    int selected = 0;
    if (state) {
        CFNumberRef number = CFDictionaryGetValue(state, CFSTR("SelectedConfiguration"));
        if (number) CFNumberGetValue(number, kCFNumberIntType, &selected);
        CFRelease(state);
    }
    return selected;
}

static int save_stock(CFDictionaryRef info) {
    mkdir(STATE_DIR, 0755);
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, info,
                                              kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    if (!data) return -1;
    FILE *file = fopen(STOCK_FILE, "wb");
    int ok = file && fwrite(CFDataGetBytePtr(data), 1, CFDataGetLength(data), file) ==
             (size_t)CFDataGetLength(data);
    if (file) fclose(file);
    CFRelease(data);
    return ok ? 0 : -1;
}

static CFDictionaryRef load_stock(void) {
    FILE *file = fopen(STOCK_FILE, "rb");
    if (!file) return NULL;
    static UInt8 buffer[256 * 1024];
    size_t length = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, buffer, (CFIndex)length);
    CFPropertyListRef list = CFPropertyListCreateWithData(kCFAllocatorDefault, data, 0, NULL, NULL);
    CFRelease(data);
    if (list && CFGetTypeID(list) != CFDictionaryGetTypeID()) { CFRelease(list); list = NULL; }
    return list;
}

static int keyboard_config_only(CFDictionaryRef info) {
    CFArrayRef configs = CFDictionaryGetValue(info, CFSTR("ConfigurationDescriptors"));
    if (!configs || CFArrayGetCount(configs) != 1) return 0;
    CFArrayRef names = CFDictionaryGetValue(CFArrayGetValueAtIndex(configs, 0), CFSTR("Interfaces"));
    return names && CFArrayContainsValue(names, CFRangeMake(0, CFArrayGetCount(names)), CFSTR("Keyboard"));
}

// The stock description with only the selected configuration, turned into
// Apple's single-configuration "Standard Keyboard" profile.
static CFMutableDictionaryRef keyboard_description(CFDictionaryRef stock, int selected) {
    CFArrayRef configs = CFDictionaryGetValue(stock, CFSTR("ConfigurationDescriptors"));
    if (!configs || selected < 1 || selected > CFArrayGetCount(configs)) return NULL;
    CFMutableDictionaryRef config = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, CFArrayGetValueAtIndex(configs, selected - 1));
    const void *names[] = { CFSTR("AppleUSBMux"), CFSTR("Keyboard") };
    CFArrayRef interfaces = CFArrayCreate(kCFAllocatorDefault, names, 2, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(config, CFSTR("Interfaces"), interfaces);
    CFDictionarySetValue(config, CFSTR("Description"), CFSTR("Standard Keyboard"));
    CFDictionarySetValue(config, CFSTR("DefaultConfiguration"), kCFBooleanTrue);
    CFDictionaryRemoveValue(config, CFSTR("InterfaceAssociation"));
    CFDictionaryRemoveValue(config, CFSTR("ExtendedConfiguration"));
    CFDictionaryRemoveValue(config, CFSTR("LockedConfiguration"));
    CFDictionaryRemoveValue(config, CFSTR("AccessoryResistorSwap"));
    const void *only[] = { config };
    CFArrayRef single = CFArrayCreate(kCFAllocatorDefault, only, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef result = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, stock);
    CFDictionaryRemoveValue(result, CFSTR("AllowMultipleCreates"));
    CFDictionarySetValue(result, CFSTR("ConfigurationDescriptors"), single);
    CFRelease(interfaces); CFRelease(config); CFRelease(single);
    return result;
}

// Every function named in `info` has a registered IOUSBDeviceInterface.
static int all_functions_registered(CFDictionaryRef info) {
    CFMutableSetRef wanted = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
    CFArrayRef configs = CFDictionaryGetValue(info, CFSTR("ConfigurationDescriptors"));
    for (CFIndex i = 0; configs && i < CFArrayGetCount(configs); i++) {
        CFArrayRef names = CFDictionaryGetValue(CFArrayGetValueAtIndex(configs, i), CFSTR("Interfaces"));
        for (CFIndex j = 0; names && j < CFArrayGetCount(names); j++)
            CFSetAddValue(wanted, CFArrayGetValueAtIndex(names, j));
    }
    io_iterator_t iterator;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBDeviceInterface"),
                                     &iterator) == kIOReturnSuccess) {
        io_service_t entry;
        while ((entry = IOIteratorNext(iterator))) {
            CFTypeRef name = IORegistryEntryCreateCFProperty(entry, CFSTR("USBDeviceFunction"),
                                                             kCFAllocatorDefault, 0);
            if (name) { CFSetRemoveValue(wanted, name); CFRelease(name); }
            IOObjectRelease(entry);
        }
        IOObjectRelease(iterator);
    }
    int complete = CFSetGetCount(wanted) == 0;
    CFRelease(wanted);
    return complete;
}

// Put the stock description back and wait until every stock function has
// registered and (if a host is attached) the host has configured it again.
// The function-registration race can strand a function, so republish up to
// three times.
static int restore_stock(void) {
    CFDictionaryRef stock = load_stock();
    if (!stock) return 0;
    int restored = 0;
    for (int attempt = 0; attempt < 4 && !restored; attempt++) {
        if (publish(stock) != kIOReturnSuccess) { sleep_ms(1000); continue; }
        for (int wait = 0; wait < 40 && !restored; wait++) {
            sleep_ms(500);
            restored = all_functions_registered(stock) && selected_configuration() > 0;
        }
    }
    CFRelease(stock);
    if (restored) unlink(STOCK_FILE);
    return restored;
}

// --- the Keyboard function ---

static io_connect_t keyboard;
static uint64_t pipe_id, buffer_address, buffer_size, buffer_token;

static kern_return_t call(uint32_t selector, const uint64_t *in, uint32_t inCount,
                          uint64_t *out, uint32_t outCount) {
    uint32_t count = outCount;
    return IOConnectCallScalarMethod(keyboard, selector, in, inCount, out, out ? &count : NULL);
}

static int open_keyboard(void) {
    for (int wait = 0; wait < 100 && !interrupted; wait++) {
        CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceInterface");
        CFMutableDictionaryRef property = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(property, CFSTR("USBDeviceFunction"), CFSTR("Keyboard"));
        CFDictionarySetValue(matching, CFSTR("IOPropertyMatch"), property);
        CFRelease(property);
        io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
        if (service) {
            kern_return_t status = IOServiceOpen(service, mach_task_self(), USER_CLIENT_TYPE, &keyboard);
            IOObjectRelease(service);
            return status == kIOReturnSuccess ? 0 : -1;
        }
        sleep_ms(100);
    }
    return -1;
}

static const uint8_t report_descriptor[] = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x03, 0x75, 0x01,
    0x05, 0x08, 0x19, 0x01, 0x29, 0x03, 0x91, 0x02, 0x95, 0x05, 0x75, 0x01, 0x91, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x05, 0x07, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x81, 0x00, 0xC0,
};

static void class_request(void *refcon, IOReturn result, void **args, uint32_t numArgs) {
    (void)refcon; (void)result;
    if (numArgs < 5) return;
    uint64_t *arg = (uint64_t *)args;
    uint8_t requestType = (arg[1] >> 24) & 0xFF, request = (arg[1] >> 16) & 0xFF;
    uint16_t length = arg[2] & 0xFFFF;
    uint64_t reply = 0;
    if ((requestType & 0x80) && length) {            // device-to-host: zeros,
        reply = length > 64 ? 64 : length;            // GET_PROTOCOL = report (1)
        memset((void *)(uintptr_t)buffer_address, 0, reply);
        if (requestType == 0xA1 && request == 0x03) ((uint8_t *)(uintptr_t)buffer_address)[0] = 1;
    }
    uint64_t complete[5] = { 1, reply, buffer_address, 0, arg[4] };
    call(9, complete, 5, NULL, 0);
}

static int configure_keyboard(void) {
    uint8_t hid_descriptor[] = { 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, sizeof(report_descriptor), 0 };
    uint64_t zero[1] = { 0 }, out[3];
    uint64_t class_[2] = { 3, 0 }, subclass[2] = { 1, 0 }, protocol[2] = { 1, 0 };
    uint64_t hid_type[2] = { 0x21, 0x0F }, report_type[2] = { 0x22, 0x0F };
    uint64_t endpoint[6] = { 3 /*interrupt*/, 1 /*IN*/, 8, 10, 0, 0 }, buffer[1] = { 0x1000 };
    if (call(0, zero, 1, NULL, 0) || call(3, class_, 2, NULL, 0) || call(4, subclass, 2, NULL, 0) ||
        call(5, protocol, 2, NULL, 0) ||
        IOConnectCallMethod(keyboard, 6, hid_type, 2, hid_descriptor, sizeof(hid_descriptor),
                            NULL, NULL, NULL, NULL) ||
        IOConnectCallMethod(keyboard, 7, report_type, 2, report_descriptor, sizeof(report_descriptor),
                            NULL, NULL, NULL, NULL) ||
        call(10, endpoint, 6, out, 1)) return -1;
    pipe_id = out[0];
    if (call(18, buffer, 1, out, 3)) return -1;
    buffer_address = out[0]; buffer_size = out[1]; buffer_token = out[2];
    if (call(11, NULL, 0, NULL, 0)) return -1;
    // Class requests arrive on a notification port served on a dispatch queue.
    IONotificationPortRef port = IONotificationPortCreate(kIOMainPortDefault);
    IONotificationPortSetDispatchQueue(port, dispatch_queue_create("ipad2jb", DISPATCH_QUEUE_SERIAL));
    uint64_t reference[kOSAsyncRef64Count] = { 0 };
    reference[kIOAsyncReservedIndex] = IONotificationPortGetMachPort(port);
    reference[kIOAsyncCalloutFuncIndex] = (uint64_t)(uintptr_t)class_request;
    uint64_t flags[3] = { 1, 0, 0 };
    return IOConnectCallAsyncScalarMethod(keyboard, 8, IONotificationPortGetMachPort(port), reference,
                                          kOSAsyncRef64Count, flags, 3, NULL, NULL) ? -1 : 0;
}

// Write one 8-byte report; returns the raw IOReturn (0 once the host read it).
static kern_return_t send_report(const uint8_t report[8]) {
    memcpy((void *)(uintptr_t)buffer_address, report, 8);
    uint64_t write[4] = { pipe_id, buffer_token, 8, 250 }, transferred = 0;
    return call(14, write, 4, &transferred, 1);
}

static int host_selected_keyboard(void) {
    uint64_t in[1] = { pipe_id }, size = 0;
    return call(17, in, 1, &size, 1) == 0 && size > 0;
}

// Keep the host's view neutral for `ms`; returns 0 if the host stays connected.
static int hold_neutral(unsigned ms) {
    static const uint8_t neutral[8] = { 0 };
    for (unsigned elapsed = 0; elapsed < ms && !interrupted; elapsed += 30) {
        kern_return_t status = send_report(neutral);
        if (status && status != (kern_return_t)0xE00002D6) return -1;   // not just a timeout
        sleep_ms(30);
    }
    return 0;
}

static int keycode(char c, uint8_t *modifier, uint8_t *code) {
    *modifier = 0;
    if (c >= 'a' && c <= 'z') *code = 0x04 + (c - 'a');
    else if (c >= 'A' && c <= 'Z') { *code = 0x04 + (c - 'A'); *modifier = 0x02; }
    else if (c >= '1' && c <= '9') *code = 0x1E + (c - '1');
    else if (c == '0') *code = 0x27;
    else if (c == ' ') *code = 0x2C;
    else return -1;
    return 0;
}

static int type_text(const char *text) {
    // Wait for the host to select the keyboard and start polling it.
    int polled = 0;
    static const uint8_t neutral[8] = { 0 };
    for (int wait = 0; wait < 600 && !interrupted && !polled; wait++) {
        if (host_selected_keyboard() && send_report(neutral) == 0) polled = 1;
        else sleep_ms(100);
    }
    if (!polled) { say("the host never started reading the keyboard"); return -1; }
    say("host is reading the keyboard; typing");
    if (hold_neutral(3000)) return -1;                  // let the host finish attaching
    for (const char *c = text; *c && !interrupted; c++) {
        uint8_t report[8] = { 0 };
        keycode(*c, &report[0], &report[2]);
        if (send_report(report) || send_report(neutral)) return -1;
        sleep_ms(30);
    }
    return hold_neutral(1000);
}

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "ipad2jb";
    uint8_t m, k;
    for (const char *c = text; *c; c++)
        if (keycode(*c, &m, &k)) { fprintf(stderr, "ipad2jb: only letters, digits and spaces\n"); return 1; }
    if (getuid() != 0) { fprintf(stderr, "ipad2jb: run as root: sudo ipad2jb\n"); return 1; }
    if (load_api()) { say("USB device controller unavailable"); return 1; }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal); signal(SIGHUP, on_signal);

    if (access(STOCK_FILE, F_OK) == 0) {
        say("restoring USB left over from an earlier run");
        if (!restore_stock()) { say("could not restore; replug the cable or reboot"); return 1; }
    }
    CFMutableDictionaryRef stock = live_description();
    int selected = selected_configuration();
    if (!stock || keyboard_config_only(stock)) { say("USB is not in its stock state; reboot"); return 1; }
    if (selected < 1) { say("no USB host has selected a configuration; plug into the host first"); return 1; }
    CFDictionaryRemoveValue(stock, CFSTR("AllowMultipleCreates"));
    CFMutableDictionaryRef keyboard_info = keyboard_description(stock, selected);
    if (!keyboard_info || save_stock(stock)) { say("could not prepare the keyboard description"); return 1; }

    int typed = -1;
    if (publish(keyboard_info) != kIOReturnSuccess) say("the controller refused the keyboard description");
    else if (open_keyboard() || configure_keyboard()) say("could not set up the keyboard function");
    else { say("keyboard published"); typed = type_text(text); }
    if (keyboard) IOServiceClose(keyboard);

    say("restoring normal USB");
    int restored = restore_stock();
    say(restored ? "normal USB restored" : "USB not back yet; run ipad2jb again or replug the cable");
    if (typed == 0) printf("ipad2jb: typed \"%s\"\n", text);
    return typed == 0 && restored ? 0 : 1;
}
