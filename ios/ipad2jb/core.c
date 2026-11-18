// The ipad2jb run and its pure helpers. No IOKit: the device is reached only
// through ipad2jb_env, so tests/test_core.c can drive every path with fakes.

#include "ipad2jb.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Timing. The host needs a moment after it starts polling before its input
// system attaches to a new keyboard, and the canary-era runs showed reports
// typed in the first milliseconds can be dropped.
enum {
    POLL_WAIT_MS = 60000,        // for the host to start reading the keyboard
    POLL_INTERVAL_MS = 100,
    SETTLE_MS = 3000,            // neutral reports before typing
    KEY_GAP_MS = 30,
    HOLD_MS = 1000,              // neutral reports after typing, before restoring
    NEUTRAL_INTERVAL_MS = 30,
    RESTORE_ATTEMPTS = 4,        // the function-registration race can strand a function
    REGISTER_WAIT_MS = 20000,
    RESTORE_POLL_MS = 500,
    HOST_RESELECT_WAIT_MS = 10000,
    REPUBLISH_DELAY_MS = 1000,
};

#define MAX_CLASS_REPLY 64
#define LEFT_SHIFT 0x02

static const uint8_t neutral_report[IPAD2JB_REPORT_LENGTH] = { 0 };

// --- pure helpers -----------------------------------------------------------

bool ipad2jb_keycode(char c, uint8_t *modifier, uint8_t *usage) {
    *modifier = 0;
    if (c >= 'a' && c <= 'z') *usage = (uint8_t)(0x04 + (c - 'a'));
    else if (c >= 'A' && c <= 'Z') { *usage = (uint8_t)(0x04 + (c - 'A')); *modifier = LEFT_SHIFT; }
    else if (c >= '1' && c <= '9') *usage = (uint8_t)(0x1E + (c - '1'));
    else if (c == '0') *usage = 0x27;
    else if (c == ' ') *usage = 0x2C;
    else return false;
    return true;
}

bool ipad2jb_text_is_typable(const char *text) {
    if (!text || !*text || strlen(text) > IPAD2JB_MAX_TEXT) return false;
    uint8_t modifier, usage;
    for (const char *c = text; *c; c++)
        if (!ipad2jb_keycode(*c, &modifier, &usage)) return false;
    return true;
}

size_t ipad2jb_class_reply(uint8_t request_type, uint8_t request, uint16_t length,
                           uint8_t *reply, size_t capacity) {
    enum { DEVICE_TO_HOST = 0x80, HID_CLASS_IN = 0xA1, GET_PROTOCOL = 0x03, REPORT_PROTOCOL = 1 };
    if (!(request_type & DEVICE_TO_HOST) || length == 0 || !reply) return 0;
    size_t size = length;
    if (size > MAX_CLASS_REPLY) size = MAX_CLASS_REPLY;
    if (size > capacity) size = capacity;
    memset(reply, 0, size);
    if (request_type == HID_CLASS_IN && request == GET_PROTOCOL && size >= 1) reply[0] = REPORT_PROTOCOL;
    return size;
}

static CFArrayRef configurations(CFDictionaryRef description) {
    CFTypeRef value = CFDictionaryGetValue(description, CFSTR("ConfigurationDescriptors"));
    return value && CFGetTypeID(value) == CFArrayGetTypeID() ? value : NULL;
}

static CFArrayRef interface_names(CFTypeRef configuration) {
    if (!configuration || CFGetTypeID(configuration) != CFDictionaryGetTypeID()) return NULL;
    CFTypeRef value = CFDictionaryGetValue(configuration, CFSTR("Interfaces"));
    return value && CFGetTypeID(value) == CFArrayGetTypeID() ? value : NULL;
}

CFMutableDictionaryRef ipad2jb_keyboard_description(CFDictionaryRef stock, int selected) {
    CFArrayRef configs = configurations(stock);
    if (!configs || selected < 1 || selected > CFArrayGetCount(configs)) return NULL;
    CFTypeRef source = CFArrayGetValueAtIndex(configs, selected - 1);
    if (CFGetTypeID(source) != CFDictionaryGetTypeID()) return NULL;

    CFMutableDictionaryRef keyboard = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, source);
    const void *names[] = { CFSTR("AppleUSBMux"), CFSTR("Keyboard") };
    CFArrayRef interfaces = CFArrayCreate(kCFAllocatorDefault, names, 2, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(keyboard, CFSTR("Interfaces"), interfaces);
    CFDictionarySetValue(keyboard, CFSTR("Description"), CFSTR("Standard Keyboard"));
    CFDictionarySetValue(keyboard, CFSTR("DefaultConfiguration"), kCFBooleanTrue);
    // Keys that only make sense among the stock configurations.
    const CFStringRef stock_only[] = { CFSTR("InterfaceAssociation"), CFSTR("ExtendedConfiguration"),
                                       CFSTR("LockedConfiguration"), CFSTR("AccessoryResistorSwap") };
    for (size_t i = 0; i < sizeof(stock_only) / sizeof(stock_only[0]); i++)
        CFDictionaryRemoveValue(keyboard, stock_only[i]);

    const void *only[] = { keyboard };
    CFArrayRef single = CFArrayCreate(kCFAllocatorDefault, only, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef result = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, stock);
    CFDictionarySetValue(result, CFSTR("ConfigurationDescriptors"), single);
    CFRelease(interfaces);
    CFRelease(keyboard);
    CFRelease(single);
    return result;
}

bool ipad2jb_is_keyboard_description(CFDictionaryRef description) {
    CFArrayRef configs = configurations(description);
    if (!configs || CFArrayGetCount(configs) != 1) return false;
    CFArrayRef names = interface_names(CFArrayGetValueAtIndex(configs, 0));
    return names && CFArrayContainsValue(names, CFRangeMake(0, CFArrayGetCount(names)), CFSTR("Keyboard"));
}

CFSetRef ipad2jb_function_names(CFDictionaryRef description) {
    CFMutableSetRef functions = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
    CFArrayRef configs = configurations(description);
    for (CFIndex i = 0; configs && i < CFArrayGetCount(configs); i++) {
        CFArrayRef names = interface_names(CFArrayGetValueAtIndex(configs, i));
        for (CFIndex j = 0; names && j < CFArrayGetCount(names); j++)
            CFSetAddValue(functions, CFArrayGetValueAtIndex(names, j));
    }
    return functions;
}

// --- the saved stock description -------------------------------------------

static bool make_parent_directory(const char *path) {
    char parent[1024];
    const char *slash = strrchr(path, '/');
    if (!slash || (size_t)(slash - path) >= sizeof(parent)) return false;
    memcpy(parent, path, (size_t)(slash - path));
    parent[slash - path] = '\0';
    return parent[0] == '\0' || mkdir(parent, 0755) == 0 || errno == EEXIST;
}

static bool save_stock(const char *path, CFDictionaryRef description) {
    if (!make_parent_directory(path)) return false;
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, description,
                                              kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    if (!data) return false;
    FILE *file = fopen(path, "wb");
    size_t length = (size_t)CFDataGetLength(data);
    bool ok = file && fwrite(CFDataGetBytePtr(data), 1, length, file) == length;
    if (file && fclose(file) != 0) ok = false;
    CFRelease(data);
    return ok;
}

static CFDictionaryRef load_stock(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    uint8_t chunk[16384];
    size_t count;
    while ((count = fread(chunk, 1, sizeof(chunk), file)) > 0) CFDataAppendBytes(data, chunk, (CFIndex)count);
    fclose(file);
    CFPropertyListRef list = CFPropertyListCreateWithData(kCFAllocatorDefault, data, 0, NULL, NULL);
    CFRelease(data);
    if (list && CFGetTypeID(list) != CFDictionaryGetTypeID()) { CFRelease(list); list = NULL; }
    return list;
}

// --- waiting ----------------------------------------------------------------

typedef bool (*condition)(const ipad2jb_env *env, const void *argument);

// Poll `done` every `interval_ms` until it holds or `timeout_ms` of sleeping
// has passed. The restore deliberately ignores interruption.
static bool wait_until(const ipad2jb_env *env, condition done, const void *argument,
                       unsigned timeout_ms, unsigned interval_ms, bool stop_on_interrupt) {
    for (unsigned slept = 0;; slept += interval_ms) {
        if (done(env, argument)) return true;
        if (slept >= timeout_ms || (stop_on_interrupt && *env->interrupted)) return false;
        env->sleep_ms(interval_ms);
    }
}

static bool functions_registered(const ipad2jb_env *env, const void *functions) {
    return env->usb.functions_registered(env->usb.context, functions);
}

static bool host_selected_configuration(const ipad2jb_env *env, const void *unused) {
    (void)unused;
    return env->usb.selected_configuration(env->usb.context) > 0;
}

static bool host_reading_keyboard(const ipad2jb_env *env, const void *unused) {
    (void)unused;
    return env->keyboard.host_selected(env->keyboard.context) &&
           env->keyboard.send(env->keyboard.context, neutral_report) == IPAD2JB_SEND_OK;
}

// --- restoring --------------------------------------------------------------

// Publish the saved stock description until every stock function registers,
// then give a host a moment to select a configuration again. The file is
// removed once the functions are back, host or not.
static ipad2jb_restore restore_stock(const ipad2jb_env *env) {
    CFDictionaryRef stock = load_stock(env->stock_path);
    if (!stock) return IPAD2JB_NOTHING_TO_RESTORE;
    CFSetRef functions = ipad2jb_function_names(stock);
    bool registered = false;
    for (int attempt = 0; attempt < RESTORE_ATTEMPTS && !registered; attempt++) {
        if (!env->usb.publish(env->usb.context, stock)) { env->sleep_ms(REPUBLISH_DELAY_MS); continue; }
        registered = wait_until(env, functions_registered, functions,
                                REGISTER_WAIT_MS, RESTORE_POLL_MS, false);
    }
    CFRelease(functions);
    CFRelease(stock);
    if (!registered) return IPAD2JB_RESTORE_FAILED;
    unlink(env->stock_path);
    return wait_until(env, host_selected_configuration, NULL, HOST_RESELECT_WAIT_MS, RESTORE_POLL_MS, false)
        ? IPAD2JB_RESTORED : IPAD2JB_RESTORED_NO_HOST;
}

static const char *restore_message(ipad2jb_restore restore) {
    switch (restore) {
    case IPAD2JB_RESTORED: return "normal USB restored";
    case IPAD2JB_RESTORED_NO_HOST: return "normal USB restored (no host reconnected)";
    case IPAD2JB_RESTORE_FAILED: return "USB not back yet; run ipad2jb again or replug the cable";
    case IPAD2JB_NOTHING_TO_RESTORE: return "nothing to restore";
    }
    return "";
}

// --- typing -----------------------------------------------------------------

// Offer neutral reports for `milliseconds`. A timed-out offer only means the
// host did not poll in that slice; any other failure means it went away.
static bool hold_neutral(const ipad2jb_env *env, unsigned milliseconds) {
    for (unsigned elapsed = 0; elapsed < milliseconds && !*env->interrupted; elapsed += NEUTRAL_INTERVAL_MS) {
        if (env->keyboard.send(env->keyboard.context, neutral_report) == IPAD2JB_SEND_FAILED) return false;
        env->sleep_ms(NEUTRAL_INTERVAL_MS);
    }
    return true;
}

static bool press_and_release(const ipad2jb_env *env, char c) {
    uint8_t report[IPAD2JB_REPORT_LENGTH] = { 0 };
    if (!ipad2jb_keycode(c, &report[0], &report[2])) return false;
    return env->keyboard.send(env->keyboard.context, report) == IPAD2JB_SEND_OK &&
           env->keyboard.send(env->keyboard.context, neutral_report) == IPAD2JB_SEND_OK;
}

static ipad2jb_typing type_text(const ipad2jb_env *env, const char *text) {
    if (!wait_until(env, host_reading_keyboard, NULL, POLL_WAIT_MS, POLL_INTERVAL_MS, true))
        return *env->interrupted ? IPAD2JB_INTERRUPTED : IPAD2JB_NEVER_POLLED;
    env->say("host is reading the keyboard; typing");
    if (!hold_neutral(env, SETTLE_MS)) return IPAD2JB_HOST_LOST;
    for (const char *c = text; *c; c++) {
        if (*env->interrupted) return IPAD2JB_INTERRUPTED;
        if (!press_and_release(env, *c)) return IPAD2JB_HOST_LOST;
        env->sleep_ms(KEY_GAP_MS);
    }
    if (*env->interrupted) return IPAD2JB_INTERRUPTED;
    return hold_neutral(env, HOLD_MS) ? IPAD2JB_TYPED : IPAD2JB_HOST_LOST;
}

// --- the run ----------------------------------------------------------------

static ipad2jb_typing publish_and_type(const ipad2jb_env *env, CFDictionaryRef keyboard_description,
                                       const char *text) {
    if (!env->usb.publish(env->usb.context, keyboard_description)) {
        env->say("the controller refused the keyboard description");
        return IPAD2JB_PUBLISH_FAILED;
    }
    const char *failed_step = "unknown";
    if (!env->keyboard.open(env->keyboard.context, &failed_step)) {
        char message[128];
        snprintf(message, sizeof(message), "could not set up the keyboard function (%s)", failed_step);
        env->say(message);
        return IPAD2JB_SETUP_FAILED;
    }
    env->say("keyboard published");
    return type_text(env, text);
}

ipad2jb_outcome ipad2jb_run(const ipad2jb_env *env, const char *text) {
    ipad2jb_outcome outcome = { IPAD2JB_PREPARE_FAILED, IPAD2JB_NOTHING_TO_RESTORE };

    if (access(env->stock_path, F_OK) == 0) {
        env->say("restoring USB left over from an earlier run");
        if (restore_stock(env) == IPAD2JB_RESTORE_FAILED) {
            env->say("could not restore; replug the cable or reboot");
            outcome.typing = IPAD2JB_LEFTOVER_FAILED;
            outcome.restore = IPAD2JB_RESTORE_FAILED;
            return outcome;
        }
    }

    CFMutableDictionaryRef stock = env->usb.live_description(env->usb.context);
    int selected = env->usb.selected_configuration(env->usb.context);
    if (!stock) { env->say("USB device controller unavailable"); return outcome; }
    if (ipad2jb_is_keyboard_description(stock)) {
        env->say("USB is not in its stock state; reboot");
        outcome.typing = IPAD2JB_NOT_STOCK;
    } else if (selected < 1) {
        env->say("no USB host has selected a configuration; plug into the host first");
        outcome.typing = IPAD2JB_NO_HOST;
    } else {
        CFMutableDictionaryRef keyboard_description = ipad2jb_keyboard_description(stock, selected);
        if (!keyboard_description || !save_stock(env->stock_path, stock)) {
            env->say("could not prepare the keyboard description");
        } else {
            outcome.typing = publish_and_type(env, keyboard_description, text);
            env->keyboard.close(env->keyboard.context);
            env->say("restoring normal USB");
            outcome.restore = restore_stock(env);
            env->say(restore_message(outcome.restore));
        }
        if (keyboard_description) CFRelease(keyboard_description);
    }
    CFRelease(stock);
    return outcome;
}
