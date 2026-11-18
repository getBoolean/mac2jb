// Host tests for ipad2jb's core: pure helpers, and the full run driven through
// fake USB controller and keyboard implementations. Run with ../test.sh.

#include "../ipad2jb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(condition, ...) do { if (!(condition)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

// --- fixtures -----------------------------------------------------------------

static CFArrayRef strings(int count, const char **values) {
    CFStringRef items[8];
    for (int i = 0; i < count; i++) items[i] = CFStringCreateWithCString(NULL, values[i], kCFStringEncodingUTF8);
    CFArrayRef array = CFArrayCreate(NULL, (const void **)items, count, &kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) CFRelease(items[i]);
    return array;
}

static CFMutableDictionaryRef configuration(const char *description, int count, const char **interfaces) {
    CFMutableDictionaryRef config = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                                              &kCFTypeDictionaryValueCallBacks);
    CFStringRef name = CFStringCreateWithCString(NULL, description, kCFStringEncodingUTF8);
    CFArrayRef names = strings(count, interfaces);
    int attributes = 0xC0, power = 500;
    CFNumberRef attributes_number = CFNumberCreate(NULL, kCFNumberIntType, &attributes);
    CFNumberRef power_number = CFNumberCreate(NULL, kCFNumberIntType, &power);
    CFDictionarySetValue(config, CFSTR("Description"), name);
    CFDictionarySetValue(config, CFSTR("Interfaces"), names);
    CFDictionarySetValue(config, CFSTR("Attributes"), attributes_number);
    CFDictionarySetValue(config, CFSTR("MaxPower"), power_number);
    CFRelease(name); CFRelease(names); CFRelease(attributes_number); CFRelease(power_number);
    return config;
}

// Three stock-like configurations; the host picks 1 (PTP) like the Switch 2.
static CFMutableDictionaryRef stock_description(void) {
    const char *ptp[] = { "PTP" };
    const char *ipod[] = { "USBAudioControl", "IapOverUsbHid" };
    const char *mux[] = { "PTP", "AppleUSBMux", "AppleUSBNCMData" };
    CFMutableDictionaryRef c1 = configuration("PTP", 1, ptp);
    CFMutableDictionaryRef c2 = configuration("iPod USB Interface", 2, ipod);
    CFMutableDictionaryRef c3 = configuration("PTP + Apple Mobile Device + NCM", 3, mux);
    CFDictionarySetValue(c2, CFSTR("AccessoryResistorSwap"), kCFBooleanTrue);
    CFDictionarySetValue(c3, CFSTR("ExtendedConfiguration"), kCFBooleanTrue);
    const void *configs[] = { c1, c2, c3 };
    CFArrayRef array = CFArrayCreate(NULL, configs, 3, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef description = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                                                   &kCFTypeDictionaryValueCallBacks);
    int vendor = 0x05ac;
    CFNumberRef vendor_number = CFNumberCreate(NULL, kCFNumberIntType, &vendor);
    CFDictionarySetValue(description, CFSTR("vendorID"), vendor_number);
    CFDictionarySetValue(description, CFSTR("ConfigurationDescriptors"), array);
    CFRelease(vendor_number); CFRelease(array); CFRelease(c1); CFRelease(c2); CFRelease(c3);
    return description;
}

// --- fakes --------------------------------------------------------------------

typedef struct {
    CFMutableDictionaryRef live;
    int selected;                 // what the host has selected right now
    int selected_after_restore;   // what the host selects after a stock publish
    int register_after_polls;     // polls before freshly published functions register
    int polls;
    int publishes, stock_publishes;
    bool refuse_publish;
} fake_usb;

static CFMutableDictionaryRef fake_live(void *context) {
    fake_usb *usb = context;
    return CFDictionaryCreateMutableCopy(NULL, 0, usb->live);
}

static bool fake_publish(void *context, CFDictionaryRef description) {
    fake_usb *usb = context;
    if (usb->refuse_publish) return false;
    usb->publishes++;
    CFRelease(usb->live);
    usb->live = CFDictionaryCreateMutableCopy(NULL, 0, description);
    usb->polls = 0;
    if (!ipad2jb_is_keyboard_description(description)) {
        usb->stock_publishes++;
        usb->selected = usb->selected_after_restore;
    }
    return true;
}

static int fake_selected(void *context) { return ((fake_usb *)context)->selected; }

static bool fake_registered(void *context, CFSetRef functions) {
    fake_usb *usb = context;
    (void)functions;
    return usb->polls++ >= usb->register_after_polls;
}

typedef struct {
    bool refuse_open;
    int host_selected_after;      // host_selected() calls before the host selects the keyboard
    int host_selected_calls;
    int timeouts_first;           // the first sends time out (host not polling yet)
    int fail_send_at;             // this send fails (host gone); -1 for never
    int interrupt_at_send;        // the signal arrives during this send; -1 for never
    volatile sig_atomic_t *interrupted;
    uint8_t sent[1024][IPAD2JB_REPORT_LENGTH];
    int sent_count;
    bool opened, closed;
} fake_keyboard;

static bool fake_open(void *context, const char **failed_step) {
    fake_keyboard *keyboard = context;
    *failed_step = "commit";
    keyboard->opened = !keyboard->refuse_open;
    return keyboard->opened;
}

static bool fake_host_selected(void *context) {
    fake_keyboard *keyboard = context;
    return keyboard->host_selected_calls++ >= keyboard->host_selected_after;
}

static ipad2jb_send_result fake_send(void *context, const uint8_t report[IPAD2JB_REPORT_LENGTH]) {
    fake_keyboard *keyboard = context;
    int index = keyboard->sent_count;
    if (index < 1024) memcpy(keyboard->sent[index], report, IPAD2JB_REPORT_LENGTH);
    keyboard->sent_count++;
    if (index == keyboard->interrupt_at_send) *keyboard->interrupted = 1;
    if (index < keyboard->timeouts_first) return IPAD2JB_SEND_TIMEOUT;
    if (index == keyboard->fail_send_at) return IPAD2JB_SEND_FAILED;
    return IPAD2JB_SEND_OK;
}

static void fake_close(void *context) { ((fake_keyboard *)context)->closed = true; }

static unsigned long slept_ms;
static void fake_sleep(unsigned milliseconds) { slept_ms += milliseconds; }
static void quiet(const char *message) { (void)message; }

typedef struct {
    fake_usb usb;
    fake_keyboard keyboard;
    volatile sig_atomic_t interrupted;
    char stock_path[256];
    ipad2jb_env env;
} harness;

static void harness_init(harness *h) {
    memset(h, 0, sizeof(*h));
    h->usb.live = stock_description();
    h->usb.selected = 1;
    h->usb.selected_after_restore = 1;
    h->keyboard.fail_send_at = -1;
    h->keyboard.interrupt_at_send = -1;
    h->keyboard.interrupted = &h->interrupted;
    char directory[] = "/tmp/ipad2jb-test-XXXXXX";
    snprintf(h->stock_path, sizeof(h->stock_path), "%s/state/stock.plist", mkdtemp(directory));
    h->env = (ipad2jb_env){
        .usb = { &h->usb, fake_live, fake_publish, fake_selected, fake_registered },
        .keyboard = { &h->keyboard, fake_open, fake_host_selected, fake_send, fake_close },
        .stock_path = h->stock_path, .sleep_ms = fake_sleep, .say = quiet, .interrupted = &h->interrupted,
    };
    slept_ms = 0;
}

static void harness_free(harness *h) { CFRelease(h->usb.live); unlink(h->stock_path); }

// The non-neutral reports, decoded back to text.
static void typed_text(const fake_keyboard *keyboard, char *out, size_t capacity) {
    size_t length = 0;
    for (int i = 0; i < keyboard->sent_count && i < 1024 && length + 1 < capacity; i++) {
        const uint8_t *r = keyboard->sent[i];
        if (r[2] == 0) continue;
        char c = '?';
        if (r[2] >= 0x04 && r[2] <= 0x1D) c = (char)((r[0] & 0x02 ? 'A' : 'a') + r[2] - 0x04);
        else if (r[2] >= 0x1E && r[2] <= 0x26) c = (char)('1' + r[2] - 0x1E);
        else if (r[2] == 0x27) c = '0';
        else if (r[2] == 0x2C) c = ' ';
        out[length++] = c;
    }
    out[length] = '\0';
}

static bool file_exists(const char *path) { return access(path, F_OK) == 0; }

// --- pure helpers -------------------------------------------------------------

static void test_keycodes(void) {
    uint8_t modifier, usage;
    CHECK(ipad2jb_keycode('a', &modifier, &usage) && usage == 0x04 && modifier == 0, "a");
    CHECK(ipad2jb_keycode('z', &modifier, &usage) && usage == 0x1D, "z");
    CHECK(ipad2jb_keycode('J', &modifier, &usage) && usage == 0x0D && modifier == 0x02, "J with shift");
    CHECK(ipad2jb_keycode('1', &modifier, &usage) && usage == 0x1E, "1");
    CHECK(ipad2jb_keycode('0', &modifier, &usage) && usage == 0x27, "0");
    CHECK(ipad2jb_keycode(' ', &modifier, &usage) && usage == 0x2C, "space");
    CHECK(!ipad2jb_keycode('-', &modifier, &usage), "punctuation refused");
    CHECK(ipad2jb_text_is_typable("ipad2jb") && ipad2jb_text_is_typable("Hello World 42"), "typable");
    CHECK(!ipad2jb_text_is_typable("") && !ipad2jb_text_is_typable("a-b"), "untypable");
}

static void test_class_replies(void) {
    uint8_t reply[128];
    memset(reply, 0xAA, sizeof(reply));
    CHECK(ipad2jb_class_reply(0x21, 0x0B, 0, reply, sizeof(reply)) == 0, "SET_PROTOCOL is a zero-length success");
    CHECK(ipad2jb_class_reply(0x21, 0x09, 1, reply, sizeof(reply)) == 0, "SET_REPORT (LEDs) is a zero-length success");
    CHECK(ipad2jb_class_reply(0xA1, 0x03, 1, reply, sizeof(reply)) == 1 && reply[0] == 1, "GET_PROTOCOL answers report protocol");
    memset(reply, 0xAA, sizeof(reply));
    CHECK(ipad2jb_class_reply(0xA1, 0x01, 8, reply, sizeof(reply)) == 8, "GET_REPORT returns 8 bytes");
    bool zeros = true;
    for (int i = 0; i < 8; i++) zeros = zeros && reply[i] == 0;
    CHECK(zeros && reply[8] == 0xAA, "GET_REPORT is all keys up and writes nothing past its length");
    CHECK(ipad2jb_class_reply(0xA1, 0x01, 500, reply, sizeof(reply)) == 64, "replies are capped at 64 bytes");
    CHECK(ipad2jb_class_reply(0xA1, 0x01, 500, reply, 16) == 16, "replies are capped at the buffer size");
}

static void test_keyboard_description(void) {
    CFMutableDictionaryRef stock = stock_description();
    CFMutableDictionaryRef keyboard = ipad2jb_keyboard_description(stock, 3);
    CHECK(keyboard != NULL, "configuration 3 builds");
    CFArrayRef configs = CFDictionaryGetValue(keyboard, CFSTR("ConfigurationDescriptors"));
    CHECK(CFArrayGetCount(configs) == 1, "exactly one configuration");
    CFDictionaryRef only = CFArrayGetValueAtIndex(configs, 0);
    CFArrayRef names = CFDictionaryGetValue(only, CFSTR("Interfaces"));
    CHECK(CFArrayGetCount(names) == 2 && CFEqual(CFArrayGetValueAtIndex(names, 0), CFSTR("AppleUSBMux")) &&
          CFEqual(CFArrayGetValueAtIndex(names, 1), CFSTR("Keyboard")), "interfaces are [AppleUSBMux, Keyboard]");
    CHECK(CFEqual(CFDictionaryGetValue(only, CFSTR("Description")), CFSTR("Standard Keyboard")), "description");
    CHECK(CFDictionaryGetValue(only, CFSTR("DefaultConfiguration")) == kCFBooleanTrue, "default configuration");
    CHECK(!CFDictionaryContainsKey(only, CFSTR("ExtendedConfiguration")), "stock-only keys dropped");
    CHECK(CFDictionaryContainsKey(only, CFSTR("MaxPower")) && CFDictionaryContainsKey(only, CFSTR("Attributes")),
          "power and attributes kept from the selected configuration");
    CHECK(CFDictionaryContainsKey(keyboard, CFSTR("vendorID")), "device fields kept");
    CHECK(ipad2jb_is_keyboard_description(keyboard) && !ipad2jb_is_keyboard_description(stock), "detected");
    CHECK(ipad2jb_keyboard_description(stock, 0) == NULL && ipad2jb_keyboard_description(stock, 4) == NULL,
          "out-of-range configuration refused");
    CFSetRef functions = ipad2jb_function_names(stock);
    CHECK(CFSetGetCount(functions) == 5 && CFSetContainsValue(functions, CFSTR("IapOverUsbHid")),
          "function names across every configuration, deduplicated");
    CFRelease(functions); CFRelease(keyboard); CFRelease(stock);
}

// --- the run ------------------------------------------------------------------

static void test_types_and_restores(void) {
    harness h; harness_init(&h);
    h.keyboard.timeouts_first = 3;   // the host takes a moment to start polling
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "Hi 2");
    char typed[64]; typed_text(&h.keyboard, typed, sizeof(typed));
    CHECK(outcome.typing == IPAD2JB_TYPED, "typed (got %d)", outcome.typing);
    CHECK(outcome.restore == IPAD2JB_RESTORED, "restored (got %d)", outcome.restore);
    CHECK(strcmp(typed, "Hi 2") == 0, "typed text was '%s'", typed);
    CHECK(h.usb.publishes == 2 && h.usb.stock_publishes == 1, "keyboard then stock published once each");
    CHECK(!ipad2jb_is_keyboard_description(h.usb.live), "stock is live again");
    CHECK(!file_exists(h.stock_path), "saved stock removed after restoring");
    CHECK(h.keyboard.closed, "keyboard closed");
    harness_free(&h);
}

static void test_interrupt_during_typing(void) {
    harness h; harness_init(&h);
    h.keyboard.interrupt_at_send = 110;  // after the settle period, mid-text
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "abcdefghij");
    CHECK(outcome.typing == IPAD2JB_INTERRUPTED, "interrupted is not reported as typed (got %d)", outcome.typing);
    CHECK(outcome.restore == IPAD2JB_RESTORED, "still restored (got %d)", outcome.restore);
    harness_free(&h);
}

static void test_no_host(void) {
    harness h; harness_init(&h);
    h.usb.selected = 0;
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ipad2jb");
    CHECK(outcome.typing == IPAD2JB_NO_HOST && outcome.restore == IPAD2JB_NOTHING_TO_RESTORE, "no host");
    CHECK(h.usb.publishes == 0 && !file_exists(h.stock_path), "nothing published or saved");
    harness_free(&h);
}

static void test_leftover_keyboard_description(void) {
    harness h; harness_init(&h);
    CFMutableDictionaryRef keyboard = ipad2jb_keyboard_description(h.usb.live, 1);
    CFRelease(h.usb.live); h.usb.live = keyboard;
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ipad2jb");
    CHECK(outcome.typing == IPAD2JB_NOT_STOCK && h.usb.publishes == 0, "refuses to save a keyboard description as stock");
    harness_free(&h);
}

static void test_never_polled(void) {
    harness h; harness_init(&h);
    h.keyboard.host_selected_after = 1 << 30;
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ipad2jb");
    CHECK(outcome.typing == IPAD2JB_NEVER_POLLED, "never polled (got %d)", outcome.typing);
    CHECK(outcome.restore == IPAD2JB_RESTORED, "restored anyway");
    harness_free(&h);
}

static void test_host_lost_mid_typing(void) {
    harness h; harness_init(&h);
    h.keyboard.fail_send_at = 105;
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "abcdefghij");
    CHECK(outcome.typing == IPAD2JB_HOST_LOST, "host lost (got %d)", outcome.typing);
    CHECK(outcome.restore == IPAD2JB_RESTORED, "restored anyway");
    harness_free(&h);
}

static void test_setup_failure_restores(void) {
    harness h; harness_init(&h);
    h.keyboard.refuse_open = true;
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ipad2jb");
    CHECK(outcome.typing == IPAD2JB_SETUP_FAILED && outcome.restore == IPAD2JB_RESTORED, "setup failure restores");
    harness_free(&h);
}

static void test_restore_without_host_is_quick(void) {
    harness h; harness_init(&h);
    h.usb.selected_after_restore = 0;   // cable pulled before the restore
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ipad2jb");
    CHECK(outcome.typing == IPAD2JB_TYPED, "typed");
    CHECK(outcome.restore == IPAD2JB_RESTORED_NO_HOST, "restored without a host (got %d)", outcome.restore);
    CHECK(h.usb.stock_publishes == 1, "stock published once, not retried (got %d)", h.usb.stock_publishes);
    CHECK(!file_exists(h.stock_path), "saved stock removed once the functions are back");
    harness_free(&h);
}

static void test_restore_retries_stranded_functions(void) {
    harness h; harness_init(&h);
    h.usb.register_after_polls = 1 << 30;   // functions never register
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ipad2jb");
    CHECK(outcome.restore == IPAD2JB_RESTORE_FAILED, "restore failure reported (got %d)", outcome.restore);
    CHECK(h.usb.stock_publishes == 4, "stock republished 4 times (got %d)", h.usb.stock_publishes);
    CHECK(file_exists(h.stock_path), "saved stock kept for the next run");
    harness_free(&h);
}

static void test_leftover_is_restored_first(void) {
    harness h; harness_init(&h);
    // A previous run saved the stock description and died with the keyboard published.
    h.usb.register_after_polls = 1 << 30;
    ipad2jb_run(&h.env, "ipad2jb");
    CHECK(file_exists(h.stock_path), "precondition: leftover saved stock");
    h.usb.register_after_polls = 0;
    h.usb.stock_publishes = 0;
    h.keyboard.sent_count = 0;
    ipad2jb_outcome outcome = ipad2jb_run(&h.env, "ab");
    char typed[16]; typed_text(&h.keyboard, typed, sizeof(typed));
    CHECK(outcome.typing == IPAD2JB_TYPED && strcmp(typed, "ab") == 0, "typed after restoring the leftover");
    CHECK(h.usb.stock_publishes == 2, "leftover restored, then restored again after typing (got %d)",
          h.usb.stock_publishes);
    harness_free(&h);
}

int main(void) {
    test_keycodes();
    test_class_replies();
    test_keyboard_description();
    test_types_and_restores();
    test_interrupt_during_typing();
    test_no_host();
    test_leftover_keyboard_description();
    test_never_polled();
    test_host_lost_mid_typing();
    test_setup_failure_restores();
    test_restore_without_host_is_quick();
    test_restore_retries_stranded_functions();
    test_leftover_is_restored_first();
    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("ipad2jb core tests passed\n");
    return 0;
}
