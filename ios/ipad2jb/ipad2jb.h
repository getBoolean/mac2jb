// ipad2jb: make a jailbroken iPad type text as a USB keyboard on the host it is
// plugged into (tested: Nintendo Switch 2 and macOS), then restore normal USB.
//
// The run (core.c) only talks to the device through the two interfaces below,
// so it can be exercised with fakes (tests/test_core.c). iokit.c implements
// them with the iPad's USB device controller.
#ifndef IPAD2JB_H
#define IPAD2JB_H

#include <CoreFoundation/CoreFoundation.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IPAD2JB_REPORT_LENGTH 8
#define IPAD2JB_MAX_TEXT (1024 * 1024)

// --- pure helpers -----------------------------------------------------------

// US-layout boot-keyboard usage for printable ASCII and newline.
bool ipad2jb_keycode(char c, uint8_t *modifier, uint8_t *usage);
bool ipad2jb_text_is_typable(const char *text);

// Bytes to return for a class request on the keyboard interface. Host-to-device
// requests (SET_PROTOCOL, SET_IDLE, SET_REPORT) get a zero-length success;
// device-to-host requests get zeros, except GET_PROTOCOL which answers report
// protocol (1). Returns the reply length (at most `capacity` and 64).
size_t ipad2jb_class_reply(uint8_t request_type, uint8_t request, uint16_t length,
                           uint8_t *reply, size_t capacity);

// The stock description with ConfigurationDescriptors replaced by the
// host-selected configuration turned into Apple's single-configuration
// "Standard Keyboard" profile [AppleUSBMux, Keyboard]. NULL if `selected` is
// not a configuration of `stock`. Caller releases.
CFMutableDictionaryRef ipad2jb_keyboard_description(CFDictionaryRef stock, int selected);

// True for a description produced by ipad2jb_keyboard_description.
bool ipad2jb_is_keyboard_description(CFDictionaryRef description);

// Every function name used by any configuration of `description`. Caller releases.
CFSetRef ipad2jb_function_names(CFDictionaryRef description);

// --- device interfaces ------------------------------------------------------

typedef struct {
    void *context;
    // A copy of the live description without the AllowMultipleCreates flag.
    CFMutableDictionaryRef (*live_description)(void *context);
    // Publish `description` (the implementation adds AllowMultipleCreates).
    bool (*publish)(void *context, CFDictionaryRef description);
    // The configuration a host has selected, 0 if none.
    int (*selected_configuration)(void *context);
    // Every name in `functions` has a registered function interface.
    bool (*functions_registered)(void *context, CFSetRef functions);
} ipad2jb_usb;

typedef enum {
    IPAD2JB_SEND_OK,        // the host read the report
    IPAD2JB_SEND_TIMEOUT,   // the host did not poll within the write timeout
    IPAD2JB_SEND_FAILED,    // anything else: the host or the function went away
} ipad2jb_send_result;

typedef struct {
    void *context;
    // Open the Keyboard function, make it a boot keyboard and start answering
    // class requests. Returns false with `failed_step` naming the step.
    bool (*open)(void *context, const char **failed_step);
    // A host has selected a configuration containing the keyboard endpoint.
    bool (*host_selected)(void *context);
    ipad2jb_send_result (*send)(void *context, const uint8_t report[IPAD2JB_REPORT_LENGTH]);
    void (*close)(void *context);
} ipad2jb_keyboard;

typedef struct {
    bool turbo_typing;                         // experimental shorter key hold
    bool fast_typing;                          // shorter inter-key and Enter delays
    bool clear_autoindent;                     // clear inherited spaces after Enter
    ipad2jb_usb usb;
    ipad2jb_keyboard keyboard;
    const char *stock_path;                      // saved stock description
    void (*sleep_ms)(unsigned milliseconds);
    void (*say)(const char *message);
    volatile sig_atomic_t *interrupted;          // set by the signal handler
} ipad2jb_env;

// --- the run ----------------------------------------------------------------

typedef enum {
    IPAD2JB_TYPED,
    IPAD2JB_NO_HOST,             // no host had selected a configuration
    IPAD2JB_NOT_STOCK,           // live description is a leftover keyboard one
    IPAD2JB_PREPARE_FAILED,      // could not build or save the descriptions
    IPAD2JB_PUBLISH_FAILED,
    IPAD2JB_SETUP_FAILED,        // the keyboard function could not be set up
    IPAD2JB_NEVER_POLLED,        // the host never read the keyboard
    IPAD2JB_HOST_LOST,           // a report failed mid-typing
    IPAD2JB_INTERRUPTED,
    IPAD2JB_LEFTOVER_FAILED,     // an earlier run's stock description would not restore
} ipad2jb_typing;

typedef enum {
    IPAD2JB_RESTORED,            // stock functions registered and a host reselected
    IPAD2JB_RESTORED_NO_HOST,    // stock functions registered, no host reconnected
    IPAD2JB_RESTORE_FAILED,      // stock functions did not all register
    IPAD2JB_NOTHING_TO_RESTORE,  // nothing was published
} ipad2jb_restore;

typedef struct {
    ipad2jb_typing typing;
    ipad2jb_restore restore;
} ipad2jb_outcome;

ipad2jb_outcome ipad2jb_run(const ipad2jb_env *env, const char *text);

#endif
