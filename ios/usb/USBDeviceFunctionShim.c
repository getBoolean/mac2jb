#include "USBDeviceFunctionShim.h"
#include "USBFunctionName.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ANCESTORS 16     /* a gadget interface sits a few levels under its controller */
#define MAX_DESCRIPTOR 4096  /* a HID report descriptor is far smaller than this */

// Resolved from IOKit at open time in the same style the restore shim uses, so
// a build whose IOKit lacks one of them reports MAC2JBUSBFunctionMissingAPI
// instead of failing to link.
typedef kern_return_t (*ConnectScalar)(mach_port_t, uint32_t, const uint64_t *,
                                       uint32_t, uint64_t *, uint32_t *);
typedef kern_return_t (*ConnectMethod)(mach_port_t, uint32_t, const uint64_t *,
                                       uint32_t, const void *, size_t,
                                       uint64_t *, uint32_t *, void *, size_t *);
typedef kern_return_t (*ConnectAsyncScalar)(mach_port_t, uint32_t, mach_port_t,
                                            uint64_t *, uint32_t,
                                            const uint64_t *, uint32_t,
                                            uint64_t *, uint32_t *);

struct MAC2JBUSBFunctionSession {
    io_connect_t connection;
    uint64_t controllerRegistryID;
    void *iokit;
    ConnectScalar callScalar;
    ConnectMethod callMethod;
    ConnectAsyncScalar callAsyncScalar;
    MAC2JBUSBFunctionLedger ledger;
};

MAC2JBUSBFunctionResult MAC2JBUSBFunctionValidateName(const char *name) {
    return mac2jb_usb_function_name_is_legal(name)
        ? MAC2JBUSBFunctionSuccess : MAC2JBUSBFunctionInvalidInput;
}

bool MAC2JBUSBFunctionNameMatches(const char *property, const char *wanted) {
    // Both sides must be legal names of equal length and equal bytes. Length
    // equality is what rejects a prefix, a suffix and a value truncated at an
    // embedded NUL; the byte compare is case-sensitive, so a case variant of
    // the published name is a different function.
    if (MAC2JBUSBFunctionValidateName(property) != MAC2JBUSBFunctionSuccess) return false;
    if (MAC2JBUSBFunctionValidateName(wanted) != MAC2JBUSBFunctionSuccess) return false;
    size_t length = strnlen(wanted, MAC2JB_USB_FUNCTION_NAME_MAX + 1);
    if (strnlen(property, MAC2JB_USB_FUNCTION_NAME_MAX + 1) != length) return false;
    return memcmp(property, wanted, length) == 0;
}

void MAC2JBUSBFunctionLedgerInit(MAC2JBUSBFunctionLedger *ledger) {
    if (!ledger) return;
    ledger->attempted = 0;
    ledger->refused = 0;
    ledger->abortedBy = MAC2JBUSBFunctionOperationNone;
    for (int index = 0; index < MAC2JBUSBFunctionOperationCount; index++) {
        ledger->attempts[index] = 0;
        ledger->calls[index] = MAC2JBUSBFunctionCallNotAttempted;
    }
}

bool MAC2JBUSBFunctionOperationIsRepeatable(MAC2JBUSBFunctionOperation operation) {
    return operation == MAC2JBUSBFunctionOperationWritePipe ||
        operation == MAC2JBUSBFunctionOperationPipeMaxPacketSize;
}

void MAC2JBUSBFunctionSplitScalarResult(
    int32_t rawReturn, const uint64_t *output, uint32_t outputCount,
    uint64_t *value
) {
    if (!value) return;
    *value = (rawReturn == 0 && output && outputCount >= 1) ? output[0] : 0;
}

// The interface open is the gate for everything else, and it is derivable
// from the ledger rather than tracked twice: attempted and not refused.
static bool interface_is_open(const MAC2JBUSBFunctionLedger *ledger) {
    uint32_t bit = 1u << (uint32_t)MAC2JBUSBFunctionOperationInterfaceOpen;
    return (ledger->attempted & bit) && !(ledger->refused & bit);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionLedgerBegin(
    MAC2JBUSBFunctionLedger *ledger, MAC2JBUSBFunctionOperation operation
) {
    if (!ledger || operation >= MAC2JBUSBFunctionOperationCount)
        return MAC2JBUSBFunctionInvalidInput;
    uint32_t bit = 1u << (uint32_t)operation;
    // A transmit operation runs once per report, so only the configuration
    // cells are spent by a single attempt.
    if ((ledger->attempted & bit) &&
        !MAC2JBUSBFunctionOperationIsRepeatable(operation))
        return MAC2JBUSBFunctionAlreadyAttempted;
    // A half-configured interface must not be configured further, so the first
    // refusal closes the session to every later operation, transmit included.
    if (ledger->abortedBy != MAC2JBUSBFunctionOperationNone)
        return MAC2JBUSBFunctionOperationRefused;
    // Order is enforced here, not left to the caller's call order: nothing but
    // the interface open may run before that open has succeeded, so a refused
    // configuration selector can never be an unopened interface in disguise.
    if (operation != MAC2JBUSBFunctionOperationInterfaceOpen &&
        !interface_is_open(ledger))
        return MAC2JBUSBFunctionInterfaceNotOpen;
    ledger->attempted |= bit;
    if (ledger->attempts[operation] < UINT32_MAX) ledger->attempts[operation]++;
    return MAC2JBUSBFunctionSuccess;
}

void MAC2JBUSBFunctionLedgerRecord(
    MAC2JBUSBFunctionLedger *ledger, MAC2JBUSBFunctionOperation operation,
    int32_t rawReturn
) {
    if (!ledger || operation >= MAC2JBUSBFunctionOperationCount) return;
    ledger->calls[operation] = rawReturn;
    if (rawReturn == 0) return;
    ledger->refused |= 1u << (uint32_t)operation;
    // A transient transfer failure is not a refused configuration selector, so
    // a repeatable operation never closes the session; the caller decides
    // whether to send the next report.
    if (MAC2JBUSBFunctionOperationIsRepeatable(operation)) return;
    if (ledger->abortedBy == MAC2JBUSBFunctionOperationNone)
        ledger->abortedBy = (uint8_t)operation;
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionCopyLedger(
    const MAC2JBUSBFunctionSession *session, MAC2JBUSBFunctionLedger *ledger
) {
    if (!session || !ledger) return MAC2JBUSBFunctionInvalidInput;
    *ledger = session->ledger;
    return MAC2JBUSBFunctionSuccess;
}

// Walk the service plane up from a matched interface to its controller and
// require that exact registry entry ID. A function of the same name under
// another controller is not ours.
static bool on_expected_controller(io_service_t service, uint64_t expected) {
    io_registry_entry_t entry = service;
    bool owned = false;  // The first entry is the caller's; later ones are ours.
    bool matched = false;
    for (int level = 0; level < MAX_ANCESTORS; level++) {
        io_registry_entry_t parent = IO_OBJECT_NULL;
        if (IORegistryEntryGetParentEntry(entry, kIOServicePlane, &parent) !=
            kIOReturnSuccess || parent == IO_OBJECT_NULL) goto done;
        if (owned) IOObjectRelease(entry);
        entry = parent;
        owned = true;
        if (!IOObjectConformsTo(entry, "IOUSBDeviceController")) continue;
        uint64_t registryID = 0;
        matched = IORegistryEntryGetRegistryEntryID(entry, &registryID) ==
            kIOReturnSuccess && registryID == expected;
        goto done;
    }
done:
    if (owned) IOObjectRelease(entry);
    return matched;
}

static bool function_name_of(io_registry_entry_t entry, char *out, size_t size) {
    out[0] = 0;
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        entry, CFSTR("USBDeviceFunction"), kCFAllocatorDefault, 0);
    if (!value) return false;
    bool copied = false;
    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        CFStringRef string = (CFStringRef)value;
        // Reject anything that would not survive the copy intact, so a
        // truncated or multi-byte value can never pass as an exact match.
        copied = CFStringGetLength(string) < (CFIndex)size &&
            CFStringGetCString(string, out, (CFIndex)size, kCFStringEncodingUTF8) &&
            CFStringGetLength(string) == (CFIndex)strnlen(out, size);
    }
    CFRelease(value);
    return copied;
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionOpen(
    uint64_t expectedControllerRegistryID,
    const char *functionName,
    uint32_t userClientType,
    MAC2JBUSBFunctionSession **session,
    int32_t *matchReturn,
    int32_t *openReturn
) {
    if (matchReturn) *matchReturn = MAC2JBUSBFunctionCallNotAttempted;
    if (openReturn) *openReturn = MAC2JBUSBFunctionCallNotAttempted;
    if (session) *session = NULL;
    if (!session || expectedControllerRegistryID == 0 ||
        MAC2JBUSBFunctionValidateName(functionName) != MAC2JBUSBFunctionSuccess)
        return MAC2JBUSBFunctionInvalidInput;

    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                          RTLD_NOW | RTLD_LOCAL);
    if (!handle) return MAC2JBUSBFunctionMissingAPI;
    MAC2JBUSBFunctionResult result = MAC2JBUSBFunctionServiceAbsent;
    ConnectScalar callScalar = (ConnectScalar)dlsym(handle, "IOConnectCallScalarMethod");
    ConnectMethod callMethod = (ConnectMethod)dlsym(handle, "IOConnectCallMethod");
    ConnectAsyncScalar callAsyncScalar =
        (ConnectAsyncScalar)dlsym(handle, "IOConnectCallAsyncScalarMethod");
    if (!callScalar || !callMethod || !callAsyncScalar) {
        result = MAC2JBUSBFunctionMissingAPI;
        goto close_handle;
    }

    // Narrow with the same IOPropertyMatch the reference uses, then confirm the
    // name ourselves: the match semantics are the kernel's, the exactness is
    // ours.
    CFStringRef wanted = CFStringCreateWithCString(kCFAllocatorDefault, functionName,
                                                   kCFStringEncodingUTF8);
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBDeviceInterface");
    CFMutableDictionaryRef property = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (!wanted || !matching || !property) {
        if (wanted) CFRelease(wanted);
        if (matching) CFRelease(matching);
        if (property) CFRelease(property);
        result = MAC2JBUSBFunctionControllerUnavailable;
        goto close_handle;
    }
    CFDictionarySetValue(property, CFSTR("USBDeviceFunction"), wanted);
    CFDictionarySetValue(matching, CFSTR("IOPropertyMatch"), property);
    CFRelease(property);
    CFRelease(wanted);

    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn matchStatus = IOServiceGetMatchingServices(kIOMainPortDefault, matching,
                                                        &iterator);
    if (matchReturn) *matchReturn = matchStatus;
    if (matchStatus != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        result = MAC2JBUSBFunctionControllerUnavailable;
        goto close_handle;
    }

    io_service_t chosen = IO_OBJECT_NULL;
    bool sawName = false;
    io_service_t candidate;
    while ((candidate = IOIteratorNext(iterator))) {
        char name[MAC2JB_USB_FUNCTION_NAME_MAX + 2];
        if (function_name_of(candidate, name, sizeof(name)) &&
            MAC2JBUSBFunctionNameMatches(name, functionName)) {
            sawName = true;
            if (chosen == IO_OBJECT_NULL &&
                on_expected_controller(candidate, expectedControllerRegistryID)) {
                chosen = candidate;
                continue;  // Kept, released below.
            }
        }
        IOObjectRelease(candidate);
    }
    IOObjectRelease(iterator);
    if (chosen == IO_OBJECT_NULL) {
        // The name appearing under a different controller is a different
        // failure from the name never appearing at all.
        result = sawName ? MAC2JBUSBFunctionWrongController
                         : MAC2JBUSBFunctionServiceAbsent;
        goto close_handle;
    }

    // One attempt. The reference sleeps and retries; here the caller sees the
    // first real answer and decides whether to try again.
    io_connect_t connection = IO_OBJECT_NULL;
    IOReturn openStatus = IOServiceOpen(chosen, mach_task_self(), userClientType,
                                        &connection);
    if (openReturn) *openReturn = openStatus;
    IOObjectRelease(chosen);
    if (openStatus != kIOReturnSuccess || connection == IO_OBJECT_NULL) {
        if (connection != IO_OBJECT_NULL) IOServiceClose(connection);
        result = MAC2JBUSBFunctionOpenDenied;
        goto close_handle;
    }

    MAC2JBUSBFunctionSession *opened = calloc(1, sizeof(*opened));
    if (!opened) {
        IOServiceClose(connection);
        result = MAC2JBUSBFunctionInvalidInput;
        goto close_handle;
    }
    opened->connection = connection;
    opened->controllerRegistryID = expectedControllerRegistryID;
    opened->iokit = handle;  // Held for the session: the call pointers live in it.
    opened->callScalar = callScalar;
    opened->callMethod = callMethod;
    opened->callAsyncScalar = callAsyncScalar;
    MAC2JBUSBFunctionLedgerInit(&opened->ledger);
    *session = opened;
    return MAC2JBUSBFunctionSuccess;

close_handle:
    dlclose(handle);
    return result;
}

void MAC2JBUSBFunctionClose(MAC2JBUSBFunctionSession *session) {
    if (!session) return;
    if (session->connection != IO_OBJECT_NULL) IOServiceClose(session->connection);
    if (session->iokit) dlclose(session->iokit);
    free(session);
}

// Shared preamble: validate, consult the ledger, and leave the raw return at
// "not attempted" until the call is actually placed.
static MAC2JBUSBFunctionResult begin(
    MAC2JBUSBFunctionSession *session, MAC2JBUSBFunctionOperation operation,
    int32_t *callReturn
) {
    if (callReturn) *callReturn = MAC2JBUSBFunctionCallNotAttempted;
    if (!session || !callReturn) return MAC2JBUSBFunctionInvalidInput;
    return MAC2JBUSBFunctionLedgerBegin(&session->ledger, operation);
}

static MAC2JBUSBFunctionResult finish(
    MAC2JBUSBFunctionSession *session, MAC2JBUSBFunctionOperation operation,
    kern_return_t status, int32_t *callReturn
) {
    *callReturn = (int32_t)status;
    MAC2JBUSBFunctionLedgerRecord(&session->ledger, operation, (int32_t)status);
    return status == KERN_SUCCESS ? MAC2JBUSBFunctionSuccess
                                  : MAC2JBUSBFunctionOperationRefused;
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionInterfaceOpen(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint64_t argument, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(
        session, MAC2JBUSBFunctionOperationInterfaceOpen, callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    uint64_t arguments[1] = { argument };
    return finish(session, MAC2JBUSBFunctionOperationInterfaceOpen,
                  session->callScalar(session->connection, selector, arguments, 1,
                                      NULL, NULL),
                  callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionInterfaceClose(
    MAC2JBUSBFunctionSession *session, uint32_t selector, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(
        session, MAC2JBUSBFunctionOperationInterfaceClose, callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    return finish(session, MAC2JBUSBFunctionOperationInterfaceClose,
                  session->callScalar(session->connection, selector, NULL, 0,
                                      NULL, NULL),
                  callReturn);
}

// The three one-byte setters share the reference's argument shape: the value
// then the configuration identifier.
static MAC2JBUSBFunctionResult set_byte(
    MAC2JBUSBFunctionSession *session, MAC2JBUSBFunctionOperation operation,
    uint32_t selector, uint8_t value, uint64_t configurationID, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(session, operation, callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    uint64_t arguments[2] = { value, configurationID };
    return finish(session, operation,
                  session->callScalar(session->connection, selector, arguments, 2,
                                      NULL, NULL),
                  callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetClass(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t value, uint64_t configurationID, int32_t *callReturn
) {
    return set_byte(session, MAC2JBUSBFunctionOperationSetClass, selector, value,
                    configurationID, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetSubClass(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t value, uint64_t configurationID, int32_t *callReturn
) {
    return set_byte(session, MAC2JBUSBFunctionOperationSetSubClass, selector, value,
                    configurationID, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetProtocol(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t value, uint64_t configurationID, int32_t *callReturn
) {
    return set_byte(session, MAC2JBUSBFunctionOperationSetProtocol, selector, value,
                    configurationID, callReturn);
}

// Both descriptor appends pass two scalars and the descriptor as a struct input.
static MAC2JBUSBFunctionResult append_descriptor(
    MAC2JBUSBFunctionSession *session, MAC2JBUSBFunctionOperation operation,
    uint32_t selector, uint8_t descriptorType, uint8_t secondArgument,
    const uint8_t *descriptor, size_t length, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(session, operation, callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    if (!descriptor || length == 0 || length > MAX_DESCRIPTOR) {
        // The attempt is spent either way; record the rejection as ours.
        return MAC2JBUSBFunctionInvalidInput;
    }
    uint64_t arguments[2] = { descriptorType, secondArgument };
    return finish(session, operation,
                  session->callMethod(session->connection, selector, arguments, 2,
                                      descriptor, length, NULL, NULL, NULL, NULL),
                  callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionAppendStandardDescriptor(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t descriptorType, uint8_t secondArgument,
    const uint8_t *descriptor, size_t length, int32_t *callReturn
) {
    return append_descriptor(session, MAC2JBUSBFunctionOperationAppendStandardDescriptor,
                             selector, descriptorType, secondArgument, descriptor,
                             length, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionAppendNonstandardDescriptor(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t descriptorType, uint8_t secondArgument,
    const uint8_t *descriptor, size_t length, int32_t *callReturn
) {
    return append_descriptor(session,
                             MAC2JBUSBFunctionOperationAppendNonstandardDescriptor,
                             selector, descriptorType, secondArgument, descriptor,
                             length, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetClassCommandCallbacks(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint32_t notificationPort, const uint64_t *asyncReference,
    uint32_t asyncReferenceCount,
    bool flagA, bool flagB, bool flagC, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(
        session, MAC2JBUSBFunctionOperationSetClassCommandCallbacks, callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    if (!asyncReference || asyncReferenceCount == 0 ||
        asyncReferenceCount > kOSAsyncRef64Count)
        return MAC2JBUSBFunctionInvalidInput;
    // IOKit takes the reference block mutably; copy so the caller's block is
    // not rewritten under it.
    uint64_t reference[kOSAsyncRef64Count];
    memcpy(reference, asyncReference, asyncReferenceCount * sizeof(uint64_t));
    uint64_t arguments[3] = { flagA, flagB, flagC };
    return finish(session, MAC2JBUSBFunctionOperationSetClassCommandCallbacks,
                  session->callAsyncScalar(session->connection, selector,
                                           (mach_port_t)notificationPort, reference,
                                           asyncReferenceCount, arguments, 3,
                                           NULL, NULL),
                  callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionCreatePipe(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t type, uint8_t direction, uint32_t maxPacketSize, uint8_t interval,
    uint64_t unknownArgument, uint64_t configurationID,
    uint64_t *pipeID, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(session, MAC2JBUSBFunctionOperationCreatePipe,
                                         callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    if (!pipeID) return MAC2JBUSBFunctionInvalidInput;
    *pipeID = 0;
    uint64_t arguments[6] = { type, direction, maxPacketSize, interval,
                              unknownArgument, configurationID };
    uint64_t output[1] = { 0 };
    uint32_t outputCount = 1;
    kern_return_t status = session->callScalar(session->connection, selector,
                                               arguments, 6, output, &outputCount);
    MAC2JBUSBFunctionSplitScalarResult((int32_t)status, output, outputCount, pipeID);
    return finish(session, MAC2JBUSBFunctionOperationCreatePipe, status, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionCommit(
    MAC2JBUSBFunctionSession *session, uint32_t selector, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(session, MAC2JBUSBFunctionOperationCommit,
                                         callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    return finish(session, MAC2JBUSBFunctionOperationCommit,
                  session->callScalar(session->connection, selector, NULL, 0,
                                      NULL, NULL),
                  callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionCreateBuffer(
    MAC2JBUSBFunctionSession *session, uint32_t selector, uint32_t size,
    uint64_t *address, uint64_t *bufferSize, uint64_t *token, int32_t *callReturn
) {
    MAC2JBUSBFunctionResult gate = begin(session, MAC2JBUSBFunctionOperationCreateBuffer,
                                         callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    if (!address || !bufferSize || !token || size == 0)
        return MAC2JBUSBFunctionInvalidInput;
    *address = 0;
    *bufferSize = 0;
    *token = 0;
    uint64_t arguments[1] = { size };
    uint64_t output[3] = { 0, 0, 0 };
    uint32_t outputCount = 3;
    kern_return_t status = session->callScalar(session->connection, selector,
                                               arguments, 1, output, &outputCount);
    if (status == KERN_SUCCESS && outputCount == 3) {
        *address = output[0];
        *bufferSize = output[1];
        *token = output[2];
    }
    return finish(session, MAC2JBUSBFunctionOperationCreateBuffer, status, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionWritePipe(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint64_t pipeID, uint64_t bufferToken, uint64_t length,
    uint64_t timeoutMilliseconds, uint64_t *transferred, int32_t *callReturn
) {
    if (transferred) *transferred = 0;
    MAC2JBUSBFunctionResult gate = begin(session, MAC2JBUSBFunctionOperationWritePipe,
                                         callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    // The report bytes are already in the mapped buffer: the caller staged
    // them there and hands over the token, so a kernel refusal here cannot be
    // mistaken for a bad copy.
    if (!transferred || length == 0) return MAC2JBUSBFunctionInvalidInput;
    uint64_t arguments[4] = { pipeID, bufferToken, length, timeoutMilliseconds };
    uint64_t output[1] = { 0 };
    uint32_t outputCount = 1;
    kern_return_t status = session->callScalar(session->connection, selector,
                                               arguments, 4, output, &outputCount);
    // Separate storage: the raw return goes to callReturn, the byte count to
    // transferred, and the caller compares the count against length.
    MAC2JBUSBFunctionSplitScalarResult((int32_t)status, output, outputCount,
                                       transferred);
    return finish(session, MAC2JBUSBFunctionOperationWritePipe, status, callReturn);
}

MAC2JBUSBFunctionResult MAC2JBUSBFunctionPipeMaxPacketSize(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint64_t pipeID, uint64_t *maxPacketSize, int32_t *callReturn
) {
    if (maxPacketSize) *maxPacketSize = 0;
    MAC2JBUSBFunctionResult gate = begin(
        session, MAC2JBUSBFunctionOperationPipeMaxPacketSize, callReturn);
    if (gate != MAC2JBUSBFunctionSuccess) return gate;
    if (!maxPacketSize) return MAC2JBUSBFunctionInvalidInput;
    uint64_t arguments[1] = { pipeID };
    uint64_t output[1] = { 0 };
    uint32_t outputCount = 1;
    kern_return_t status = session->callScalar(session->connection, selector,
                                               arguments, 1, output, &outputCount);
    MAC2JBUSBFunctionSplitScalarResult((int32_t)status, output, outputCount,
                                       maxPacketSize);
    return finish(session, MAC2JBUSBFunctionOperationPipeMaxPacketSize, status,
                  callReturn);
}
