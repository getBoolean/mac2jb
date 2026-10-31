#ifndef MAC2JB_USB_DEVICE_FUNCTION_SHIM_H
#define MAC2JB_USB_DEVICE_FUNCTION_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Finds one named gadget function interface under an exact controller and
// configures it through its user client. Nothing here publishes a device
// description: a broker adds the function name first, and this code only
// discovers and configures what the kernel materialized for that name.
//
// The header stays free of IOKit types so Swift can import it through the
// module map; the session is opaque and carries the Mach connection.
//
// Every selector number, user client type and argument shape below comes from
// reading the macOS libusbd backend. They are observations of that build, not
// constants this build guarantees: each entry takes the selector as a caller
// parameter so a probe can try a neighbouring number, and each records the raw
// IOReturn verbatim so an unsupported selector is visible rather than guessed.

typedef struct MAC2JBUSBFunctionSession MAC2JBUSBFunctionSession;

typedef enum {
    MAC2JBUSBFunctionSuccess = 0,
    MAC2JBUSBFunctionInvalidInput = 1,
    MAC2JBUSBFunctionMissingAPI = 2,
    MAC2JBUSBFunctionControllerUnavailable = 3,
    MAC2JBUSBFunctionWrongController = 4,
    MAC2JBUSBFunctionServiceAbsent = 5,   /* no interface with that name appeared */
    MAC2JBUSBFunctionOpenDenied = 6,      /* the service exists; the open was refused */
    MAC2JBUSBFunctionOperationRefused = 7,/* a configuration selector was refused */
    MAC2JBUSBFunctionAlreadyAttempted = 8,/* this operation was already tried this run */
    MAC2JBUSBFunctionInterfaceNotOpen = 9 /* the interface open has not succeeded yet */
} MAC2JBUSBFunctionResult;

// The operations, in the order the macOS reference performs them: the
// interface open comes first, over the connection, straight after the service
// open and before any class, descriptor or pipe selector.
typedef enum {
    MAC2JBUSBFunctionOperationInterfaceOpen = 0,
    MAC2JBUSBFunctionOperationSetClass = 1,
    MAC2JBUSBFunctionOperationSetSubClass = 2,
    MAC2JBUSBFunctionOperationSetProtocol = 3,
    MAC2JBUSBFunctionOperationAppendStandardDescriptor = 4,
    MAC2JBUSBFunctionOperationAppendNonstandardDescriptor = 5,
    MAC2JBUSBFunctionOperationSetClassCommandCallbacks = 6,
    MAC2JBUSBFunctionOperationCreatePipe = 7,
    MAC2JBUSBFunctionOperationCommit = 8,
    MAC2JBUSBFunctionOperationCreateBuffer = 9,
    MAC2JBUSBFunctionOperationInterfaceClose = 10,
    MAC2JBUSBFunctionOperationCount = 11,
    MAC2JBUSBFunctionOperationNone = 255  /* nothing has aborted the sequence */
} MAC2JBUSBFunctionOperation;

// Reference selector numbers from the macOS backend. Hypotheses to test on this
// build, not constants to trust: pass one of these, or a neighbour, as the
// selector argument of the matching entry.
typedef enum {
    MAC2JBUSBFunctionSelectorInterfaceOpen = 0,
    MAC2JBUSBFunctionSelectorInterfaceClose = 1,
    MAC2JBUSBFunctionSelectorSetClass = 3,
    MAC2JBUSBFunctionSelectorSetSubClass = 4,
    MAC2JBUSBFunctionSelectorSetProtocol = 5,
    MAC2JBUSBFunctionSelectorAppendStandardDescriptor = 6,
    MAC2JBUSBFunctionSelectorAppendNonstandardDescriptor = 7,
    MAC2JBUSBFunctionSelectorSetClassCommandCallbacks = 8,
    MAC2JBUSBFunctionSelectorCreatePipe = 10,
    MAC2JBUSBFunctionSelectorCommit = 11,
    MAC2JBUSBFunctionSelectorCreateBuffer = 18
} MAC2JBUSBFunctionSelector;

// The reference opens the interface user client with this type. Also an
// observation of that build; MAC2JBUSBFunctionOpen takes it as a parameter.
#define MAC2JBUSBFunctionReferenceUserClientType 123u

// USB HID descriptor types, for the two descriptor-append entries.
#define MAC2JBUSBFunctionHIDDescriptorType 0x21u
#define MAC2JBUSBFunctionHIDReportDescriptorType 0x22u

// Placeholder raw return meaning "this call was never made". Same value the
// restore shim uses for an unattempted IOKit call (kIOReturnNotReady), spelled
// out here so the header needs no IOKit.
#define MAC2JBUSBFunctionCallNotAttempted ((int32_t)0xE00002D1)

// The attempt matrix for one session: which operations were tried, which were
// refused, which refusal aborted the sequence, and the raw IOReturn of each
// call exactly as the kernel returned it.
typedef struct {
    uint32_t attempted;  /* bit (1u << operation) set once the call was made */
    uint32_t refused;    /* bit set when that call returned nonzero */
    uint8_t abortedBy;   /* first refusing operation, else MAC2JBUSBFunctionOperationNone */
    int32_t calls[MAC2JBUSBFunctionOperationCount];
} MAC2JBUSBFunctionLedger;

// Pure name logic, testable with no controller present.

// True only when the registry property is the whole wanted name: a prefix, a
// suffix, a case variant, a truncation at an embedded NUL and an over-long
// string all fail.
bool MAC2JBUSBFunctionNameMatches(const char *property, const char *wanted);

// Accepts ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ and nothing else.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionValidateName(const char *name);

// Pure ledger logic; the real entries below go through exactly these.
void MAC2JBUSBFunctionLedgerInit(MAC2JBUSBFunctionLedger *ledger);
// Gate for one operation: MAC2JBUSBFunctionAlreadyAttempted when it already
// ran this session, MAC2JBUSBFunctionOperationRefused once any operation has
// been refused, MAC2JBUSBFunctionInterfaceNotOpen for anything other than the
// interface open while that open has not succeeded, otherwise
// MAC2JBUSBFunctionSuccess with the attempt recorded. Only a success spends
// the single attempt; a gate refusal spends nothing.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionLedgerBegin(
    MAC2JBUSBFunctionLedger *ledger, MAC2JBUSBFunctionOperation operation);
// Stores the raw return verbatim; a nonzero return names this operation as the
// aborter unless an earlier one already holds that place.
void MAC2JBUSBFunctionLedgerRecord(
    MAC2JBUSBFunctionLedger *ledger, MAC2JBUSBFunctionOperation operation,
    int32_t rawReturn);

// Match one IOUSBDeviceInterface whose USBDeviceFunction property is exactly
// functionName and whose service-plane ancestor controller has the expected
// registry entry ID, then open its user client once. One attempt only: no
// retry and no waiting loop, unlike the reference, so the caller sees the real
// first answer and decides whether to try again.
// Returns MAC2JBUSBFunctionServiceAbsent when the name never appeared and
// MAC2JBUSBFunctionOpenDenied when it appeared and the open was refused; both
// raw returns are always written.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionOpen(
    uint64_t expectedControllerRegistryID,
    const char *functionName,
    uint32_t userClientType,
    MAC2JBUSBFunctionSession **session,
    int32_t *matchReturn,
    int32_t *openReturn
);

// Teardown: tears down the Mach connection and frees the session. This is not
// a USB operation and is not ledger-tracked; the selector-1 operation on the
// interface itself is MAC2JBUSBFunctionInterfaceClose below. NULL is harmless.
void MAC2JBUSBFunctionClose(MAC2JBUSBFunctionSession *session);

// Reads back the whole attempt matrix so a caller can report it.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionCopyLedger(
    const MAC2JBUSBFunctionSession *session, MAC2JBUSBFunctionLedger *ledger);

// One entry per operation. Each is accepted at most once per session, each
// aborts every later operation once one is refused, and each writes the raw
// IOReturn to callReturn with no interpretation. Every entry below except the
// interface open is refused with MAC2JBUSBFunctionInterfaceNotOpen until that
// open has succeeded, so a first device trial cannot probe a half-opened
// interface and blame the selector.

// The interface open over the connection, which the reference places directly
// after IOServiceOpen. MAC2JBUSBFunctionOpen deliberately does not call it:
// walking the matrix one operation at a time means this open gets its own
// attempt and its own recorded raw return. argument is the reference's single
// scalar, undocumented there; it passes 0.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionInterfaceOpen(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint64_t argument, int32_t *callReturn);

// The selector-1 counterpart of the interface open. Not the teardown: see
// MAC2JBUSBFunctionClose above.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionInterfaceClose(
    MAC2JBUSBFunctionSession *session, uint32_t selector, int32_t *callReturn);

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetClass(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t value, uint64_t configurationID, int32_t *callReturn);

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetSubClass(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t value, uint64_t configurationID, int32_t *callReturn);

MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetProtocol(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t value, uint64_t configurationID, int32_t *callReturn);

// descriptorType is the USB descriptor type (0x21 for a HID descriptor).
// secondArgument is the reference's second scalar, whose meaning that backend
// does not document; it passes 0.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionAppendStandardDescriptor(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t descriptorType, uint8_t secondArgument,
    const uint8_t *descriptor, size_t length, int32_t *callReturn);

// Same shape, for the report descriptor (0x22).
MAC2JBUSBFunctionResult MAC2JBUSBFunctionAppendNonstandardDescriptor(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t descriptorType, uint8_t secondArgument,
    const uint8_t *descriptor, size_t length, int32_t *callReturn);

// The reference issues this asynchronously against a Mach notification port it
// owns, so the port, the async reference block and the callback belong to the
// caller that runs the run loop; this entry only places the call. The three
// flags are the reference's three booleans, which that backend passes as
// (true, false, false) and does not explain beyond guessing that the second
// asks for successful-send reports.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionSetClassCommandCallbacks(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint32_t notificationPort, const uint64_t *asyncReference,
    uint32_t asyncReferenceCount,
    bool flagA, bool flagB, bool flagC, int32_t *callReturn);

// An interrupt-IN pipe for the keyboard reports. unknownArgument is the
// reference's fifth scalar, undocumented there; it passes 0.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionCreatePipe(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint8_t type, uint8_t direction, uint32_t maxPacketSize, uint8_t interval,
    uint64_t unknownArgument, uint64_t configurationID,
    uint64_t *pipeID, int32_t *callReturn);

MAC2JBUSBFunctionResult MAC2JBUSBFunctionCommit(
    MAC2JBUSBFunctionSession *session, uint32_t selector, int32_t *callReturn);

// Shared buffer for setup and pipe traffic. The three outputs are the
// reference's address, size and token.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionCreateBuffer(
    MAC2JBUSBFunctionSession *session, uint32_t selector, uint32_t size,
    uint64_t *address, uint64_t *bufferSize, uint64_t *token, int32_t *callReturn);

#endif
