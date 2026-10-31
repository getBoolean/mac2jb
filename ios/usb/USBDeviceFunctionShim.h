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

// Identifiers for the ledger's cells. These are not a call order: only the
// interface open is ordered here, and it is enforced, because it goes over the
// connection straight after the service open and before any class, descriptor
// or pipe selector. The caller owns the rest of the order, which in the macOS
// reference runs class, subclass, protocol, both descriptor appends, the pipe,
// the buffers, the commit, and the class-command callbacks last.
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
    /* The transmit path. Repeatable: a keyboard sends many reports. */
    MAC2JBUSBFunctionOperationWritePipe = 11,
    MAC2JBUSBFunctionOperationPipeMaxPacketSize = 12,
    MAC2JBUSBFunctionOperationCount = 13,
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
    MAC2JBUSBFunctionSelectorWritePipe = 14,
    MAC2JBUSBFunctionSelectorPipeMaxPacketSize = 17,
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

// The attempt matrix for one session: which operations were tried and how
// often, which were refused, which refusal aborted the sequence, and the raw
// IOReturn of each call exactly as the kernel returned it.
//
// A repeatable cell is read differently from a once-only one, and
// MAC2JBUSBFunctionOperationIsRepeatable is how a reader tells them apart:
// attempts can exceed 1, calls holds the most recent raw return rather than
// the only one, and refused means at least one call was refused.
typedef struct {
    uint32_t attempted;  /* bit (1u << operation) set once the call was made */
    uint32_t refused;    /* bit set when a call returned nonzero */
    uint8_t abortedBy;   /* first refusing configuration operation, else
                            MAC2JBUSBFunctionOperationNone; a repeatable
                            operation never names itself here */
    uint32_t attempts[MAC2JBUSBFunctionOperationCount];
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
// True for the transmit operations, which run once per report rather than once
// per session and whose failure is a transient transfer problem, not a refused
// configuration selector.
bool MAC2JBUSBFunctionOperationIsRepeatable(MAC2JBUSBFunctionOperation operation);
// Gate for one operation: MAC2JBUSBFunctionAlreadyAttempted when a once-only
// operation already ran this session, MAC2JBUSBFunctionOperationRefused once
// the sequence has been aborted, MAC2JBUSBFunctionInterfaceNotOpen for
// anything other than the interface open while that open has not succeeded,
// otherwise MAC2JBUSBFunctionSuccess with the attempt counted. A repeatable
// operation skips only the once-only rule; it is gated like the rest. A gate
// refusal counts nothing.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionLedgerBegin(
    MAC2JBUSBFunctionLedger *ledger, MAC2JBUSBFunctionOperation operation);
// Stores the raw return verbatim; a nonzero return from a once-only operation
// names it as the aborter unless an earlier one already holds that place. A
// repeatable operation never becomes the aborter: one timed-out report must
// not kill a configured interface, so the caller decides what to do next.
void MAC2JBUSBFunctionLedgerRecord(
    MAC2JBUSBFunctionLedger *ledger, MAC2JBUSBFunctionOperation operation,
    int32_t rawReturn);

// Publishes the single output scalar of a scalar method without letting it
// share storage with the return code. The reference backend assigns
// output[0] over its IOReturn variable, so a short transfer and an error are
// indistinguishable there; here *value is the scalar and the raw IOReturn
// stays in its own out parameter. A refused call accounts for nothing, so
// *value becomes 0 and only the raw return describes the failure.
void MAC2JBUSBFunctionSplitScalarResult(
    int32_t rawReturn, const uint64_t *output, uint32_t outputCount,
    uint64_t *value);

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
// reference's address, size and token: the caller writes its report bytes to
// address and passes token to MAC2JBUSBFunctionWritePipe.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionCreateBuffer(
    MAC2JBUSBFunctionSession *session, uint32_t selector, uint32_t size,
    uint64_t *address, uint64_t *bufferSize, uint64_t *token, int32_t *callReturn);

// The transmit path. Both entries are repeatable and both still require a
// successful interface open and an unaborted sequence.

// Hands one already-staged report to the pipe. The caller copies its bytes to
// the mapped address MAC2JBUSBFunctionCreateBuffer returned and passes that
// buffer's token here; this entry does not copy, so a kernel refusal is never
// confused with a bad memcpy. length must not exceed the buffer size
// MAC2JBUSBFunctionCreateBuffer reported, and the caller compares *transferred
// against the length it asked for to detect a short write: *callReturn is the
// raw IOReturn and *transferred is the byte count, never the same value.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionWritePipe(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint64_t pipeID, uint64_t bufferToken, uint64_t length,
    uint64_t timeoutMilliseconds, uint64_t *transferred, int32_t *callReturn);

// The pipe's current maximum packet size, which bounds one report.
MAC2JBUSBFunctionResult MAC2JBUSBFunctionPipeMaxPacketSize(
    MAC2JBUSBFunctionSession *session, uint32_t selector,
    uint64_t pipeID, uint64_t *maxPacketSize, int32_t *callReturn);

#endif
