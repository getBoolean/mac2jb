// Mac-only tests for the added-function matcher and the interface operation
// entries. Nothing here publishes a description, opens a user client on a real
// gadget interface, or sends a keystroke: the matcher is exercised against a
// name that cannot exist, and the operation entries are exercised through the
// same attempt ledger the real entries use.
//
// The shim source is included rather than linked so a session can be built by
// hand with recording fakes in place of the three resolved IOKit call entry
// points. That is what lets the entries run past their guards and have the
// selector, scalars, struct input and output counts they pass checked.

#include "../usb/USBDeviceFunctionShim.c"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define require(condition) do { \
    if (!(condition)) { \
        failures++; \
        fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #condition); \
    } \
} while (0)

// A refusal observed on this device for an unsupported user client; used here
// only as a nonzero raw return, never interpreted.
#define REFUSED ((int32_t)-536870201)

static void name_matching(void) {
    require(MAC2JBUSBFunctionNameMatches("hidcanary", "hidcanary"));
    // A prefix, a suffix and a case variant must all be rejected: the kernel
    // publishes one exact name and a near miss is a different function.
    require(!MAC2JBUSBFunctionNameMatches("hid", "hidcanary"));
    require(!MAC2JBUSBFunctionNameMatches("hidcanary", "hid"));
    require(!MAC2JBUSBFunctionNameMatches("hidcanaryx", "hidcanary"));
    require(!MAC2JBUSBFunctionNameMatches("xhidcanary", "hidcanary"));
    require(!MAC2JBUSBFunctionNameMatches("HIDCanary", "hidcanary"));
    require(!MAC2JBUSBFunctionNameMatches("hidcanary", "HIDCanary"));
    require(!MAC2JBUSBFunctionNameMatches(NULL, "hidcanary"));
    require(!MAC2JBUSBFunctionNameMatches("hidcanary", NULL));
    require(!MAC2JBUSBFunctionNameMatches("", ""));
    // A property truncated at an embedded NUL is not the full name.
    static const char embedded[] = { 'h', 'i', 'd', 0, 'c', 'a', 'n', 'a', 'r', 'y', 0 };
    require(!MAC2JBUSBFunctionNameMatches(embedded, "hidcanary"));
    // Over-long on either side is rejected before any comparison.
    char over[34];
    memset(over, 'a', sizeof(over) - 1);
    over[sizeof(over) - 1] = 0;
    require(!MAC2JBUSBFunctionNameMatches(over, over));
    char exact[33];
    memset(exact, 'a', sizeof(exact) - 1);
    exact[sizeof(exact) - 1] = 0;
    require(MAC2JBUSBFunctionNameMatches(exact, exact));
}

static void name_validation(void) {
    require(MAC2JBUSBFunctionValidateName("hidcanary") == MAC2JBUSBFunctionSuccess);
    require(MAC2JBUSBFunctionValidateName("H1d-canary.v2_x") == MAC2JBUSBFunctionSuccess);
    require(MAC2JBUSBFunctionValidateName("0") == MAC2JBUSBFunctionSuccess);
    require(MAC2JBUSBFunctionValidateName(NULL) == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionValidateName("") == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionValidateName("_leading") == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionValidateName("-leading") == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionValidateName(".leading") == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionValidateName("has space") == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionValidateName("has/slash") == MAC2JBUSBFunctionInvalidInput);
    char exact[33];
    memset(exact, 'a', sizeof(exact) - 1);
    exact[sizeof(exact) - 1] = 0;
    require(MAC2JBUSBFunctionValidateName(exact) == MAC2JBUSBFunctionSuccess);
    char over[34];
    memset(over, 'a', sizeof(over) - 1);
    over[sizeof(over) - 1] = 0;
    require(MAC2JBUSBFunctionValidateName(over) == MAC2JBUSBFunctionInvalidInput);
}

static void distinct_outcomes(void) {
    // The whole point of the unit: "the name never appeared" and "the name
    // appeared and the open was refused" are different answers, and neither is
    // a pass.
    require(MAC2JBUSBFunctionServiceAbsent != MAC2JBUSBFunctionOpenDenied);
    require(MAC2JBUSBFunctionServiceAbsent != MAC2JBUSBFunctionSuccess);
    require(MAC2JBUSBFunctionOpenDenied != MAC2JBUSBFunctionSuccess);
    require(MAC2JBUSBFunctionWrongController != MAC2JBUSBFunctionServiceAbsent);
    require(MAC2JBUSBFunctionAlreadyAttempted != MAC2JBUSBFunctionOperationRefused);
    // "You never opened the interface" is its own answer, so a first device
    // trial cannot read it as a refused selector.
    require(MAC2JBUSBFunctionInterfaceNotOpen != MAC2JBUSBFunctionOperationRefused);
    require(MAC2JBUSBFunctionInterfaceNotOpen != MAC2JBUSBFunctionAlreadyAttempted);
    require(MAC2JBUSBFunctionInterfaceNotOpen != MAC2JBUSBFunctionSuccess);
}

static void open_rejects_bad_input(void) {
    MAC2JBUSBFunctionSession *session = (MAC2JBUSBFunctionSession *)1;
    int32_t matchReturn = 0, openReturn = 0;
    require(MAC2JBUSBFunctionOpen(1, "has space", 123, &session,
                                  &matchReturn, &openReturn) ==
            MAC2JBUSBFunctionInvalidInput);
    require(session == NULL);
    session = (MAC2JBUSBFunctionSession *)1;
    require(MAC2JBUSBFunctionOpen(0, "hidcanary", 123, &session,
                                  &matchReturn, &openReturn) ==
            MAC2JBUSBFunctionInvalidInput);
    require(session == NULL);
    require(MAC2JBUSBFunctionOpen(1, "hidcanary", 123, NULL,
                                  &matchReturn, &openReturn) ==
            MAC2JBUSBFunctionInvalidInput);
}

static void open_reports_absent_service(void) {
    // Read-only on this Mac: a name no controller publishes must come back as
    // absent, with the raw matching return recorded and no session handed over.
    MAC2JBUSBFunctionSession *session = (MAC2JBUSBFunctionSession *)1;
    int32_t matchReturn = 0, openReturn = 0;
    MAC2JBUSBFunctionResult result = MAC2JBUSBFunctionOpen(
        1, "mac2jbnosuchfunction", 123, &session, &matchReturn, &openReturn);
    require(result != MAC2JBUSBFunctionSuccess);
    require(session == NULL);
    // Absent, specifically. A match that succeeds and yields nothing means the
    // name is not published; reporting it as an unavailable controller made a
    // caller waiting for a function it had just asked a broker to publish give
    // up before the publication could land. Accepting either answer here is
    // what let that through, so this asserts the exact one.
    require(matchReturn == 0);
    require(result == MAC2JBUSBFunctionServiceAbsent);
    require(openReturn == MAC2JBUSBFunctionCallNotAttempted);
}

static void ledger_accepts_each_operation_once(void) {
    MAC2JBUSBFunctionLedger ledger;
    MAC2JBUSBFunctionLedgerInit(&ledger);
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationNone);
    for (int index = 0; index < MAC2JBUSBFunctionOperationCount; index++)
        require(ledger.calls[index] == MAC2JBUSBFunctionCallNotAttempted);
    for (int index = 0; index < MAC2JBUSBFunctionOperationCount; index++) {
        MAC2JBUSBFunctionOperation operation = (MAC2JBUSBFunctionOperation)index;
        require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                MAC2JBUSBFunctionSuccess);
        MAC2JBUSBFunctionLedgerRecord(&ledger, operation, 0);
        // A transmit operation runs as often as the keyboard has reports to
        // send, so only the configuration cells are once-only.
        require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                (MAC2JBUSBFunctionOperationIsRepeatable(operation)
                     ? MAC2JBUSBFunctionSuccess
                     : MAC2JBUSBFunctionAlreadyAttempted));
        require(ledger.calls[index] == 0);
        require(ledger.attempts[index] ==
                (MAC2JBUSBFunctionOperationIsRepeatable(operation) ? 2u : 1u));
    }
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationNone);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationCount) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionLedgerBegin(NULL, MAC2JBUSBFunctionOperationCommit) ==
            MAC2JBUSBFunctionInvalidInput);
}

// The reference opens the interface over the connection immediately after
// IOServiceOpen and before any class, descriptor or pipe selector, so the
// ledger must enforce that order rather than trust the call order.
static void configuration_requires_the_interface_open(void) {
    MAC2JBUSBFunctionLedger ledger;
    MAC2JBUSBFunctionLedgerInit(&ledger);
    for (int index = 0; index < MAC2JBUSBFunctionOperationCount; index++) {
        MAC2JBUSBFunctionOperation operation = (MAC2JBUSBFunctionOperation)index;
        if (operation == MAC2JBUSBFunctionOperationInterfaceOpen) continue;
        require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                MAC2JBUSBFunctionInterfaceNotOpen);
        require(ledger.calls[index] == MAC2JBUSBFunctionCallNotAttempted);
    }
    // A gate refusal is not an attempt: nothing is spent, and the open is
    // still available.
    require(ledger.attempted == 0);
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationNone);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger,
                                         MAC2JBUSBFunctionOperationInterfaceOpen) ==
            MAC2JBUSBFunctionSuccess);
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationInterfaceOpen, 0);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationSetClass) ==
            MAC2JBUSBFunctionSuccess);
    // The interface open is accepted once and only once.
    require(MAC2JBUSBFunctionLedgerBegin(&ledger,
                                         MAC2JBUSBFunctionOperationInterfaceOpen) ==
            MAC2JBUSBFunctionAlreadyAttempted);
}

static void refused_interface_open_aborts_everything(void) {
    MAC2JBUSBFunctionLedger ledger;
    MAC2JBUSBFunctionLedgerInit(&ledger);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger,
                                         MAC2JBUSBFunctionOperationInterfaceOpen) ==
            MAC2JBUSBFunctionSuccess);
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationInterfaceOpen,
                                  REFUSED);
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationInterfaceOpen);
    require(ledger.calls[MAC2JBUSBFunctionOperationInterfaceOpen] == REFUSED);
    for (int index = 0; index < MAC2JBUSBFunctionOperationCount; index++) {
        MAC2JBUSBFunctionOperation operation = (MAC2JBUSBFunctionOperation)index;
        if (operation == MAC2JBUSBFunctionOperationInterfaceOpen) {
            require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                    MAC2JBUSBFunctionAlreadyAttempted);
            continue;
        }
        // A refused open aborts the run; it does not read as "not opened yet".
        require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                MAC2JBUSBFunctionOperationRefused);
        require(ledger.calls[index] == MAC2JBUSBFunctionCallNotAttempted);
    }
}

// The transmit path: repeatable, gated the same way, and not allowed to kill a
// session because one write timed out.
static void transmit_operations_repeat_without_aborting(void) {
    require(MAC2JBUSBFunctionOperationIsRepeatable(
        MAC2JBUSBFunctionOperationWritePipe));
    require(MAC2JBUSBFunctionOperationIsRepeatable(
        MAC2JBUSBFunctionOperationPipeMaxPacketSize));
    require(!MAC2JBUSBFunctionOperationIsRepeatable(
        MAC2JBUSBFunctionOperationCommit));
    require(!MAC2JBUSBFunctionOperationIsRepeatable(
        MAC2JBUSBFunctionOperationInterfaceOpen));

    MAC2JBUSBFunctionLedger ledger;
    MAC2JBUSBFunctionLedgerInit(&ledger);
    // Gated like everything else: no interface open, no write.
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationWritePipe) ==
            MAC2JBUSBFunctionInterfaceNotOpen);
    require(MAC2JBUSBFunctionLedgerBegin(
                &ledger, MAC2JBUSBFunctionOperationPipeMaxPacketSize) ==
            MAC2JBUSBFunctionInterfaceNotOpen);
    require(ledger.attempts[MAC2JBUSBFunctionOperationWritePipe] == 0);

    require(MAC2JBUSBFunctionLedgerBegin(&ledger,
                                         MAC2JBUSBFunctionOperationInterfaceOpen) ==
            MAC2JBUSBFunctionSuccess);
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationInterfaceOpen, 0);
    for (uint32_t round = 1; round <= 5; round++) {
        require(MAC2JBUSBFunctionLedgerBegin(
                    &ledger, MAC2JBUSBFunctionOperationWritePipe) ==
                MAC2JBUSBFunctionSuccess);
        MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationWritePipe, 0);
        require(ledger.attempts[MAC2JBUSBFunctionOperationWritePipe] == round);
    }
    require(MAC2JBUSBFunctionLedgerBegin(
                &ledger, MAC2JBUSBFunctionOperationPipeMaxPacketSize) ==
            MAC2JBUSBFunctionSuccess);

    // A failed write records its raw return but does not name itself aborter,
    // so the next report may still be attempted.
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationWritePipe, REFUSED);
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationNone);
    require(ledger.calls[MAC2JBUSBFunctionOperationWritePipe] == REFUSED);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationWritePipe) ==
            MAC2JBUSBFunctionSuccess);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationCommit) ==
            MAC2JBUSBFunctionSuccess);

    // A refused configuration selector still closes the transmit path.
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationCommit, REFUSED);
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationCommit);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationWritePipe) ==
            MAC2JBUSBFunctionOperationRefused);
    require(MAC2JBUSBFunctionLedgerBegin(
                &ledger, MAC2JBUSBFunctionOperationPipeMaxPacketSize) ==
            MAC2JBUSBFunctionOperationRefused);
}

// The reference returns a transferred byte count through the same variable as
// the IOReturn, so a short write is indistinguishable from an error code.
// Here the two are split and never share storage.
static void scalar_output_never_carries_the_return_code(void) {
    uint64_t value = 999;
    uint64_t output[1] = { 4 };
    // A short write: success, fewer bytes than the caller asked for. The
    // caller, not this code, decides whether 4 of 8 is a problem.
    MAC2JBUSBFunctionSplitScalarResult(0, output, 1, &value);
    require(value == 4);
    // A refused call accounts for no bytes; the error stays in the return.
    value = 999;
    output[0] = (uint64_t)(uint32_t)REFUSED;
    MAC2JBUSBFunctionSplitScalarResult(REFUSED, output, 1, &value);
    require(value == 0);
    // A success with no output scalar reports no bytes rather than garbage.
    value = 999;
    MAC2JBUSBFunctionSplitScalarResult(0, output, 0, &value);
    require(value == 0);
    value = 999;
    MAC2JBUSBFunctionSplitScalarResult(0, NULL, 1, &value);
    require(value == 0);
    MAC2JBUSBFunctionSplitScalarResult(0, output, 1, NULL);  // Harmless.
}

static void refusal_aborts_the_sequence(void) {
    MAC2JBUSBFunctionLedger ledger;
    MAC2JBUSBFunctionLedgerInit(&ledger);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger,
                                         MAC2JBUSBFunctionOperationInterfaceOpen) ==
            MAC2JBUSBFunctionSuccess);
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationInterfaceOpen, 0);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationSetClass) ==
            MAC2JBUSBFunctionSuccess);
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationSetClass, 0);
    require(MAC2JBUSBFunctionLedgerBegin(&ledger, MAC2JBUSBFunctionOperationSetSubClass) ==
            MAC2JBUSBFunctionSuccess);
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationSetSubClass, REFUSED);
    // The matrix names the operation that aborted the run, and the raw return
    // is kept verbatim.
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationSetSubClass);
    require(ledger.calls[MAC2JBUSBFunctionOperationSetSubClass] == REFUSED);
    for (int index = 0; index < MAC2JBUSBFunctionOperationCount; index++) {
        MAC2JBUSBFunctionOperation operation = (MAC2JBUSBFunctionOperation)index;
        if (operation == MAC2JBUSBFunctionOperationInterfaceOpen ||
            operation == MAC2JBUSBFunctionOperationSetClass ||
            operation == MAC2JBUSBFunctionOperationSetSubClass) {
            require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                    MAC2JBUSBFunctionAlreadyAttempted);
            continue;
        }
        require(MAC2JBUSBFunctionLedgerBegin(&ledger, operation) ==
                MAC2JBUSBFunctionOperationRefused);
        require(ledger.calls[index] == MAC2JBUSBFunctionCallNotAttempted);
    }
    // A later refusal does not rename the first aborter.
    MAC2JBUSBFunctionLedgerRecord(&ledger, MAC2JBUSBFunctionOperationCommit, REFUSED);
    require(ledger.abortedBy == MAC2JBUSBFunctionOperationSetSubClass);
}

static void selectors_are_exposed_and_overridable(void) {
    // Reference selector numbers from the macOS backend, kept as named
    // hypotheses so a probe can try a neighbour when one is unsupported.
    require(MAC2JBUSBFunctionSelectorInterfaceOpen == 0);
    require(MAC2JBUSBFunctionSelectorInterfaceClose == 1);
    require(MAC2JBUSBFunctionSelectorSetClass == 3);
    require(MAC2JBUSBFunctionSelectorSetSubClass == 4);
    require(MAC2JBUSBFunctionSelectorSetProtocol == 5);
    require(MAC2JBUSBFunctionSelectorAppendStandardDescriptor == 6);
    require(MAC2JBUSBFunctionSelectorAppendNonstandardDescriptor == 7);
    require(MAC2JBUSBFunctionSelectorSetClassCommandCallbacks == 8);
    require(MAC2JBUSBFunctionSelectorCreatePipe == 10);
    require(MAC2JBUSBFunctionSelectorCommit == 11);
    require(MAC2JBUSBFunctionSelectorCreateBuffer == 18);
    require(MAC2JBUSBFunctionSelectorWritePipe == 14);
    require(MAC2JBUSBFunctionSelectorPipeMaxPacketSize == 17);
    require(MAC2JBUSBFunctionReferenceUserClientType == 123);
    require(MAC2JBUSBFunctionHIDDescriptorType == 0x21);
    require(MAC2JBUSBFunctionHIDReportDescriptorType == 0x22);
}

static void entries_reject_a_missing_session(void) {
    // Every entry takes a caller-chosen selector, so a neighbouring number can
    // be probed without a rebuild; with no session none of them calls anything.
    static const uint8_t descriptor[] = { 0x09, 0x21 };
    uint64_t pipe = 0, address = 0, size = 0, token = 0;
    int32_t raw = 0;
    require(MAC2JBUSBFunctionInterfaceOpen(NULL, 99, 0, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionInterfaceClose(NULL, 99, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionSetClass(NULL, 99, 3, 0, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionSetSubClass(NULL, 99, 0, 0, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionSetProtocol(NULL, 99, 1, 0, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionAppendStandardDescriptor(
                NULL, 99, MAC2JBUSBFunctionHIDDescriptorType, 0,
                descriptor, sizeof(descriptor), &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionAppendNonstandardDescriptor(
                NULL, 99, MAC2JBUSBFunctionHIDReportDescriptorType, 0,
                descriptor, sizeof(descriptor), &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionSetClassCommandCallbacks(
                NULL, 99, 0, NULL, 0, true, false, false, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionCreatePipe(NULL, 99, 3, 1, 8, 10, 0, 0, &pipe, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionCommit(NULL, 99, &raw) == MAC2JBUSBFunctionInvalidInput);
    require(MAC2JBUSBFunctionCreateBuffer(NULL, 99, 0x1000, &address, &size,
                                          &token, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    // The transferred count and the raw return are separate out parameters, so
    // neither can arrive carrying the other.
    uint64_t transferred = 999, maxPacket = 999;
    require(MAC2JBUSBFunctionWritePipe(NULL, 99, 1, token, 8, 50, &transferred,
                                       &raw) == MAC2JBUSBFunctionInvalidInput);
    require(transferred == 0);
    require(MAC2JBUSBFunctionPipeMaxPacketSize(NULL, 99, 1, &maxPacket, &raw) ==
            MAC2JBUSBFunctionInvalidInput);
    require(maxPacket == 0);
    require(raw == MAC2JBUSBFunctionCallNotAttempted);
    MAC2JBUSBFunctionLedger ledger;
    require(MAC2JBUSBFunctionCopyLedger(NULL, &ledger) == MAC2JBUSBFunctionInvalidInput);
    MAC2JBUSBFunctionClose(NULL);  // Harmless, like free(NULL).
}

// ---- Operation entries run against recording fakes ----

#define CHECK_CONN 0x1234u
#define CHECK_RAW ((int32_t)0xE00002C2)

static int scenarios = 0;

static void check_at(bool ok, const char *entry, const char *what, int line) {
    if (ok) return;
    failures++;
    fprintf(stderr, "FAIL %s:%d %s: %s\n", __FILE__, line, entry, what);
}
#define check(condition, what) check_at((condition), "-", (what), __LINE__)
#define check_op(condition, op, what) check_at((condition), op_name(op), (what), __LINE__)

typedef struct {
    int calls;
    char kind;  // 's' scalar, 'm' method with struct, 'a' async scalar
    mach_port_t connection;
    uint32_t selector;
    uint64_t scalars[8];
    uint32_t scalarCount;
    const void *inStruct;
    size_t inStructLength;
    bool outScalar, outStruct;
    uint32_t outCapacity;
    mach_port_t port;
    const uint64_t *referencePointer;
    uint64_t reference[8];
    uint32_t referenceCount;
    // What the fake kernel answers with. Outputs are written even when the
    // status is a refusal, as junk a real driver could leave behind.
    kern_return_t status;
    uint64_t produce[3];
    uint32_t produceCount;
} Fake;

static Fake fake;

static void record_scalars(const uint64_t *in, uint32_t count) {
    fake.scalarCount = count;
    for (uint32_t index = 0; index < count && index < 8; index++)
        fake.scalars[index] = in[index];
}

static kern_return_t fake_scalar(mach_port_t connection, uint32_t selector,
                                 const uint64_t *in, uint32_t inCount,
                                 uint64_t *out, uint32_t *outCount) {
    fake.calls++;
    fake.kind = 's';
    fake.connection = connection;
    fake.selector = selector;
    record_scalars(in, inCount);
    fake.outScalar = out != NULL || outCount != NULL;
    fake.outCapacity = outCount ? *outCount : 0;
    if (out && outCount) {
        for (uint32_t index = 0; index < fake.produceCount; index++)
            out[index] = fake.produce[index];
        *outCount = fake.produceCount;
    }
    return fake.status;
}

static kern_return_t fake_method(mach_port_t connection, uint32_t selector,
                                 const uint64_t *in, uint32_t inCount,
                                 const void *inStruct, size_t inStructLength,
                                 uint64_t *outScalar, uint32_t *outScalarCount,
                                 void *outStruct, size_t *outStructLength) {
    fake.calls++;
    fake.kind = 'm';
    fake.connection = connection;
    fake.selector = selector;
    record_scalars(in, inCount);
    fake.inStruct = inStruct;
    fake.inStructLength = inStructLength;
    fake.outScalar = outScalar != NULL || outScalarCount != NULL;
    fake.outStruct = outStruct != NULL || outStructLength != NULL;
    return fake.status;
}

static kern_return_t fake_async(mach_port_t connection, uint32_t selector,
                                mach_port_t port, uint64_t *reference,
                                uint32_t referenceCount, const uint64_t *in,
                                uint32_t inCount, uint64_t *out, uint32_t *outCount) {
    fake.calls++;
    fake.kind = 'a';
    fake.connection = connection;
    fake.selector = selector;
    fake.port = port;
    fake.referencePointer = reference;
    fake.referenceCount = referenceCount;
    for (uint32_t index = 0; index < referenceCount && index < 8; index++)
        fake.reference[index] = reference[index];
    reference[0] ^= 0xFFFF;  // IOKit takes the block mutably.
    record_scalars(in, inCount);
    fake.outScalar = out != NULL || outCount != NULL;
    return fake.status;
}

static const char *const OP_NAMES[] = {
    "InterfaceOpen", "SetClass", "SetSubClass", "SetProtocol",
    "AppendStandardDescriptor", "AppendNonstandardDescriptor",
    "SetClassCommandCallbacks", "CreatePipe", "Commit", "CreateBuffer",
    "InterfaceClose", "WritePipe", "PipeMaxPacketSize"
};
static const char *op_name(int op) { return OP_NAMES[op]; }

// A hand-built session whose three call entry points are the fakes. With
// `opened` the interface open has already gone through the real entry.
static void fresh(MAC2JBUSBFunctionSession *session, bool opened) {
    memset(&fake, 0, sizeof(fake));
    memset(session, 0, sizeof(*session));
    session->connection = CHECK_CONN;
    session->callScalar = fake_scalar;
    session->callMethod = fake_method;
    session->callAsyncScalar = fake_async;
    MAC2JBUSBFunctionLedgerInit(&session->ledger);
    if (!opened) return;
    int32_t raw = 7;
    check(MAC2JBUSBFunctionInterfaceOpen(session, 0, 0, &raw) ==
          MAC2JBUSBFunctionSuccess, "setup interface open");
    memset(&fake, 0, sizeof(fake));
}

static uint32_t selector_of(int op) { return 0x100u + (uint32_t)op; }

static const uint8_t DESCRIPTOR[] = { 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3f, 0x00 };
static uint64_t callback_reference[3] = { 0x11, 0x22, 0x33 };

typedef struct { uint64_t pipe, address, size, token, transferred, maxPacket; } Outputs;

// Every entry, with arguments that are all different so a swap is visible and
// none equal to the reference constants so a substituted constant is visible.
static MAC2JBUSBFunctionResult invoke(int op, MAC2JBUSBFunctionSession *session,
                                      int32_t *raw, Outputs *out) {
    uint32_t sel = selector_of(op);
    switch (op) {
    case MAC2JBUSBFunctionOperationInterfaceOpen:
        return MAC2JBUSBFunctionInterfaceOpen(session, sel, 0xA1, raw);
    case MAC2JBUSBFunctionOperationInterfaceClose:
        return MAC2JBUSBFunctionInterfaceClose(session, sel, raw);
    case MAC2JBUSBFunctionOperationSetClass:
        return MAC2JBUSBFunctionSetClass(session, sel, 0x03, 0xC1, raw);
    case MAC2JBUSBFunctionOperationSetSubClass:
        return MAC2JBUSBFunctionSetSubClass(session, sel, 0x01, 0xC2, raw);
    case MAC2JBUSBFunctionOperationSetProtocol:
        return MAC2JBUSBFunctionSetProtocol(session, sel, 0x02, 0xC3, raw);
    case MAC2JBUSBFunctionOperationAppendStandardDescriptor:
        return MAC2JBUSBFunctionAppendStandardDescriptor(
            session, sel, 0x21, 0x07, DESCRIPTOR, sizeof(DESCRIPTOR), raw);
    case MAC2JBUSBFunctionOperationAppendNonstandardDescriptor:
        return MAC2JBUSBFunctionAppendNonstandardDescriptor(
            session, sel, 0x22, 0x09, DESCRIPTOR, sizeof(DESCRIPTOR), raw);
    case MAC2JBUSBFunctionOperationSetClassCommandCallbacks:
        return MAC2JBUSBFunctionSetClassCommandCallbacks(
            session, sel, 0x1303, callback_reference, 3, true, false, false, raw);
    case MAC2JBUSBFunctionOperationCreatePipe:
        return MAC2JBUSBFunctionCreatePipe(session, sel, 3, 1, 0x40, 10, 0x55, 0xC4,
                                           &out->pipe, raw);
    case MAC2JBUSBFunctionOperationCommit:
        return MAC2JBUSBFunctionCommit(session, sel, raw);
    case MAC2JBUSBFunctionOperationCreateBuffer:
        return MAC2JBUSBFunctionCreateBuffer(session, sel, 0x1000, &out->address,
                                             &out->size, &out->token, raw);
    case MAC2JBUSBFunctionOperationWritePipe:
        return MAC2JBUSBFunctionWritePipe(session, sel, 0x91, 0x92, 8, 50,
                                          &out->transferred, raw);
    case MAC2JBUSBFunctionOperationPipeMaxPacketSize:
        return MAC2JBUSBFunctionPipeMaxPacketSize(session, sel, 0x93,
                                                  &out->maxPacket, raw);
    }
    return MAC2JBUSBFunctionInvalidInput;
}

typedef struct {
    char kind;
    uint32_t scalarCount;
    uint64_t scalars[6];
    bool structInput;
    uint32_t outCapacity;  // Output scalar slots offered; 0 means none offered.
} Expected;

static const Expected EXPECTED[MAC2JBUSBFunctionOperationCount] = {
    [MAC2JBUSBFunctionOperationInterfaceOpen] = { 's', 1, { 0xA1 }, false, 0 },
    [MAC2JBUSBFunctionOperationInterfaceClose] = { 's', 0, { 0 }, false, 0 },
    [MAC2JBUSBFunctionOperationSetClass] = { 's', 2, { 0x03, 0xC1 }, false, 0 },
    [MAC2JBUSBFunctionOperationSetSubClass] = { 's', 2, { 0x01, 0xC2 }, false, 0 },
    [MAC2JBUSBFunctionOperationSetProtocol] = { 's', 2, { 0x02, 0xC3 }, false, 0 },
    [MAC2JBUSBFunctionOperationAppendStandardDescriptor] = { 'm', 2, { 0x21, 0x07 }, true, 0 },
    [MAC2JBUSBFunctionOperationAppendNonstandardDescriptor] = { 'm', 2, { 0x22, 0x09 }, true, 0 },
    [MAC2JBUSBFunctionOperationSetClassCommandCallbacks] = { 'a', 3, { 1, 0, 0 }, false, 0 },
    [MAC2JBUSBFunctionOperationCreatePipe] = { 's', 6, { 3, 1, 0x40, 10, 0x55, 0xC4 }, false, 1 },
    [MAC2JBUSBFunctionOperationCommit] = { 's', 0, { 0 }, false, 0 },
    [MAC2JBUSBFunctionOperationCreateBuffer] = { 's', 1, { 0x1000 }, false, 3 },
    [MAC2JBUSBFunctionOperationWritePipe] = { 's', 4, { 0x91, 0x92, 8, 50 }, false, 1 },
    [MAC2JBUSBFunctionOperationPipeMaxPacketSize] = { 's', 1, { 0x93 }, false, 1 },
};

static void program_outputs(int op) {
    switch (op) {
    case MAC2JBUSBFunctionOperationCreatePipe:
        fake.produce[0] = 0x5150; fake.produceCount = 1; break;
    case MAC2JBUSBFunctionOperationCreateBuffer:
        fake.produce[0] = 0xA0; fake.produce[1] = 0xB0; fake.produce[2] = 0xC0;
        fake.produceCount = 3; break;
    case MAC2JBUSBFunctionOperationWritePipe:
        fake.produce[0] = 4; fake.produceCount = 1; break;
    case MAC2JBUSBFunctionOperationPipeMaxPacketSize:
        fake.produce[0] = 64; fake.produceCount = 1; break;
    default: break;
    }
}

static bool outputs_are(const Outputs *out, uint64_t pipe, uint64_t address,
                        uint64_t size, uint64_t token, uint64_t transferred,
                        uint64_t maxPacket) {
    return out->pipe == pipe && out->address == address && out->size == size &&
        out->token == token && out->transferred == transferred &&
        out->maxPacket == maxPacket;
}

static void every_entry_marshals_its_arguments(void) {
    for (int op = 0; op < MAC2JBUSBFunctionOperationCount; op++) {
        const Expected *want = &EXPECTED[op];
        MAC2JBUSBFunctionSession session;
        Outputs out;
        int32_t raw = 77;

        // The kernel accepts: the selector the caller chose reaches the call
        // entry point, with the right scalars in order and nothing else.
        fresh(&session, op != MAC2JBUSBFunctionOperationInterfaceOpen);
        program_outputs(op);
        memset(&out, 0, sizeof(out));
        memcpy(callback_reference, (uint64_t[3]){ 0x11, 0x22, 0x33 }, sizeof(callback_reference));
        check_op(invoke(op, &session, &raw, &out) == MAC2JBUSBFunctionSuccess, op, "success");
        check_op(fake.calls == 1, op, "exactly one call placed");
        check_op(fake.kind == want->kind, op, "call entry point kind");
        check_op(fake.connection == CHECK_CONN, op, "connection");
        check_op(fake.selector == selector_of(op), op, "caller selector used, not a constant");
        check_op(fake.scalarCount == want->scalarCount, op, "scalar count");
        for (uint32_t index = 0; index < want->scalarCount; index++)
            check_op(fake.scalars[index] == want->scalars[index], op, "scalar value or order");
        if (want->kind == 'm') {
            check_op(fake.inStruct == DESCRIPTOR && fake.inStructLength == sizeof(DESCRIPTOR),
                     op, "struct input pointer and length");
            check_op(!fake.outScalar && !fake.outStruct, op, "no outputs requested");
        } else if (want->kind == 's') {
            check_op(fake.inStructLength == 0, op, "no struct input");
            check_op(fake.outScalar == (want->outCapacity > 0), op, "output scalars offered or not");
            check_op(fake.outCapacity == want->outCapacity, op, "output scalar capacity");
        } else {
            check_op(fake.port == 0x1303, op, "notification port");
            check_op(fake.referenceCount == 3, op, "reference count");
            check_op(fake.referencePointer != callback_reference, op, "reference block copied");
            check_op(fake.reference[0] == 0x11 && fake.reference[1] == 0x22 &&
                     fake.reference[2] == 0x33, op, "reference contents");
            check_op(callback_reference[0] == 0x11, op, "caller block not rewritten");
            check_op(!fake.outScalar, op, "no outputs requested");
        }
        check_op(raw == 0, op, "raw return zero");
        check_op(session.ledger.calls[op] == 0 && session.ledger.attempts[op] == 1,
                 op, "ledger cell recorded");
        check_op(session.ledger.abortedBy == MAC2JBUSBFunctionOperationNone, op, "no abort");
        switch (op) {
        case MAC2JBUSBFunctionOperationCreatePipe:
            check_op(outputs_are(&out, 0x5150, 0, 0, 0, 0, 0), op, "pipe id delivered"); break;
        case MAC2JBUSBFunctionOperationCreateBuffer:
            check_op(outputs_are(&out, 0, 0xA0, 0xB0, 0xC0, 0, 0), op, "buffer triple delivered"); break;
        case MAC2JBUSBFunctionOperationWritePipe:
            check_op(outputs_are(&out, 0, 0, 0, 0, 4, 0), op, "transferred delivered"); break;
        case MAC2JBUSBFunctionOperationPipeMaxPacketSize:
            check_op(outputs_are(&out, 0, 0, 0, 0, 0, 64), op, "max packet delivered"); break;
        default:
            check_op(outputs_are(&out, 0, 0, 0, 0, 0, 0), op, "no outputs touched"); break;
        }

        // The kernel refuses: the raw return reaches the caller and the cell
        // verbatim, junk left in the outputs is not passed on.
        fresh(&session, op != MAC2JBUSBFunctionOperationInterfaceOpen);
        program_outputs(op);
        fake.status = CHECK_RAW;
        memset(&out, 0, sizeof(out));
        check_op(invoke(op, &session, &raw, &out) == MAC2JBUSBFunctionOperationRefused,
                 op, "refusal result");
        check_op(raw == CHECK_RAW, op, "raw return verbatim");
        check_op(session.ledger.calls[op] == CHECK_RAW, op, "ledger cell verbatim");
        check_op(fake.calls == 1, op, "one call on refusal");
        check_op(outputs_are(&out, 0, 0, 0, 0, 0, 0), op, "refusal reports no outputs");
        check_op(session.ledger.abortedBy ==
                 (MAC2JBUSBFunctionOperationIsRepeatable((MAC2JBUSBFunctionOperation)op)
                      ? MAC2JBUSBFunctionOperationNone : op),
                 op, "abort attribution");
    }
}

static void callback_flags_map_to_their_own_scalars(void) {
    // One flag at a time, so swapping any two is visible.
    for (int which = 0; which < 3; which++) {
        MAC2JBUSBFunctionSession session;
        int32_t raw = 0;
        fresh(&session, true);
        check(MAC2JBUSBFunctionSetClassCommandCallbacks(
                  &session, 5, 1, callback_reference, 3, which == 0, which == 1,
                  which == 2, &raw) == MAC2JBUSBFunctionSuccess, "callbacks");
        check(fake.scalarCount == 3, "callback scalar count");
        for (int index = 0; index < 3; index++)
            check(fake.scalars[index] == (index == which ? 1u : 0u), "callback flag position");
    }
}

static void entries_enforce_the_open_gate_themselves(void) {
    MAC2JBUSBFunctionSession session;
    Outputs out;
    // Before the interface open, every other entry is refused by the gate
    // without placing a call and without spending its one attempt.
    fresh(&session, false);
    for (int op = 1; op < MAC2JBUSBFunctionOperationCount; op++) {
        int32_t raw = 77;
        memset(&out, 0, sizeof(out));
        check_op(invoke(op, &session, &raw, &out) == MAC2JBUSBFunctionInterfaceNotOpen,
                 op, "refused as not open");
        check_op(raw == MAC2JBUSBFunctionCallNotAttempted, op, "raw return untouched");
        check_op(fake.calls == 0, op, "no call placed before open");
        check_op(session.ledger.attempts[op] == 0, op, "attempt not consumed");
    }
    check(session.ledger.attempted == 0 && session.ledger.abortedBy ==
          MAC2JBUSBFunctionOperationNone, "gate refusals leave the ledger untouched");
    // The same entries then work once the open has succeeded.
    int32_t raw = 0;
    check(MAC2JBUSBFunctionInterfaceOpen(&session, 0, 1, &raw) == MAC2JBUSBFunctionSuccess,
          "open");
    check(MAC2JBUSBFunctionSetClass(&session, 3, 3, 0, &raw) == MAC2JBUSBFunctionSuccess,
          "set class after open");
    check(fake.calls == 2, "both calls placed");
    // The open itself is once only, and a second try places no call.
    check(MAC2JBUSBFunctionInterfaceOpen(&session, 0, 1, &raw) ==
          MAC2JBUSBFunctionAlreadyAttempted, "second open");
    check(raw == MAC2JBUSBFunctionCallNotAttempted && fake.calls == 2, "second open placed no call");
    check(MAC2JBUSBFunctionSetClass(&session, 3, 3, 0, &raw) ==
          MAC2JBUSBFunctionAlreadyAttempted && fake.calls == 2, "configuration is once only");

    // A refused open is not "not open yet": it aborts, and nothing else runs.
    fresh(&session, false);
    fake.status = CHECK_RAW;
    check(MAC2JBUSBFunctionInterfaceOpen(&session, 0, 1, &raw) ==
          MAC2JBUSBFunctionOperationRefused && raw == CHECK_RAW, "refused open");
    fake.status = 0;
    int placed = fake.calls;
    for (int op = 1; op < MAC2JBUSBFunctionOperationCount; op++) {
        memset(&out, 0, sizeof(out));
        check_op(invoke(op, &session, &raw, &out) == MAC2JBUSBFunctionOperationRefused,
                 op, "aborted after refused open");
    }
    check(fake.calls == placed, "no call after a refused open");
}

static void first_refusal_through_the_entries_aborts_the_rest(void) {
    MAC2JBUSBFunctionSession session;
    int32_t raw = 0;
    fresh(&session, true);
    check(MAC2JBUSBFunctionSetClass(&session, 3, 3, 0, &raw) == MAC2JBUSBFunctionSuccess,
          "class");
    fake.status = CHECK_RAW;
    check(MAC2JBUSBFunctionSetSubClass(&session, 4, 1, 0, &raw) ==
          MAC2JBUSBFunctionOperationRefused && raw == CHECK_RAW, "sub class refused");
    fake.status = 0;
    int placed = fake.calls;
    raw = 77;
    check(MAC2JBUSBFunctionSetProtocol(&session, 5, 1, 0, &raw) ==
          MAC2JBUSBFunctionOperationRefused, "protocol aborted");
    check(raw == MAC2JBUSBFunctionCallNotAttempted, "aborted entry reports not attempted");
    check(MAC2JBUSBFunctionCommit(&session, 11, &raw) == MAC2JBUSBFunctionOperationRefused,
          "commit aborted");
    uint64_t transferred = 9;
    check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
          MAC2JBUSBFunctionOperationRefused && transferred == 0, "transmit aborted too");
    check(MAC2JBUSBFunctionSetSubClass(&session, 4, 1, 0, &raw) ==
          MAC2JBUSBFunctionAlreadyAttempted, "refused entry is not retried");
    check(fake.calls == placed, "no call after the first refusal");
    check(session.ledger.abortedBy == MAC2JBUSBFunctionOperationSetSubClass,
          "first refusal named as aborter");
}

static void transmit_entries_repeat_and_report_count_apart(void) {
    MAC2JBUSBFunctionSession session;
    int32_t raw = 0;
    uint64_t transferred = 0, maxPacket = 0;
    fresh(&session, true);
    fake.produce[0] = 8; fake.produceCount = 1;
    for (uint32_t round = 1; round <= 3; round++) {
        transferred = 999;
        check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
              MAC2JBUSBFunctionSuccess, "write succeeds each time");
        check(transferred == 8 && raw == 0, "count and raw return separate");
        check(session.ledger.attempts[MAC2JBUSBFunctionOperationWritePipe] == round,
              "each write counted");
    }
    // A short write is a success with a smaller count, not an error code.
    fake.produce[0] = 4;
    check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
          MAC2JBUSBFunctionSuccess && transferred == 4 && raw == 0, "short write");
    // A failed write carries the error only in the raw return, stays
    // attempted-again-able and does not abort anything.
    fake.status = CHECK_RAW;
    fake.produce[0] = 0xDEAD;
    check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
          MAC2JBUSBFunctionOperationRefused, "failed write");
    check(transferred == 0 && raw == CHECK_RAW, "failed write reports no bytes");
    check(session.ledger.abortedBy == MAC2JBUSBFunctionOperationNone, "write failure does not abort");
    fake.status = 0;
    fake.produce[0] = 8;
    check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
          MAC2JBUSBFunctionSuccess && transferred == 8, "write after a failed write");
    // The packet size query repeats the same way.
    fake.produce[0] = 64;
    for (int round = 0; round < 2; round++)
        check(MAC2JBUSBFunctionPipeMaxPacketSize(&session, 17, 1, &maxPacket, &raw) ==
              MAC2JBUSBFunctionSuccess && maxPacket == 64, "max packet repeats");
    // A kernel that reports no output slot yields no count, not stale data.
    fake.produceCount = 0;
    transferred = 999;
    check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
          MAC2JBUSBFunctionSuccess && transferred == 0, "missing output slot");
    // A refused configuration selector still closes the transmit path.
    fake.status = CHECK_RAW;
    check(MAC2JBUSBFunctionCommit(&session, 11, &raw) == MAC2JBUSBFunctionOperationRefused,
          "commit refused");
    fake.status = 0;
    int placed = fake.calls;
    check(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, &transferred, &raw) ==
          MAC2JBUSBFunctionOperationRefused && fake.calls == placed, "write after abort");
}

static void entries_reject_bad_arguments_without_calling(void) {
    MAC2JBUSBFunctionSession session;
    int32_t raw = 0;
    uint64_t a = 1, b = 1, c = 1;
    // Each rejection gets its own opened session, because a rejected attempt
    // is still spent, and must place no call.
#define REJECTED(call, what) do { fresh(&session, true); \
    check((call) == MAC2JBUSBFunctionInvalidInput, what); \
    check(fake.calls == 0, what " placed a call"); } while (0)
    REJECTED(MAC2JBUSBFunctionAppendStandardDescriptor(&session, 6, 0x21, 0, NULL, 4, &raw), "null descriptor");
    REJECTED(MAC2JBUSBFunctionAppendNonstandardDescriptor(&session, 7, 0x22, 0, DESCRIPTOR, 0, &raw), "empty descriptor");
    static uint8_t huge[4097];
    REJECTED(MAC2JBUSBFunctionAppendNonstandardDescriptor(&session, 7, 0x22, 0, huge, sizeof(huge), &raw), "oversized descriptor");
    REJECTED(MAC2JBUSBFunctionSetClassCommandCallbacks(&session, 8, 1, NULL, 3, 1, 0, 0, &raw), "null reference");
    REJECTED(MAC2JBUSBFunctionSetClassCommandCallbacks(&session, 8, 1, callback_reference, 0, 1, 0, 0, &raw), "empty reference");
    REJECTED(MAC2JBUSBFunctionSetClassCommandCallbacks(&session, 8, 1, callback_reference,
                                                    kOSAsyncRef64Count + 1, 1, 0, 0, &raw), "oversized reference");
    REJECTED(MAC2JBUSBFunctionCreatePipe(&session, 10, 3, 1, 8, 10, 0, 0, NULL, &raw), "null pipe output");
    REJECTED(MAC2JBUSBFunctionCreateBuffer(&session, 18, 0, &a, &b, &c, &raw), "zero buffer size");
    REJECTED(MAC2JBUSBFunctionCreateBuffer(&session, 18, 8, &a, NULL, &c, &raw), "missing buffer output");
    REJECTED(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 0, 50, &a, &raw), "zero length write");
    REJECTED(MAC2JBUSBFunctionWritePipe(&session, 14, 1, 2, 8, 50, NULL, &raw), "write without count output");
    REJECTED(MAC2JBUSBFunctionPipeMaxPacketSize(&session, 17, 1, NULL, &raw), "packet size without output");
    // A buffer reply with the wrong number of outputs is not a buffer.
    fresh(&session, true);
    fake.produce[0] = 1; fake.produce[1] = 2; fake.produce[2] = 3; fake.produceCount = 2;
    check(MAC2JBUSBFunctionCreateBuffer(&session, 18, 8, &a, &b, &c, &raw) ==
          MAC2JBUSBFunctionSuccess && a == 0 && b == 0 && c == 0,
          "short buffer reply yields no values");
}

int main(void) {
    name_matching();
    name_validation();
    distinct_outcomes();
    open_rejects_bad_input();
    open_reports_absent_service();
    ledger_accepts_each_operation_once();
    configuration_requires_the_interface_open();
    refused_interface_open_aborts_everything();
    transmit_operations_repeat_without_aborting();
    scalar_output_never_carries_the_return_code();
    refusal_aborts_the_sequence();
    selectors_are_exposed_and_overridable();
    entries_reject_a_missing_session();
    scenarios = 13;
#define RUN(scenario) do { scenario(); scenarios++; } while (0)
    RUN(every_entry_marshals_its_arguments);
    RUN(callback_flags_map_to_their_own_scalars);
    RUN(entries_enforce_the_open_gate_themselves);
    RUN(first_refusal_through_the_entries_aborts_the_rest);
    RUN(transmit_entries_repeat_and_report_count_apart);
    RUN(entries_reject_bad_arguments_without_calling);
    if (failures) {
        fprintf(stderr, "FAIL added-function shim: %d check(s)\n", failures);
        return 1;
    }
    printf("PASS added-function matcher and interface operation entries: "
           "exact name match, name validation, absent vs denied distinct, "
           "one attempt per configuration operation, interface open required "
           "before configuration, refusal aborts the sequence, repeatable "
           "transmit path that does not abort it, transferred count split from "
           "the raw return, overridable reference selectors, and every entry's "
           "selector, scalars, struct input and output counts through recording "
           "fakes (%d scenarios)\n", scenarios);
    return 0;
}
