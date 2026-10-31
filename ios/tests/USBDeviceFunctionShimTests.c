// Mac-only tests for the added-function matcher and the interface operation
// entries. Nothing here publishes a description, opens a user client on a real
// gadget interface, or sends a keystroke: the matcher is exercised against a
// name that cannot exist, and the operation entries are exercised through the
// same attempt ledger the real entries use.

#include "../usb/USBDeviceFunctionShim.h"

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
    require(result == MAC2JBUSBFunctionServiceAbsent ||
            result == MAC2JBUSBFunctionMissingAPI ||
            result == MAC2JBUSBFunctionControllerUnavailable);
    if (result == MAC2JBUSBFunctionServiceAbsent) {
        require(openReturn == MAC2JBUSBFunctionCallNotAttempted);
    }
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
    if (failures) {
        fprintf(stderr, "FAIL added-function shim: %d check(s)\n", failures);
        return 1;
    }
    printf("PASS added-function matcher and interface operation entries: "
           "exact name match, name validation, absent vs denied distinct, "
           "one attempt per configuration operation, interface open required "
           "before configuration, refusal aborts the sequence, repeatable "
           "transmit path that does not abort it, transferred count split from "
           "the raw return, overridable reference selectors\n");
    return 0;
}
