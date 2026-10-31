#ifndef MAC2JB_USB_RESTORE_CONTROLLER_SHIM_H
#define MAC2JB_USB_RESTORE_CONTROLLER_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Only the watchdog binary may link the publication implementation.
// A dry run creates and compares an in-process description without a USB write.
// Both paths require the exact controller registry ID and full live plist bytes.
typedef enum {
    MAC2JBUSBSuccess = 0,
    MAC2JBUSBInvalidInput = 1,
    MAC2JBUSBMissingAPI = 2,
    MAC2JBUSBControllerUnavailable = 3,
    MAC2JBUSBWrongController = 4,
    MAC2JBUSBDescriptionMismatch = 5,
    MAC2JBUSBSetFailed = 6,
    MAC2JBUSBBusCycleFailed = 7,
    // The requested added function name or configuration number was refused
    // before any controller write. Kept distinct from MAC2JBUSBInvalidInput so
    // the Swift side and the host tools can tell a bad request from a bad call.
    MAC2JBUSBFunctionRejected = 8
} MAC2JBUSBResult;

MAC2JBUSBResult MAC2JBUSBReconstructOrPublish(
    const uint8_t *livePlist,
    size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    bool publish,
    bool cycleBus,
    int32_t *setReturn,
    int32_t *busReturn
);

// Distinct opt-in candidate: clone the current opaque controller description,
// require its saved fields/functions to match the journaled original except
// the two observed post-publication scalar changes and replacement flag, then
// restore those scalars in memory before a guarded SetDescription. A dry run
// changes only the in-process clone; it never writes the controller or bus.
MAC2JBUSBResult MAC2JBUSBCloneOrPublish(
    const uint8_t *livePlist,
    size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    bool publish,
    bool cycleBus,
    int32_t *setReturn,
    int32_t *busReturn
);

// Additive publication: clone the current controller description, require it
// to be byte-equal to the journaled original exactly as MAC2JBUSBCloneOrPublish
// does, and only then append one named function last in the given
// configuration before a guarded SetDescription. The journaled original is the
// restore target and is never modified. A dry run appends into the in-process
// clone only; it never writes the controller or bus.
MAC2JBUSBResult MAC2JBUSBCloneAppendFunctionOrPublish(
    const uint8_t *livePlist,
    size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    const char *functionName,
    int32_t configurationNumber,
    bool publish,
    bool cycleBus,
    int32_t *setReturn,
    int32_t *busReturn
);

// Pure: deserialize a device-description plist, append one function last in the
// given configuration, and serialize the result. No IOKit, no controller. The
// caller owns *out and must free it with MAC2JBUSBFreeCapturedDescription.
// Same implementation the publication path above uses, so it is testable on a
// Mac with no device.
MAC2JBUSBResult MAC2JBUSBAppendFunctionToDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber,
    uint8_t **out, size_t *outLength
);

// Read-only: the configuration number the host has currently selected on the
// exact controller, from CurrentState.SelectedConfiguration. Success only when
// that value is a typed number greater than zero; the number is never assumed.
MAC2JBUSBResult MAC2JBUSBCopySelectedConfiguration(
    uint64_t expectedControllerRegistryID, int32_t *configurationNumber
);

// Read-only capture of the sole controller's live registry description.
// The caller owns the returned malloc buffer and must free it with
// MAC2JBUSBFreeCapturedDescription. No controller user client is opened.
MAC2JBUSBResult MAC2JBUSBCaptureLiveDescription(
    uint8_t **bytes, size_t *length, uint64_t *controllerRegistryID
);
// Read-only sole-controller identity lookup that does not depend on the live
// description shape; the watchdog uses it to restart after publication.
MAC2JBUSBResult MAC2JBUSBCaptureControllerRegistryID(uint64_t *controllerRegistryID);
// Read only CurrentState from that exact controller. Returns success only
// when the state fields are typed and available; configured is true only when
// DeviceState, OnBus and SelectedConfiguration all indicate enumeration.
MAC2JBUSBResult MAC2JBUSBCopyConfiguredState(
    uint64_t expectedControllerRegistryID, bool *configured
);
// Read-only: write a comma-separated list of USBDeviceFunction names whose
// IOUSBDeviceInterface nub under the exact controller has no IOService client
// (the registry signature of a function that failed to register after a
// description swap). Empty string when every nub is served.
MAC2JBUSBResult MAC2JBUSBCopyUnservedFunctions(
    uint64_t expectedControllerRegistryID, char *names, size_t capacity
);
// Read-only: one line per IOUSBDeviceInterface nub under the exact controller,
// "function\tclientClass\tcreator\n" per client (creator is the raw
// IOUserClientCreator string or empty), or "function\t\t\n" for an unserved
// nub. Used to learn the device profile; never opens a user client.
MAC2JBUSBResult MAC2JBUSBCopyFunctionClients(
    uint64_t expectedControllerRegistryID, char *lines, size_t capacity
);
void MAC2JBUSBFreeCapturedDescription(uint8_t *bytes);

#endif
