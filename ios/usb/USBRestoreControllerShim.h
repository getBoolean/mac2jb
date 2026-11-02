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
// expectedFunctionName is the one function a previous additive publication
// appended, or NULL. When given, exactly that name is removed from
// expectedConfigurationNumber's Interfaces array before the comparison, and the
// call is refused if that name is not the last element there; nothing else can
// be dropped. With NULL the behaviour is unchanged.
MAC2JBUSBResult MAC2JBUSBCloneOrPublish(
    const uint8_t *livePlist,
    size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    const char *expectedFunctionName,
    int32_t expectedConfigurationNumber,
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

// Re-publish the intended additive description: the journaled original plus
// the one named function, in a single SetDescription, whatever the live
// description currently carries. It accepts both shapes the healer can meet -
// a live description still carrying the appended name last in that
// configuration (stripped before the equality check, then re-appended) and one
// already restored to stock (compared as-is, then appended). Any other
// difference from the journaled original is still refused, and the journaled
// original remains the restore target and is never modified.
//
// This is the continuing kind of re-publication. Restoring - an expired lease,
// a dead worker, a watchdog restart, an explicit restore - still publishes the
// bare original through MAC2JBUSBCloneOrPublish, because the bus coming back
// matters more than the function surviving.
MAC2JBUSBResult MAC2JBUSBCloneRepublishAppendedFunctionOrPublish(
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

// Exclusive / usbmux-preserving publication (parent plan U4): clone the live
// description, require it byte-equal to the journaled original exactly as the
// additive path does, then replace the given configuration's interface list
// with the provided names before a guarded SetDescription. The journaled
// original is the restore target and is never modified; restore pushes it back
// with MAC2JBUSBSetStoredDescriptionOrPublish, since the replaced interface
// list cannot be stripped back to it. A dry run edits the in-process clone only.
MAC2JBUSBResult MAC2JBUSBCloneSetInterfacesOrPublish(
    const uint8_t *livePlist, size_t livePlistLength,
    uint64_t expectedControllerRegistryID,
    const char *const *interfaceNames, size_t interfaceCount, int32_t configurationNumber,
    bool publish, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
);

// Restore an interface-list-replacement publication by pushing the exact stored
// stock description bytes back through SetDescription, with no clone-and-compare
// (the live description no longer resembles the original, so nothing can be
// stripped back to it). The stored bytes are the journaled original captured at
// prepare time. Controller identity is checked; AllowMultipleCreates is set as
// the publish path does; the raw IOReturn of the optional cycle is reported.
MAC2JBUSBResult MAC2JBUSBSetStoredDescriptionOrPublish(
    const uint8_t *storedPlist, size_t storedPlistLength,
    uint64_t expectedControllerRegistryID, bool cycleBus,
    int32_t *setReturn, int32_t *busReturn
);

// Take the exact controller off and on the bus and do nothing else: no
// description is created, compared, edited or written. Publishing a description
// already cycles the bus, so the host reads the configuration descriptor at
// that moment - before an appended interface has a class, descriptors or
// endpoints. Committing the interface afterwards changes only the device's own
// state, so the host never re-reads the configuration and never requests a
// report descriptor. This is the one call that makes the device re-present
// itself so the host enumerates again. The raw IOReturn of the cycle is
// written to *busReturn verbatim whatever it is.
MAC2JBUSBResult MAC2JBUSBCycleControllerBus(
    uint64_t expectedControllerRegistryID,
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

// Pure inverse of the above, and the same removal the clone restore path runs:
// drop one function name from the given configuration's Interfaces array and
// change nothing else. Refused unless that name is the array's last element,
// so no other interface can ever be dropped. No IOKit, no controller; the
// caller owns *out and frees it with MAC2JBUSBFreeCapturedDescription.
MAC2JBUSBResult MAC2JBUSBRemoveFunctionFromDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber,
    uint8_t **out, size_t *outLength
);

// Pure: the exclusive-HID shape (parent plan U4). Deserialize the description,
// replace the given configuration's Interfaces array with exactly one name -
// the function alone, every stock function removed from that configuration -
// and serialize the result. Only that one configuration is changed; device
// scalars and every other configuration are untouched, so the journaled
// original restores the stripped stock functions by a plain republish. No
// IOKit, no controller; the caller owns *out and frees it with
// MAC2JBUSBFreeCapturedDescription.
MAC2JBUSBResult MAC2JBUSBSetSoleFunctionInDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *functionName, int32_t configurationNumber,
    uint8_t **out, size_t *outLength
);

// Pure, and the general form of the sole-function edit: replace the given
// configuration's Interfaces array with exactly the provided list of names.
// The caller chooses the list - the HID function alone (exclusive), or a
// lighter stock subset plus the HID function (for example PTP + AppleUSBMux +
// the keyboard, keeping the usbmux lifeline up during a trial). Names must each
// be legal and distinct, 1 to 32 of them; device scalars and every other
// configuration are untouched. No IOKit; caller owns *out and frees it with
// MAC2JBUSBFreeCapturedDescription.
MAC2JBUSBResult MAC2JBUSBSetConfigurationInterfacesInDescriptionData(
    const uint8_t *plist, size_t plistLength,
    const char *const *interfaceNames, size_t interfaceCount,
    int32_t configurationNumber, uint8_t **out, size_t *outLength
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
