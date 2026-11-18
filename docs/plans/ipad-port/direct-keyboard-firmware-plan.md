# Direct USB keyboard feasibility on iPadOS 17.0 (21A329)

## Decision

Keep the M2 iPad in its stock configuration while identifying whether a shipping component supplies keyboard reports. Success means an ordinary desktop host sees a USB keyboard and receives one user-selected key press and release over the cable. The existing same-boot recovery requirement applies to any later device experiment.

## Evidence from the restore image

The system USB configuration plist has 29 named profiles. Only standardKeyboard lists the literal Keyboard function. Its entry contains a description, a default-configuration flag and the interface names AppleUSBMux and Keyboard. It contains no HID report descriptor or producer identifier. IapOverUsbHid occurs in eight other profiles, including standardMuxPTP and DeviceModeCarplay. This makes a saved stock host capture a potentially useful source of its descriptor.

PTP provides a positive control. Its launch daemon matches the PTP function on IOUSBDeviceInterface. The ptpd executable contains both matching-property strings and Objective-C type metadata for PTPDeviceUSBCore holding an IOUSBDeviceInterfaceInterface reference. Together these connect the launch declaration to an executable that represents the device-side interface. They do not establish every operation needed for enumeration. The equivalent Keyboard ownership chain remains unidentified. The kernel catalogue and host observations are detailed in [target findings](../../ipad/target-device-findings.md).

## Investigation and decision points

1. **Identify a producer offline.** Use PTP to check search coverage across launch configuration, executable metadata, and libraries in the system dyld cache. Look for a component associating Keyboard with the USB device interface and a keyboard report source. Record the image, component and evidence linking the two. A profile reference or a local keyboard event consumer alone is insufficient. A negative result with unsearched cache images remains inconclusive.
2. **Classify the stock accessory interface independently.** Look in existing external-host captures for the HID report descriptor associated with the stock accessory interface. Inspect its application collection and input fields. If only accessory-specific reports are described, retire that configuration as a ready-made keyboard. If a keyboard collection exists, identify its input producer before proposing a trial. A missing descriptor leaves the question open.
3. **Decide whether a device trial can add evidence.** Proceed only when a candidate explains function ownership, keyboard report generation and same-boot restoration by a surviving owner. Otherwise record which link is missing. Repeating the five userspace trials would not test a different mechanism.
4. **Validate on an ordinary desktop host if separately authorized.** Independently observe the interface descriptor, a keyboard application collection, one intentional key press and release in a text editor, and return of the stock USB configuration. Correlate observations with the publication interval. A local success status or a generic USB arrival cannot satisfy this check.
