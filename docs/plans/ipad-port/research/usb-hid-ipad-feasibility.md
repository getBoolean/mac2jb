# USB HID device mode on the M2 iPad Pro target

> **SUPERSEDED 2026-11-02.** This was the pre-trial source hypothesis. Exact-device
> trials disproved its generic-userspace bridge: an arbitrary or stock-named
> userspace-configured function does not enumerate because `createUSBDevice`
> requires an in-kernel driver match. The current source-only kernel candidate
> verdict is in [`kernel-gadget-candidate-matrix.md`](kernel-gadget-candidate-matrix.md);
> retained device evidence is in
> [`../../../ipad/target-device-findings.md`](../../../ipad/target-device-findings.md).

Date: 2026-10-28  
Target: M2 iPad Pro 12.9-inch (6th generation), `iPad14,5` / `J620AP` / `T8112`, iPadOS 17.0, Dopamine, TrollStore

## Verdict

The sources originally established a testable userspace hypothesis and justified a recoverable canary. The completed exact-device trials disproved that hypothesis on this target. The iPad is USB-device capable and privileged userspace can replace a controller description, but a described function still needs an in-kernel driver match before the configuration reaches the bus.

The controller did materialize the interface and authorize the class, descriptor, endpoint, buffer, callback, commit, and write operations, but it did not bring either the arbitrary name or the stock `Keyboard` name on bus. Direct USB HID now depends on finding a reversible kernel-matched function candidate; the source-only gate found none.

## Evidence chain

1. **iPadOS uses USB device mode.** iOS 17’s `configd` loads `/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist`, creates a controller description, and sends named configurations to `IOUSBDeviceController`. Those configurations expose device-side Mux, PTP, NCM, audio, camera, and test functions. See [Synacktiv’s iOS 17 stack analysis](https://www.synacktiv.com/publications/ios-a-journey-in-the-usb-networking-stack).

2. **The controller is mutable from entitled userspace.** Apple-derived headers expose `IOUSBDeviceControllerSetDescription`, live/default description creation, and off/on-bus re-enumeration. Historical iOS code publishes a description and opens the resulting named `IOUSBDeviceInterface`: [header](https://github.com/nabla-c0d3/iphone-dataprotection/blob/master/ramdisk_tools/IOUSBDeviceControllerLib.h), [working iOS call sequence](https://github.com/nabla-c0d3/iphone-dataprotection/blob/master/ramdisk_tools/restored_external.c).

3. **The private API is not merely historical.** `vphone-cli` dynamically resolves the controller APIs, reads the live description, sets `AllowMultipleCreates`, republishes it, and cycles the bus. Its implementation documents the required `com.apple.private.usbdevice.setdescription` entitlement: [vphoned_usb.m](https://github.com/Lakr233/vphone-cli/blob/main/VPhoneDaemon/Native/vphoned_usb.m).

4. **The Mac kext is not a HID driver.** In `vendor/macos_usb_gadget_poc/usbgadget/usbgadget/Info.plist`, the kext matches `IOUSBDeviceController`. In `usbgadget.cpp`, it forwards a `SetDeviceConfiguration` dictionary to that controller from a kernel thread. It contains no HID report descriptor, endpoint implementation, or function-driver personality. Upstream says this bypasses the controller entitlement check; the local code alone proves forwarding, not equivalence to an entitled iPadOS caller.

5. **The macOS controller materializes a generic service that userspace configures.** In `vendor/libusbd/src/plat/macos/impl.c`, userspace appends an arbitrary generated function name, publishes the controller description, waits for an `IOUSBDeviceInterface` with the same `USBDeviceFunction`, opens `IOUSBDeviceInterfaceUserClient`, and invokes the interface’s class, descriptor, pipe, buffer, commit, and write operations. `sender.c` supplies the boot-keyboard descriptor and eight-byte reports. This proves that the demonstrated macOS path does not depend on a stock `AppleUSBDeviceHID` driver; whether iPadOS behaves the same is the first canary gate.

6. **The authorization can be carried on the target.** TrollStore explicitly supports iOS 17.0 and preserves arbitrary entitlements other than its documented banned set. `com.apple.private.usbdevice.setdescription` is not in that banned set; TrollStore also documents the IOKit exception requirement for platform applications. See the [TrollStore README](https://github.com/opa334/TrollStore#features). Dopamine provides the rootless service/package boundary needed for a durable broker and watchdog.

7. **The generic user client exists on iOS.** Published iOS kernel and entitlement inventories identify `IOUSBDeviceInterfaceUserClient`, including modern Apple daemons that receive an exception for it. This establishes continuity of the interface family, though the selector ABI must still be measured on the exact 17.0 build.

## What the evidence disproves

- The macOS generic-userspace behavior does not transfer to this iPadOS target. Here, a function requires an in-kernel match; no source identifies a suitable reversible HID gadget driver or reusable stock report transport.
- `IOHIDUserDevice` is not the correct mechanism; it creates a local virtual HID device and does not expose the iPad as a USB peripheral.
- Possessing only the HID report descriptor is insufficient. Controller publication, generic-interface creation, user-client access, endpoint creation, host control requests, USB-C role negotiation, and restoration must all pass.
- Bluetooth HID, a Mac relay, or an ESP32 bridge may prove the Switch accepts a keyboard, but does not prove direct iPad USB device mode.

## Exact-device proof protocol

The proof should advance only when the previous step has preserved a recovery path:

1. Record the exact ProductType, board, iPadOS build, controller ancestry, active functions, cable, and peer.
2. Resolve and read the live/default controller descriptions without mutation.
3. Verify the signed helper carries `com.apple.private.usbdevice.setdescription` and the exact `IOUSBDeviceInterfaceUserClient` exception; record the first denied boundary.
4. Exercise a no-op republish and re-enumeration, then externally verify usbmux, trust, charging, networking, and the original descriptors.
5. Append a unique generic function name and require a same-controller `IOUSBDeviceInterface` with the matching `USBDeviceFunction` property.
6. Open its user client and test class/subclass/protocol, HID descriptor append, report descriptor append, interrupt-IN pipe creation, buffer creation, callbacks, and commit individually.
7. On a generic Linux/macOS capture host, require a class-3/subclass-1/protocol-1 interface, the expected report descriptor, successful HID control requests, and exact eight-byte press/neutral reports.
8. Run crash, disconnect, sleep, respring, userspace reboot, and hard-reboot restoration tests before connecting the Switch.
9. Connect directly to the Switch, prove the iPad enters peripheral role, repeat enumeration capture where possible, and send only a harmless canary string on the keyboard screen.

Passing step 7 proves direct USB HID on the iPad. Passing step 9 proves the iPad-to-Switch path required by mac2jb.

## Remaining risks

- iPadOS 17.0 may retain the generic class but change the user-client selectors or deny one of the endpoint operations.
- Evidence is bound to `iPad14,5` / `J620AP` / `T8112`; proof from another ProductType or SoC does not cover this target.
- Two USB-C dual-role devices may choose an unusable role or power contract with a particular cable/orientation.
- Replacing or extending the active description can remove usbmux, trust, or networking until reboot. The first mutation must follow a tested hard-reboot/re-jailbreak recovery drill and a durable restore journal.
- The Switch may reject a descriptor that a desktop host accepts. Desktop capture is necessary but not sufficient.
