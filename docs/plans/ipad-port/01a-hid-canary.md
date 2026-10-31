---
title: iPad HID Canary (U3) - Plan
type: feat
date: 2026-10-31
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
parent_plan: docs/plans/ipad-port/01-hardware-feasibility.md
plan_order: 1a
execution_after: docs/plans/ipad-port/01-hardware-feasibility.md
---

# iPad HID Canary (U3) - Plan

Expands U3 of [the hardware feasibility plan](01-hardware-feasibility.md) into ordered tasks. The parent plan owns the Product Contract; this plan owns HOW. It inherits R4–R10, AE2, AE3 and KTD1–KTD9 unchanged, and adds no product scope.

## Goal Capsule

- **Objective:** Let someone bootstrap mac2jb from the iPad alone, by making the iPad type into the Switch as a USB keyboard and always come back to a working USB connection afterwards.
- **Means:** Add one HID function to the description the U2 broker already journals and restores, proving each private-API operation separately, on a generic host first and the Switch second.
- **Authority:** R4–R10 are release gates. This plan may choose how to prove them; it may not weaken them.
- **Stop conditions:** Stop at the first operation the controller refuses, and record it. Stop before the Switch until a generic host has captured correct descriptors and reports. Stop if a HID publication cannot be restored automatically.

---

## Problem Frame

U2 proved the broker can replace the USB device description and recover automatically when functions fail to re-register. Every publication so far has been a **no-op**: the description published is byte-equal to the journaled original, so the function list never changes.

U3 changes the description's content for the first time. It appends one new function name, and then needs that function to materialize as an `IOUSBDeviceInterface` service that userspace can open and configure into a boot keyboard. On the demonstrated Apple-silicon Mac stack (`vendor/libusbd/src/plat/macos/impl.c`) userspace does all of this through `IOUSBDeviceInterfaceUserClient` selectors. Whether this iPad's controller materializes an **arbitrary** named function, and authorizes the class, descriptor, pipe, buffer, callback and commit operations on it, is unproven and cannot be settled from sources.

Two U1 results frame the risk precisely:

- With the `IOUSBDeviceInterfaceUserClient` exception, **all 32 opens of the 16 existing interfaces succeeded**; every other profile was denied. Opening an interface user client on this device is therefore already proven.
- Controller user-client opens (types `0` and `123`) returned `-536870201` (unsupported) in every profile. The Mac backend's `IOServiceOpen(..., 123, ...)` is the **interface** open, which is the one that works; the controller path is not available and is not needed, since the broker owns publication.

So the unknowns are narrower than "can the iPad do HID": a new name must appear as a service, and its user client must accept configuration selectors. The second risk is behavioural: publishing a changed description re-runs the function-registration race U2 characterized, now with one more function, and the new function has no kernel driver to serve it.

## Requirements traceability

Inherited from the parent plan; this plan adds no requirements.

| Inherited | Where this plan satisfies it |
|---|---|
| R4 standards-compliant boot keyboard, one interrupt-IN endpoint, 8-byte reports | U3.4, U3.6 |
| R5 additive HID on top of the proven no-op recipe | U3.2, U3.3 |
| R6 fsynced checksummed restore recipe before publication | existing broker journal, unchanged (U3.2) |
| R7 single-writer broker restores on every failure path | existing broker, extended by U3.2; U3.8 |
| R8 short lease, neutral report on controlled exit, broker-only journal deletion | U3.5, U3.7 |
| R9 publication gate: matching interface appears, opens least-privileged, HID operations succeed | U3.3, U3.4 |
| R10 generic-host capture of descriptors and HID control requests before the Switch; propagate every error | U3.6; U3.9 |
| AE2 type `MAC2JB`, correct press/release reports, original description restored | U3.6, U3.7 |
| AE3 kill the canary mid-flight; the broker restores and keeps evidence | U3.8 |

## Key Technical Decisions

- **KTD-A. Extend the existing broker; do not add a second controller writer.** The broker in `ios/watchdog/` already owns the journal, the lease, the readiness gate and automatic healing, which R7 and R8 require. A HID publication becomes new broker commands, not a new process. *Rationale:* a second writer would break the single-writer invariant U2 passed on. (Parent KTD4, KTD1.)
- **KTD-B. Learn the HID function's identity; do not compile in a name.** The appended function name, its interface, and the selector numbers that worked go into the learned device profile (`ios/watchdog/USBDeviceProfile.swift`), like the owner map. *Rationale:* the product goal is all jailbroken/TrollStore USB-C devices, and the parent plan's scope boundary forbids baking in reference-device constants. The Mac backend generates a random name per run; a stable learned name is better for the healer, which must recognize the function across re-publications.
- **KTD-C. Treat the new function as owner-less and expect the healing gap.** U2's healer restarts a *user-space owner* when a function fails to register. The HID function's owner is our own canary, so the profile must record it as self-owned, and the healer must be able to restart it like any other owner. *Rationale:* without this the first HID publication hits the same race U2 characterized with no remedy, and the broker falls back to bounded re-publication only.
- **KTD-D. Probe selectors one at a time against a recorded matrix, from the Mac backend's numbering as hypotheses.** `impl.c` uses: open `0`, close `1`, set-description `2`, class `3`, subclass `4`, protocol `5`, standard descriptor `6`, nonstandard descriptor `7`, class-command callbacks `8`, complete-callback `9`, create-pipe `10`, commit `11`, read `13`, write `14`, stall `15`, abort `16`, max-packet `17`, create-buffer `18`, release-buffer `19`, pipe property `27`. *Rationale:* parent KTD7 forbids copying a private ABI blindly; these are observations to test on this build, and the ABI may differ.
- **KTD-E. Reuse the corrected HID fixtures as golden tests, not by linking the Mac backend.** Take the 9-byte HID descriptor, the 65-byte report descriptor, the boot-keyboard tuple (3/1/1), the 8-byte report shape and the report-length fix from `sender.c`, and the report validation from `keyboard.c`. Do not compile `vendor/libusbd`. *Rationale:* parent KTD8; the Mac backend destructively removes stock configurations, suppresses errors, declares `0xA0/255` power and omits a VID, none of which may reach the iPad path.
- **KTD-F. Prove enumeration from the host, never from a successful endpoint write.** A write returning success is not proof. *Rationale:* R10 states this, and U2 taught the same lesson for publication (API success was never recovery).
- **KTD-G. No SmileBASIC text encoding in U3.** U3 types a fixed canary string. Indentation handling and the bootstrap belong to later units. *Rationale:* parent scope boundary.

## Implementation Units

Ordered. Each unit ends with the device in a state the broker can restore, and the first failing operation is recorded rather than worked around. A device trial runs only when the Current state block in `docs/ipad/target-device-findings.md` allows it.

### U3.1 Learn and extend the device profile for a HID function

- **Goal:** the profile can describe an added function and its self-owner before any publication.
- **Files:** `ios/watchdog/USBDeviceProfile.swift`, `ios/tests/USBDeviceProfileTests.swift`, `docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-device-profile.py`
- **Approach:** add an optional `addedFunctions` section recording the function name, its interface's observed selector results, and that its owner is this port's canary. Keep `schemaVersion` migration explicit: a learned v2 profile stays valid and gains the section empty.
- **Test scenarios (Mac-only):** a v2 profile loads and validates unchanged; an added function round-trips through the store; a profile naming an added function absent from the live function list fails validation; the healer policy derived from a profile with a self-owned function restarts that owner and not another.

### U3.2 Add an additive-publication path to the broker

- **Goal:** the broker can publish `original + one named function`, journal the original unchanged, and restore it on every existing failure path.
- **Files:** `ios/usb/USBRestoreControllerShim.c/.h`, `ios/watchdog/TargetUSBRestoreController.swift`, `ios/watchdog/USBRestoreCoordinator.swift`, `ios/watchdog/NativeUSBWatchdogService.swift`, `ios/tests/NativeUSBWatchdogServiceFixture.swift`
- **Approach:** a new shim entry clones the live description, appends one function to the configuration list that mac2jb will use, and publishes. The journal still holds the **unmodified** original, so restore semantics are untouched. Add a `publish-hid <name>` command beside `publish-noop`, under the same lease and readiness gate. The restore path, the healer and `confirm` are unchanged.
- **Test scenarios (Mac-only fixture):** the published description equals the original plus exactly one function; the journal is byte-equal to the original; worker death, watchdog restart and lease expiry each restore the original; `publish-hid` is refused without a lease, with an existing journal, or when the name is already present; a malformed name is rejected before any controller call.
- **Device trial:** publish with the appended name and **no** interface configuration, then let the broker restore. This isolates "does a changed description still recover" from HID itself. Verify with the strict external check.

### U3.3 Prove the function materializes and its user client opens

- **Goal:** settle R9's first half on this device.
- **Files:** `ios/usb/USBDeviceFunctionShim.c/.h` (new), `docs/plans/ipad-port/scripts/ipad-hardware/host/read-u2-added-function-wifi.py` (new), matching `device/` payload
- **Approach:** after U3.2's publication, match `IOUSBDeviceInterface` by `USBDeviceFunction` equal to the appended name, require it under the same controller (the census already walks that subtree), then `IOServiceOpen` it with the `IOUSBDeviceInterfaceUserClient` exception that U1 proved sufficient for existing interfaces. Record the raw `IOReturn` at each step.
- **Test scenarios:** a name that never appears is reported as absent, not as success; a service under a different controller is rejected; an open failure records its raw code and leaves the description restorable. Fixture-level: the matcher rejects a property match that is a prefix or case variant of the name.
- **Stop condition:** if no matching service appears, or the open is denied, record the boundary and stop. That is an R9 failure, and U4's exclusive-HID fallback becomes the question.

### U3.4 Map the interface operation matrix one selector at a time

- **Goal:** know exactly which HID operations this build authorizes, with raw returns.
- **Files:** `ios/usb/USBDeviceFunctionShim.c`, `docs/ipad/hid-operation-matrix.md` (new, redacted)
- **Approach:** exercise, individually and in KTD-D order: set class 3, subclass 1, protocol 1; append the 9-byte HID descriptor (standard, type `0x21`); append the 65-byte report descriptor (nonstandard, type `0x22`); create one interrupt-IN pipe, 8-byte max packet, interval 10; create a buffer; register class-command callbacks; commit. Record every `IOReturn` and stop at the first refusal. Treat the selector numbers as hypotheses: if one returns an unsupported/bad-selector code, record it and probe the neighbouring numbers before concluding the operation is unavailable.
- **Test scenarios:** each operation is attempted at most once per run; a refusal aborts the remaining sequence; the recorded matrix contains no device identifiers; the broker can still restore afterwards.
- **Output:** the matrix doc plus the learned profile's selector record (KTD-B).

### U3.5 Add the lease-bound canary process

- **Goal:** a separate, least-privileged process that holds a lease, configures the function and writes reports, per R8 and KTD1.
- **Files:** `ios/canary/` (new: main, HID report model, lease client), `ios/entitlements/canary-interface.plist` (new: `platform-application` plus the interface-class exception only; **no** set-description), `ios/tests/HIDReportTests.swift` (new)
- **Approach:** the canary never publishes a description and never writes the journal; it asks the broker for a lease, configures the already-published function, writes reports, and on every exit path sends a neutral report and returns the lease. Reuse `keyboard.c`'s validation rules: no modifier-only garbage, no duplicate keycodes, no gaps, keycodes in range.
- **Test scenarios (Mac-only):** golden-test the 9-byte HID descriptor including the corrected report-length bytes, the 65-byte report descriptor, the 3/1/1 tuple, the 8-byte report shape and the VID/PID policy; reject an invalid report before any write; a controlled exit emits exactly one neutral report; lease expiry stops writes; three bounded neutral attempts on disconnect.

### U3.6 Generic-host enumeration and report capture

- **Goal:** settle R4, R10 and the report half of AE2 on a host we can observe.
- **Files:** `docs/plans/ipad-port/scripts/ipad-hardware/host/capture-u2-hid-enumeration.py` (new), reuse `host/u2-usb-lifecycle-monitor.swift` and `host/u2-readonly-raw-config-descriptors.c`
- **Approach:** with the iPad on the Mac, capture the new interface's descriptors from the host side (class 3, subclass 1, protocol 1; the expected report descriptor; one 8-byte interrupt-IN endpoint), record the host's HID control requests where observable, then have the canary type `MAC2JB` and compare every report against the expected press/release sequence.
- **Test scenarios:** a missing or mismatched report descriptor fails; an extra or missing report fails; a host that never enumerates is reported as not-enumerated rather than as a pass; the capture contains no serial or UDID.
- **Gate:** passing this unit is the proof that direct USB HID works on this iPad.

### U3.7 Restoration after HID, verified externally

- **Goal:** AE2's restoration half and R8's journal rule, on the HID path.
- **Approach:** after U3.6, have the broker restore the original description, then run the strict external check (`host/check-u2-trial-current.py`) and confirm the journal only with that check's output as proof, exactly as U2 trials do.
- **Test scenarios:** restoration returns the original function list with no HID function; the strict check passes including resolved strings and NCM packet flow; the journal is cleared only after that; a failed check leaves the journal and reports recovery-required.

### U3.8 Fault trials on the HID path

- **Goal:** AE3 and R7 with a changed description, which is harder than U2's no-op.
- **Files:** `docs/plans/ipad-port/scripts/ipad-hardware/host/run-u2-hid-trial-wifi.py` (new, modelled on `run-u2-noop-trial-auto-heal-wifi.py`)
- **Approach:** repeat U3.6's publication under each fault: kill the canary while configuring, while enumerated, and while actively writing; kill the broker; let the lease expire; disconnect the cable mid-press. Each must end with the original description restored automatically and the strict check passing. Record how often healing needed a re-publication or an owner restart, since the added function changes the race.
- **Test scenarios:** each fault state is exercised separately; a neutral report is attempted before restoration on controlled exits; no fault path confirms a journal; the HID function is absent after every restore.

### U3.9 Direct Switch run

- **Goal:** the mac2jb path itself.
- **Approach:** owner-assisted. Move the cable to the Switch 2, prove the iPad still enters peripheral role (the existing Type-C and controller readers already do this), open the keyboard screen, and type a harmless canary string. The Switch gives no host-side capture, so the evidence is the device-side state plus the owner's observation of typed characters.
- **Test scenarios:** refuse to run unless U3.6 has passed on a generic host; refuse without a recorded peer and orientation; restoration verified after the run.

## Verification Contract

- **Unit level:** the Mac-only fixtures in each unit, runnable with no device.
- **Gate level (R4–R10, AE2, AE3):** thirty generic-host cycles and thirty direct Switch keyboard-screen cycles pass with exact descriptor and report capture and externally verified restoration, as the parent plan's U3 verification states. A neutral endpoint write without host-side enumeration evidence does not count.
- **Not evidence:** a successful endpoint write, a broker "published" reply, or `awaitingVerification`.

## Risks and Mitigations

- **The new name never materializes.** Most likely failure. Mitigation: U3.3 isolates it before any HID configuration, and U4 (exclusive HID) is the recorded fallback.
- **Selector ABI differs from the Mac backend.** Mitigation: KTD-D probes one at a time and records raw returns; neighbouring selector numbers are probed before declaring an operation unavailable.
- **The added function worsens the registration race, and it has no kernel driver.** Mitigation: KTD-C records it as self-owned so the healer can restart the canary; U3.2's trial publishes the name with no configuration to measure the race alone.
- **A changed description could lose usbmux or networking for longer than a no-op did.** Mitigation: every HID trial takes a fresh restore kit first and runs under the same automatic recovery U2 proved; the owner-assisted reboot path remains the backstop.
- **The Switch rejects a descriptor the Mac accepts.** Mitigation: U3.9 is a separate gate after U3.6; desktop capture is necessary but not sufficient.
- **Entitlement creep.** Mitigation: the canary gets the interface-class exception only; publication authority stays in the broker.

## Open Questions

- Does the broker's clone-and-publish path accept an appended function in the configuration list, or does the controller validate configurations against the stock source? Settled by U3.2's device trial.
- Does the added interface need its own `AllowMultipleCreates` handling, or is the existing flag enough? Settled in U3.2.
- Can the healer restart our own canary as a function owner, or does a self-owned function need a different remedy? Settled by U3.8's fault counts.

## Sources and Research

- Parent plan and its Product Contract: [`01-hardware-feasibility.md`](01-hardware-feasibility.md). Feasibility note: [`research/usb-hid-ipad-feasibility.md`](research/usb-hid-ipad-feasibility.md), whose nine-step proof protocol this plan's unit order follows.
- U1 authorization evidence (the `interface-client` profile opened all 32 existing function user clients; controller opens were unsupported in every profile): `docs/ipad/hardware-matrix.md`, with the per-profile table in git history before `4a4c876`.
- U2 mechanism and broker behaviour: [`../../ipad/usb-auto-recovery.md`](../../ipad/usb-auto-recovery.md), [`../../ipad/usb-recovery.md`](../../ipad/usb-recovery.md).
- Repository fixtures to reuse: `sender.c` (HID descriptor, report descriptor, corrected report length, boot-keyboard tuple, enumeration-wait shape), `keyboard.c` (bounded 8-byte report validation).
- Mac backend selector sequence and generic-interface matching: `vendor/libusbd/src/plat/macos/impl.c` (`libusbd_impl_config_finalize`, `libusbd_impl_iface_finalize`, and the `IOUSBDeviceInterface_*` wrappers).
- Historical iOS publication plus named-interface open: <https://github.com/nabla-c0d3/iphone-dataprotection/blob/master/ramdisk_tools/restored_external.c>.
