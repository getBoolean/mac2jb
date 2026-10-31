---
title: iPad HID Canary (U3) - Plan
type: feat
date: 2026-10-31
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
parent_plan: docs/plans/ipad-port/01-hardware-feasibility.md
plan_order: 1c
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
| R4 standards-compliant boot keyboard, one interrupt-IN endpoint, 8-byte reports | U3.4, U3.9 |
| R5 additive HID on top of the proven no-op recipe | U3.2, U3.6 |
| R6 fsynced checksummed restore recipe before publication | existing broker journal, unchanged (U3.2) |
| R7 single-writer broker restores on every failure path | existing broker, extended by U3.2; U3.11 |
| R8 short lease, neutral report on controlled exit, broker-only journal deletion | U3.4, U3.10 |
| R9 publication gate: matching interface appears, opens least-privileged, HID operations succeed | U3.7, U3.8 |
| R10 generic-host capture of descriptors and HID control requests before the Switch; propagate every error | U3.5, U3.9 |
| R13 composite HID/network shape (partial, via KTD-H) | U3.9, U3.12 |
| AE2 type `MAC2JB`, correct press/release reports, original description restored | U3.9, U3.10 |
| AE3 kill the canary mid-flight; the broker restores and keeps evidence | U3.11 |

## Key Technical Decisions

- **KTD-A. Extend the existing broker; do not add a second controller writer.** The broker in `ios/watchdog/` already owns the journal, the lease, the readiness gate and automatic healing, which R7 and R8 require. A HID publication becomes new broker commands, not a new process. *Rationale:* a second writer would break the single-writer invariant U2 passed on. (Parent KTD4, KTD1.)
- **KTD-B. Learn the HID function's identity; do not compile in a name.** The appended function name, its interface, and the selector numbers that worked go into the learned device profile (`ios/watchdog/USBDeviceProfile.swift`), like the owner map. *Rationale:* the product goal is all jailbroken/TrollStore USB-C devices, and the parent plan's scope boundary forbids baking in reference-device constants. The Mac backend generates a random name per run; a stable learned name is better for the healer, which must recognize the function across re-publications.
- **KTD-C. Treat the new function as owner-less and expect the healing gap.** U2's healer restarts a *user-space owner* when a function fails to register. The HID function's owner is our own canary, so the profile must record it as self-owned, and the healer must be able to restart it like any other owner. *Rationale:* without this the first HID publication hits the same race U2 characterized with no remedy, and the broker falls back to bounded re-publication only.
- **KTD-D. Probe selectors one at a time against a recorded matrix, from the Mac backend's numbering as hypotheses.** `impl.c` uses: open `0`, close `1`, set-description `2`, class `3`, subclass `4`, protocol `5`, standard descriptor `6`, nonstandard descriptor `7`, class-command callbacks `8`, complete-callback `9`, create-pipe `10`, commit `11`, read `13`, write `14`, stall `15`, abort `16`, max-packet `17`, create-buffer `18`, release-buffer `19`, pipe property `27`. *Rationale:* parent KTD7 forbids copying a private ABI blindly; these are observations to test on this build, and the ABI may differ.
- **KTD-H. Append HID to the host-selected configuration, making a composite device.** (session-settled: user-directed — chosen over a dedicated HID-only configuration and over publishing both.) The HID interface is appended to configuration 5, the one the host selects today (`PTP + Apple Mobile Device + NCM`), so the device presents keyboard, usbmux and networking together. *Rationale:* usbmux, pairing and SSH-over-USB stay available during a HID trial, which keeps the existing strict external check and recovery tooling usable; it is also the only shape that can satisfy R13's composite HID/network fallback. *Consequence:* append the HID interface **last** so existing interface numbers do not shift, and expect the raw descriptor for that configuration to differ while HID is published. *Risk accepted:* the Switch may refuse a composite device; if it does, a HID-only configuration becomes the recorded fallback (parent plan U4), not a silent change here.
- **KTD-I. Keep the device's own vendor and product IDs.** (session-settled: user-directed — chosen over a distinct test VID/PID.) Only the interface becomes HID; device-level scalars stay exactly as the device reports them. *Rationale:* hosts bind keyboards by interface class, not by VID, and the strict external check requires device scalars to equal the stock values, so leaving them untouched keeps that check meaningful. This departs from the Mac sender's `PID 0x1234` with no VID, which was a desktop convenience.
- **KTD-J. Capture the enumeration proof on this Mac.** (session-settled: user-directed — chosen over a Linux capture host, with Linux kept as a fallback.) *Rationale:* reuses the lifecycle monitor, raw-descriptor reader and pairing checks that U1 and U2 already proved. *Consequence:* R10's "HID control requests where observable" is scoped to what macOS exposes; if that evidence proves too thin, or the Switch later disagrees with the Mac, a Linux `usbmon` capture is the recorded escalation.
- **KTD-K. Finish every offline unit before the first HID publication.** (session-settled: user-directed — chosen over U2's trial-then-fix pacing.) All Mac-side code, fixtures and capture tooling (U3.1–U3.5) complete before any device trial, so the first description change is attempted once with recovery, capture and verification already in place. *Rationale:* U2 needed roughly seven owner-assisted restarts; each one costs a re-jailbreak. *Consequence:* the units below are split into an offline phase and a device phase, and a longer stretch passes with no device evidence.
- **KTD-E. Reuse the corrected HID fixtures as golden tests, not by linking the Mac backend.** Take the 9-byte HID descriptor, the 65-byte report descriptor, the boot-keyboard tuple (3/1/1), the 8-byte report shape and the report-length fix from `sender.c`, and the report validation from `keyboard.c`. Do not compile `vendor/libusbd`. *Rationale:* parent KTD8; the Mac backend destructively removes stock configurations, suppresses errors, declares `0xA0/255` power and omits a VID, none of which may reach the iPad path.
- **KTD-F. Prove enumeration from the host, never from a successful endpoint write.** A write returning success is not proof. *Rationale:* R10 states this, and U2 taught the same lesson for publication (API success was never recovery).
- **KTD-G. No SmileBASIC text encoding in U3.** U3 types a fixed canary string. Indentation handling and the bootstrap belong to later units. *Rationale:* parent scope boundary.

## Implementation Units

Two phases, per KTD-K: everything offline first, then the device trials in order. Mark a unit done only when its checklist is complete.

**Phase 1 — offline (no device)**

- [x] **U3.1** Profile support for an added function
- [x] **U3.2** Additive publication path in the broker
- [x] **U3.3** Function matcher and interface operation shim
- [x] **U3.4** Lease-bound canary process
- [x] **U3.5** Host capture tooling and the HID trial runner

**Phase 2 — device (each ends restorable)**

- [x] **U3.6** Changed-description recovery trial, no HID configuration
- [x] **U3.7** Function materializes and its user client opens *(R9 gate; stop here on failure)*
- [x] **U3.8** Walk the interface operation matrix
- [ ] **U3.9** Generic-host enumeration and report capture *(the HID proof)*
- [ ] **U3.10** Restoration after HID, verified externally
- [ ] **U3.11** Fault trials on the HID path
- [ ] **U3.12** Direct Switch run *(owner-assisted)*

**Phase 1 is complete.** Code review over the whole offline change set returned a
not-ready verdict and thirteen findings, every one of which is fixed on the
branch. Two were blocking defects the offline suite could not see, and each
would have presented on hardware as a platform limitation rather than a bug:
restore refused the description the additive path had just published, and the
trial could never publish because the broker's lease must be held across the
publication. The two test weaknesses that hid them are fixed as well — a fixture
that discarded the bytes it was asked to publish, and a trial fake that accepted
a publication with no lease and so pinned the order the device refuses.

**Before the first device trial**

- [x] Grant Input Monitoring to the report reader in the ignored build tree and to the application that hosts the session that launches the trial — on this Mac that is the editor, not a terminal, because the request is attributed to the responsible process. Granted and confirmed: the platform reports listen-event access granted for the session's process tree, and the reader binds nothing when given the device's real identifiers because it also matches the boot-keyboard usage and no such interface exists yet. What remains unverified is only that seizing the appended keyboard succeeds once it appears, which needs the device; a refusal there names the pane, the binary and the re-grant rule. The grant must be given again after any change to the reader's source, since the file name carries its digest.
- [x] Add the appending-capable broker to the deployment allowlists in `host/replace-u2-broker-wifi.py` and `device/u2-replace-broker.py`.
- [x] Preflight: pinned Wi-Fi SSH, USB recognised, broker idle with a learned profile, and the strict external check passing with no journal.
- [x] Take a fresh restore kit.
- [x] Deploy the appending-capable broker, not the conservative one, which no longer carries the command at all.
- [x] Stage the canary binary on the device and record its digest for the runner.
- [x] Capture a fresh strict-check baseline if the device has rebooted since the last one. *(Not needed: the check reports `boot=same`, so the existing baseline is valid.)*
- [x] Record the deployment in the findings Current state block and the device inventory.

Each unit ends with the device in a state the broker can restore, and the first failing operation is recorded rather than worked around. A device trial runs only when the Current state block in `docs/ipad/target-device-findings.md` allows it, and only after a fresh restore kit.

### U3.1 Learn and extend the device profile for a HID function

- **Goal:** the profile can describe an added function and its self-owner before any publication.
- **Files:** `ios/watchdog/USBDeviceProfile.swift`, `ios/tests/USBDeviceProfileTests.swift`, `docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-device-profile.py`
- **Approach:** add an optional `addedFunctions` section recording the function name, the configuration it was appended to, its interface's observed selector results, and that its owner is this port's canary. Keep `schemaVersion` migration explicit: a learned v2 profile stays valid and gains the section empty.
- **Test scenarios (Mac-only):** a v2 profile loads and validates unchanged; an added function round-trips through the store; a profile naming an added function absent from the live function list fails validation; the healer policy derived from a profile with a self-owned function restarts that owner and not another.
- **Tasks:**
  - [x] Add `addedFunctions` to `USBDeviceProfile` (name, target configuration, selector record, self-owned flag) with explicit v2→v3 migration.
  - [x] Teach `healPolicy()` to treat a self-owned added function as restartable by the canary.
  - [x] Extend `USBDeviceProfileTests.swift` with the four scenarios listed above.
  - [x] Run `tests/test-u2-device-profile.py` plus the full `test-u2-*` suite; no regression.

### U3.2 Add an additive-publication path to the broker

- **Goal:** the broker can publish `original + one HID interface in configuration 5`, journal the original unchanged, and restore it on every existing failure path.
- **Files:** `ios/usb/USBRestoreControllerShim.c/.h`, `ios/watchdog/TargetUSBRestoreController.swift`, `ios/watchdog/USBRestoreCoordinator.swift`, `ios/watchdog/NativeUSBWatchdogService.swift`, `ios/tests/NativeUSBWatchdogServiceFixture.swift`
- **Approach:** a new shim entry clones the live description and appends one function **last** in the host-selected configuration (KTD-H), leaving device-level scalars untouched (KTD-I). The journal still holds the **unmodified** original. Add a `publish-hid <name>` command beside `publish-noop`, under the same lease and readiness gate.
- **Corrected during implementation:** restore semantics could **not** stay untouched, and the assumption that they could was wrong. Every restore path re-clones the live description and requires it to equal the journaled original, so the appended interface makes restore refuse; the external-failure path is refused too, because it requires the controller not to be configured. Restore is therefore told what to take off, and the appended name is journaled so a restart can still do it. On the device the original behaviour presents as this plan's own stop condition, a HID publication that cannot be restored automatically.
- **Test scenarios (Mac-only fixture):** the published description equals the original plus exactly one interface, appended last, in the expected configuration; existing interface order and all device scalars are unchanged; the journal is byte-equal to the original; worker death, watchdog restart and lease expiry each restore the original; `publish-hid` is refused without a lease, with an existing journal, or when the name is already present; a malformed name is rejected before any controller call.
- **Tasks:**
  - [x] Add the shim entry that clones the live description and appends one named function last in the host-selected configuration.
  - [x] Leave vendor, product and every other device scalar untouched.
  - [x] Reject a malformed or already-present name before any controller call.
  - [x] Add the `publish-hid <name>` broker command under the existing lease and readiness gate; heal and `confirm` are untouched, and restore is extended rather than left alone (see the correction above).
  - [x] Extend the Mac fixture with the scenarios above, including unchanged interface order and scalars.
  - [x] Run the full `test-u2-*` suite.
  - [x] Strip the appended function on every restore path, refusing unless it is the last interface of its configuration, with one plain retry when it is not on the bus so a publication that wrote nothing still recovers.
  - [x] Dry-run the append before the journal moves to published, so a refusal that writes nothing costs no restore swap.
  - [x] Compile the appending command only into the build that carries it, so the rollback target genuinely lacks it.

### U3.3 Build the function matcher and interface operation shim

- **Goal:** all code needed to find the new interface and configure it exists and compiles, before any publication.
- **Files:** `ios/usb/USBDeviceFunctionShim.c/.h` (new), `docs/plans/ipad-port/scripts/ipad-hardware/host/read-u2-added-function-wifi.py` (new) with its `device/` payload
- **Approach:** a read-only matcher finds `IOUSBDeviceInterface` by `USBDeviceFunction`, requiring the same controller subtree, then opens its user client with the interface-class entitlement U1 proved sufficient. Separately, one callable entry per HID operation in KTD-D order, each recording its raw `IOReturn` and never retrying.
- **Test scenarios (Mac-only):** the matcher rejects a prefix or case-variant property match; absent-service and open-denied are distinct outcomes, neither reported as success; each operation entry is callable exactly once per run and aborts the sequence on refusal; compile for iOS arm64.
- **Tasks:**
  - [x] Write the matcher: same-controller subtree required, exact `USBDeviceFunction` match.
  - [x] Write one entry per operation: class/subclass/protocol, standard descriptor append (`0x21`), nonstandard descriptor append (`0x22`), interrupt-IN pipe, buffer, class-command callbacks, commit.
  - [x] Record the raw `IOReturn` for every call; no retries, no suppressed errors.
  - [x] Add the pinned host reader and device payload that report absent-vs-denied distinctly.
  - [x] Compile for iOS arm64 and run the Mac-only fixtures.

### U3.4 Add the lease-bound canary process

- **Goal:** a separate, least-privileged process that holds a lease, configures the function and writes reports, per R8 and KTD1.
- **Files:** `ios/canary/` (new: main, HID report model, lease client), `ios/entitlements/canary-interface.plist` (new: `platform-application` plus the interface-class exception only; **no** set-description), `ios/tests/HIDReportTests.swift` (new)
- **Approach:** the canary never publishes a description and never writes the journal; it asks the broker for a lease, configures the already-published function, writes reports, and on every exit path sends a neutral report and returns the lease. Reuse `keyboard.c`'s validation rules: no modifier-only garbage, no duplicate keycodes, no gaps, keycodes in range.
- **Test scenarios (Mac-only):** golden-test the 9-byte HID descriptor including the corrected report-length bytes, the 65-byte report descriptor, the 3/1/1 tuple and the 8-byte report shape; the device-level VID/PID are left untouched (KTD-I); reject an invalid report before any write; a controlled exit emits exactly one neutral report; lease expiry stops writes; three bounded neutral attempts on disconnect.
- **Tasks:**
  - [x] Create `ios/canary/` with the lease client, HID report model and exit handling; no publication, no journal access.
  - [x] Add `canary-interface.plist`: `platform-application` plus the interface-class exception only.
  - [x] Port `keyboard.c`'s report validation.
  - [x] Emit exactly one neutral report on every controlled exit; stop writes on lease expiry; three bounded neutral attempts on disconnect.
  - [x] Add `HIDReportTests.swift` golden tests for the descriptors, the tuple, the report shape and the untouched device IDs.

### U3.5 Build the host capture tooling and the HID trial runner

- **Goal:** the Mac can prove enumeration and run a HID trial end to end, before the first publication.
- **Files:** `docs/plans/ipad-port/scripts/ipad-hardware/host/capture-u2-hid-enumeration.py` (new), `host/run-u2-hid-trial-wifi.py` (new, modelled on `run-u2-noop-trial-auto-heal-wifi.py`); reuse `host/u2-usb-lifecycle-monitor.swift` and `host/u2-readonly-raw-config-descriptors.c`
- **Approach:** the capture tool reads the new interface's descriptors from the host side and compares them against the golden fixtures; the trial runner wraps a HID publication the way the no-op runner wraps a trial — restore kit, network syslog, lifecycle monitor, strict check, and `confirm` only on proof. Both refuse to run when the preconditions fail.
- **Test scenarios (Mac-only):** the comparator fails a missing or mismatched report descriptor, an extra or missing report, and a non-enumerating host (reported as not-enumerated, never as a pass); captures contain no serial or UDID; the runner refuses without a restore kit, without the broker idle, or when the device is already publishing.
- **Tasks:**
  - [x] Write the host capture tool: assert interface class 3 / subclass 1 / protocol 1, the expected report descriptor, and one 8-byte interrupt-IN endpoint.
  - [x] Record the host's HID control requests as far as macOS exposes them (KTD-J).
  - [x] Write the HID trial runner with the same safety shape as the no-op runner.
  - [x] Keep serials and UDIDs out of every capture.
  - [x] Run both against synthetic inputs; no device.
  - [x] Hold the broker lease across the publication in one process, since the lease registration needs a held connection and the runner's commands each closed theirs.
  - [x] Record the report sequence this Mac receives, seizing the device and arming the reader before the publication so a trial cannot type into the operator's machine (owner-directed: capture on the Mac).
  - [x] Make every empty-capture cause its own labelled non-pass, and let none of them confirm the journal.

### U3.6 Changed-description recovery trial, no HID configuration

- **Goal:** separate "does a changed description still recover" from HID itself. This is the first device trial.
- **Approach:** publish the appended function name with **no** interface configuration at all, then let the broker restore. Compare the healing behaviour against U2's no-op baseline, since the extra function changes the registration race.
- **Test scenarios:** the broker restores automatically; the strict external check passes; the restored function list contains no added function.
- **Tasks:**
  - [x] Build and deploy a broker carrying U3.2's path; take a fresh restore kit first.
  - [x] Capture the healthy reference set, then publish the name with no configuration.
  - [x] Let the broker heal; record re-publication and owner-restart counts.
  - [x] Run the strict external check and confirm the journal only with its output as proof.
  - [x] Compare healing counts with U2's no-op trials and record the difference.

### U3.7 Prove the function materializes and its user client opens

- **Goal:** settle R9's first half on this device.
- **Approach:** after a U3.6-style publication, run the matcher from U3.3 and open the interface's user client with the interface-class entitlement only. Record the raw `IOReturn` at each step.
- **Stop condition:** if no matching service appears, or the open is denied, record the boundary and stop. That is an R9 failure, and the parent plan's U4 exclusive-HID fallback becomes the question.
- **Tasks:**
  - [x] **Device:** publish, then match the interface by `USBDeviceFunction` in the same controller subtree.
  - [x] Open its user client with the interface-class entitlement; record the raw result.
  - [x] Store the outcome in the learned profile and restore the description.
  - [x] **Stop and report** if the service never appears or the open is denied.

### U3.8 Walk the interface operation matrix

- **Goal:** know exactly which HID operations this build authorizes, with raw returns.
- **Files:** `docs/ipad/hid-operation-matrix.md` (new, redacted)
- **Approach:** exercise the KTD-D sequence one operation at a time, stopping at the first refusal. Treat the Mac backend's selector numbers as hypotheses: if one returns an unsupported-selector code, record it and probe the neighbouring numbers before concluding the operation is unavailable.
- **Test scenarios:** each operation attempted at most once per run; a refusal aborts the remainder; the recorded matrix contains no device identifiers; the broker still restores afterwards.
- **Tasks:**
  - [x] **Device:** walk class, subclass, protocol, both descriptor appends, pipe, buffer, callbacks and commit, recording every raw `IOReturn`.
  - [x] Probe neighbouring selector numbers only when one reports an unsupported selector.
  - [x] Write `docs/ipad/hid-operation-matrix.md` (redacted) and store the selector record in the profile.
  - [x] Verify the broker still restores afterwards.

### U3.9 Generic-host enumeration and report capture

- **Goal:** settle R4, R10 and the report half of AE2 on a host we can observe. **This passing is the proof that direct USB HID works on this device.**
- **Approach:** with the device on the Mac, capture the new interface's descriptors host-side, record the HID control requests macOS exposes, then have the canary type `MAC2JB` and compare every report against the expected press/release sequence.
- **Test scenarios:** as built in U3.5; a non-enumerating host is reported as not-enumerated.
- **Tasks:**
  - [ ] **Device:** publish the HID configuration and configure the interface through the canary.
  - [ ] Capture descriptors host-side and compare against the golden fixtures.
  - [ ] Type `MAC2JB` and compare every report.
  - [ ] Record the gate decision in `docs/ipad/hardware-matrix.md`.

### U3.10 Restoration after HID, verified externally

- **Goal:** AE2's restoration half and R8's journal rule, on the HID path.
- **Tasks:**
  - [ ] **Device:** have the broker restore the original description after U3.9.
  - [ ] Run `host/check-u2-trial-current.py --expect-journal=awaitingVerification`; require resolved strings and NCM packet flow to pass.
  - [ ] Confirm the journal only with that check's output as proof, then re-check with no journal.
  - [ ] Verify the restored description has no HID interface and unchanged device scalars.
  - [ ] Verify a failed check leaves the journal and reports recovery-required.

### U3.11 Fault trials on the HID path

- **Goal:** AE3 and R7 with a changed description, which is harder than U2's no-op.
- **Tasks:**
  - [ ] **Device, separately:** canary killed while configuring, while enumerated, and while writing; broker killed; lease expired; cable disconnected mid-press.
  - [ ] Require automatic restoration and a passing strict check after each.
  - [ ] Verify a neutral report is attempted before restoration on controlled exits, and that no fault path confirms a journal.
  - [ ] Record re-publication and owner-restart counts per fault; compare with U3.6 and U2's baseline.

### U3.12 Direct Switch run

- **Goal:** the mac2jb path itself. The Switch gives no host-side capture, so the evidence is device-side state plus the owner's observation.
- **Tasks:**
  - [ ] Refuse to run unless U3.9 has passed on the Mac.
  - [ ] Refuse without a recorded peer and cable orientation.
  - [ ] **Owner-assisted:** move the cable to the Switch 2 and confirm the device still enters peripheral role with the existing Type-C and controller readers.
  - [ ] Open the keyboard screen, type a harmless canary string, and record the owner's observation.
  - [ ] If the Switch refuses the composite device, record it as the KTD-H risk materialising and stop; the HID-only configuration is the parent plan's U4 question.
  - [ ] Verify restoration and the strict check afterwards.

## Verification Contract

- **Unit level:** the Mac-only fixtures in each unit, runnable with no device.
- **Gate level (R4–R10, AE2, AE3):** thirty generic-host cycles and thirty direct Switch keyboard-screen cycles pass with exact descriptor and report capture and externally verified restoration, as the parent plan's U3 verification states. A neutral endpoint write without host-side enumeration evidence does not count.
- **Not evidence:** a successful endpoint write, a broker "published" reply, or `awaitingVerification`.

## Risks and Mitigations

- **The new name never materializes.** Most likely failure. Mitigation: U3.3 isolates it before any HID configuration, and U4 (exclusive HID) is the recorded fallback.
- **Selector ABI differs from the Mac backend.** Mitigation: KTD-D probes one at a time and records raw returns; neighbouring selector numbers are probed before declaring an operation unavailable.
- **The Switch refuses a composite device.** KTD-H's accepted risk. Mitigation: U3.9 proves the descriptor on the Mac first, so a Switch-only refusal is isolated from a descriptor fault; the HID-only configuration is the recorded fallback (parent U4), not a silent change.
- **macOS exposes fewer HID control requests than Linux.** KTD-J's accepted limit. Mitigation: R10 evidence is scoped to what macOS shows, and a Linux `usbmon` capture is the recorded escalation if that proves too thin.
- **Appending to the host-selected configuration could make the host rebind and drop usbmux or NCM while HID is live.** Mitigation: pinned Wi-Fi SSH is the control channel throughout, so losing USB-side usbmux never blocks recovery; U3.9 measures whether they survive.
- **The added function worsens the registration race, and it has no kernel driver.** Mitigation: KTD-C records it as self-owned so the healer can restart the canary; U3.2's trial publishes the name with no configuration to measure the race alone.
- **A changed description could lose usbmux or networking for longer than a no-op did.** Mitigation: every HID trial takes a fresh restore kit first and runs under the same automatic recovery U2 proved; the owner-assisted reboot path remains the backstop.
- **The Switch rejects a descriptor the Mac accepts.** Mitigation: U3.9 is a separate gate after U3.6; desktop capture is necessary but not sufficient.
- **Entitlement creep.** Mitigation: the canary gets the interface-class exception only; publication authority stays in the broker.

## Open Questions

Planning questions the interview settled are now KTD-H through KTD-K. These remain, each resolved by a device trial rather than by discussion:

- Does the controller accept an appended interface in an existing configuration, or does it validate configurations against the stock source? Settled by U3.6.
- Does the added interface need its own `AllowMultipleCreates` handling, or is the existing flag enough? Settled by U3.6.
- Can the healer restart our own canary as a function owner, or does a self-owned function need a different remedy? Settled by U3.11's fault counts.
- Does appending to the host-selected configuration keep usbmux and NCM bound while HID is live, or does the host rebind and drop them? Settled by U3.9; it decides whether SSH-over-USB survives a trial.

## Sources and Research

- Parent plan and its Product Contract: [`01-hardware-feasibility.md`](01-hardware-feasibility.md). Feasibility note: [`research/usb-hid-ipad-feasibility.md`](research/usb-hid-ipad-feasibility.md), whose nine-step proof protocol this plan's unit order follows.
- U1 authorization evidence (the `interface-client` profile opened all 32 existing function user clients; controller opens were unsupported in every profile): `docs/ipad/hardware-matrix.md`, with the per-profile table in git history before `4a4c876`.
- U2 mechanism and broker behaviour: [`../../ipad/usb-auto-recovery.md`](../../ipad/usb-auto-recovery.md), [`../../ipad/usb-recovery.md`](../../ipad/usb-recovery.md).
- Repository fixtures to reuse: `sender.c` (HID descriptor, report descriptor, corrected report length, boot-keyboard tuple, enumeration-wait shape), `keyboard.c` (bounded 8-byte report validation).
- Mac backend selector sequence and generic-interface matching: `vendor/libusbd/src/plat/macos/impl.c` (`libusbd_impl_config_finalize`, `libusbd_impl_iface_finalize`, and the `IOUSBDeviceInterface_*` wrappers).
- Historical iOS publication plus named-interface open: <https://github.com/nabla-c0d3/iphone-dataprotection/blob/master/ramdisk_tools/restored_external.c>.
