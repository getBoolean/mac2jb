---
title: iPad Kernel HID Gadget (U3 feasibility + U4 function) - Plan
type: feat
date: 2026-11-02
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
parent_plan: docs/plans/ipad-port/01-hardware-feasibility.md
plan_order: 1d
execution_after: docs/plans/ipad-port/01-hardware-feasibility.md
---

# iPad Kernel HID Gadget (U3 feasibility + U4 function) - Plan

Expands the **new** U3 (kernel-code feasibility and safety gate) and U4 (kernel HID gadget function) of [the hardware feasibility plan](01-hardware-feasibility.md) into ordered subtasks. The parent plan owns the Product Contract and requirements; this plan owns HOW. It inherits R4, R5–R8, R9, R10, R16, R17, AE2, AE3, AE5 and KTD1, KTD2, KTD4, KTD7, KTD8, KTD10, KTD11 unchanged, and adds no product scope.

**Why this plan exists:** the userspace private-API HID path is closed — it never enumerates because `IOUSBDeviceController::createUSBDevice` matches each interface to an in-kernel driver before the controller goes on bus. The only path to a custom enumerable HID function is a kernel-side match (the iOS analogue of the macOS `usbgadget.kext`). U3 decides whether the jailbreak can do that **reversibly and safely at all**; U4 builds it only if U3 passes. See the verdict in [`../../ipad/hardware-matrix.md`](../../ipad/hardware-matrix.md) and [`../../ipad/target-device-findings.md`](../../ipad/target-device-findings.md).

**Standing rules for every subtask (from the parent + the device skill):**
- The U2 broker + journal + stored-description restore + Wi-Fi SSH lifeline + reboot path are the recovery spine. No kernel write or publication happens outside the broker's lease.
- Kernel offsets/primitives are pinned to iPadOS 17.0 `21A329` on `iPad14,5`/`T8112` and live in a per-build kernel profile — never hard-coded, re-derived for any other build.
- Each device-affecting subtask states its risk, exact target, how its result is inspected, and a plausible reversal, and is owner-authorized before it runs. Read-only kernel reads precede every write. Record results in the findings Current state and the matrix; durable lessons in the docs.
- Stop conditions: a kernel change that cannot be cleanly removed, a boot-loop risk, or an unrecoverable USB loss fails the gate and routes to the parent plan's alternatives (another device/build; accept infeasibility).

---

## U3 — Kernel-code feasibility and safety gate

**Gate goal:** decide, on the exact build and **before any HID publication**, whether the jailbreak's kernel primitives can make `createUSBDevice` match a HID function reversibly and without persistent instability — or produce an evidenced infeasibility verdict. No HID configuration is published anywhere in U3.

- [ ] **U3.1 — Kernel primitive surface (read-only).** Catalogue what Dopamine exposes to a root context on this build: kernel read/write reach, the patchfinder/offset source, KPP/KTRR/PPL constraints on write targets, and whether a given kernel address is writable at all. Produce `ios/kernel/` read-only probe output recording the primitive surface. *Verify:* two runs agree; nothing is written; the probe classifies "readable / writable / protected" per region it will later need.
- [ ] **U3.2 — Locate the gadget-match path (read-only).** Using the primitives from U3.1, find the structures `IOUSBDeviceController::createUSBDevice` uses to match each interface of the selected configuration to an in-kernel IOKit driver, plus the entitlement check the macOS `usbgadget.kext` bypassed. Record exact offsets/symbols for `21A329` only, into the per-build kernel profile. Cross-check against the Synacktiv RE and the stock function matches (PTP, audio) observed in the function census. *Verify:* the matching structure and entitlement check are identified with evidence; two reads agree; nothing written; offsets recorded as build-specific.
- [ ] **U3.3 — Design the smallest candidate change (offline).** Decide between (a) **register** an in-kernel function/driver match for one named HID interface, versus (b) **patch** the match/entitlement path so our interface binds. Specify the exact structure/bytes to change, why it is the minimal change, how it is applied and removed purely via KRW from userspace, and the expected before/after kernel state. Prefer the option that is additive and self-reverts on removal. No device action. *Verify:* a written candidate with an explicit apply/remove procedure and a predicted reversible diff; a second reviewer (or `ce-pov`) agrees it is minimal and reversible in principle.
- [ ] **U3.4 — Reversibility proof, device idle (first kernel write; no publication).** Behind the broker lease, with no HID configuration published, apply the candidate change, read back the kernel state, then remove it and confirm the kernel region is byte-identical to before; confirm USB/usbmux/stock functions are unaffected throughout; confirm a reboot restores stock regardless. *Risk/target/inspect/reversal stated and owner-authorized before running.* *Verify:* apply→read→remove→read shows a clean round trip; device stays on bus and healthy; reboot restores.
- [ ] **U3.5 — Worst-case recovery drill.** With the change applied (still no publication), force the bad path: kill the applier / expire the lease / drop the connection, and confirm the U2 broker + the reboot path still restore stock and leave no kernel residue. *Verify:* stock restored and the kernel change gone after the broker path and, separately, after a reboot.
- [ ] **U3.6 — Verdict + per-build kernel profile.** Record either a **PASS** (a specific reversible primitive that registers/matches a gadget function, with its apply/remove procedure and offsets in the per-build profile) or a **FAIL** (evidenced: the jailbreak cannot do this safely/reversibly). Update the findings Current state and the hardware matrix. On FAIL, stop the HID path and route to the parent plan's alternatives. *Verify:* the matrix carries a clear U3 decision; on PASS, U4 has a documented, reversible primitive to build on.

**U3 pass condition (R16):** U3.4 demonstrated a clean apply/remove of a gadget-match change with the device idle, U3.5 proved recovery from the worst case, and the primitive + offsets are in the per-build profile. Otherwise U3 fails and the HID path stops here.

---

## U4 — Kernel HID gadget function (only if U3 passed)

**Goal:** make a HID boot-keyboard interface, appended to the selected configuration, be matched by the kernel so `createUSBDevice` brings the configuration on bus — behind the recovery spine, cleanly removable.

- [ ] **U4.1 — Broker lifecycle integration.** Wire the reversible primitive from U3 into the broker's lease lifecycle: apply the kernel match as part of `publish`, remove it as part of every restore/recover/heal path and on worker death/lease expiry. The match is never left applied once the publication is gone. Add a compile flag so a broker without the kernel path builds unchanged. *Verify (offline + fixtures):* unit/fixture tests show apply-on-publish and remove-on-every-restore-path; a broker built without the flag is byte-identical to v21's behaviour.
- [ ] **U4.2 — Bring the HID configuration on bus.** Behind the lease, enable the kernel match, publish `[AppleUSBMux, <HID>]` via the existing interface-list path, and cycle the bus. Observe on-bus via the device syslog (`handleUSBConnectionDone`, and the absence of `goOnBus: not on bus`) and the Wi-Fi lifeline, since usbmux may be absent during the hold. *Risk/target/inspect/reversal stated and owner-authorized.* *Verify:* the controller goes on bus with the match present — the discriminating opposite of the five closed userspace trials.
- [ ] **U4.3 — Discriminating control.** In the same session, confirm the controller goes on bus **with** the kernel match enabled and does **not** without it (match disabled, same publish). This isolates the kernel match as the cause, not some other change. *Verify:* on-bus iff match enabled, recorded with syslog evidence.
- [ ] **U4.4 — Fault trials on the kernel path.** Kill the injector / expire the lease / pull the cable mid-hold; confirm the broker removes the kernel match and the stored-description restore returns stock (with the owner-restart heal available for the audio re-registration race), and that the match is gone after restore and after a reboot. Repeat for normal exit, SIGKILL, and watchdog restart. *Verify:* every fault path restores stock and leaves no kernel residue; recovery needs no manual step beyond the proven recover tool / reboot.
- [ ] **U4.5 — Record result.** Update the findings Current state, the hardware matrix, and the device-cleanup ledger (the kernel change is a persistent-capable device change — record its apply/remove and that it is removed). Durable lessons to the docs. *Verify:* the record states clearly whether a kernel-matched HID function comes on bus on this build, with evidence paths.

**U4 pass condition (R4, R9):** the controller brings the HID configuration on bus with the kernel match present and not without it, restoration is externally verified on every fault path, and the kernel change is cleanly removed. Enumeration + report injection to a host is proven next in the parent plan's **U5** (R10, R17).

---

## Notes carried from the closed userspace work (reusable)

- HID fixtures: the corrected 9-byte HID descriptor, 65-byte report descriptor, boot-keyboard tuple, 8-byte report validation, no-replay rule, neutral-report fixtures (`ios/canary/HIDKeyboardReport.*`).
- Host tooling: enumeration capture (`host/capture-u2-hid-enumeration.py`), seized report reader, lifecycle monitor, strict external check, the trial runner shape (`host/run-u2-hid-trial-wifi.py`).
- Publish/restore: the interface-list publish (`MAC2JBUSBCloneSetInterfacesOrPublish`) and the stored-description restore (`MAC2JBUSBSetStoredDescriptionOrPublish`), both proven on device.
- Recovery: `host/recover-u2-over-wifi.py`, the owner-restart heal for the audio race, and the reboot resume (`host/resume-u3-after-reboot.py`).
