---
title: iPad USB Restoration Journal and Watchdog (U2) - Plan
type: feat
date: 2026-10-31
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
parent_plan: docs/plans/ipad-port/01-hardware-feasibility.md
plan_order: 1b
execution_after: docs/plans/ipad-port/01-hardware-feasibility.md
---

# iPad USB Restoration Journal and Watchdog (U2) - Plan

**Status: PASS, 2026-10-31.** U2 of [the hardware feasibility plan](01-hardware-feasibility.md). The parent plan owns the Product Contract; this plan owned HOW and is kept as the completed record. It inherits R5–R8 and KTD2, KTD4, KTD9 unchanged.

Current device state is the Current state block in [`../../ipad/target-device-findings.md`](../../ipad/target-device-findings.md); gate evidence is in [`../../ipad/hardware-matrix.md`](../../ipad/hardware-matrix.md). This plan is a planning record, not a runbook — to operate the result, use [`../../ipad/usb-recovery.md`](../../ipad/usb-recovery.md).

## Goal

Make restoration provable before any custom descriptor is published, so a USB change can never leave the device without a USB connection and no way back.

## Unit definition (as planned)

- **Requirements:** R5–R8
- **Dependencies:** U1
- **Files:** `ios/watchdog/`, `ios/usb/USBRestoreJournal.*`, `ios/tests/USBRestoreJournalTests.*`, `packaging/ios/probe-rootless/`
- **Approach:** Build the minimal rootless probe package. Capture live and default descriptions through target-validated APIs when available; canonicalize device scalars, configurations, ordered function names, source hashes, controller identity, and external descriptor observations. If readback is unavailable, reconstruct a build-pinned recipe from the configuration plist, device tree, and registry and mark its provenance. Validate whether republishing requires `AllowMultipleCreates` and a bounded off/on-bus cycle. Implement atomic journal creation plus file/parent fsync, restrictive ownership, lifecycle states, leases, hash/boot/source validation, and idempotent external restore verification. The watchdog is the only journal/controller writer.
- **Execution note:** Test journal corruption and watchdog restarts against fixtures before granting it a controller entitlement.
- **Test scenarios:**
  - Reject a truncated, wrong-owner, wrong-controller, or wrong-boot journal without applying its payload.
  - Restore the same valid journal twice and report the second pass as already restored.
  - Preserve a failed journal and surface recovery-required instead of deleting evidence.
  - Kill and restart the watchdog, canary, and future main-service stand-in independently; prevent concurrent writers and restore on lease expiry.
  - Compare live-readback, default-plus-controller, and externally captured descriptors; reject a reconstructed fallback whose functions or scalar descriptors differ.
- **Verification:** The watchdog passes fixture fault injection and completes a no-op republish/restore against the captured live description, with usbmux/trust/charging and any active network function externally recovered.

## Completion (2026-10-31)

- [x] **Restore baseline.** The live description is journaled per trial; the strict external baseline (raw configurations, resolved strings, host interfaces, scalars, NCM binding and packet reply, pairing, power) is captured twice-stable per boot (`host/capture-u2-trial-baseline.py`).
- [x] **Durable journal.** Versioned canonical recipe, exclusive creation, checksum, atomic replacement with file and directory fsync, phases `prepared → published → restoring → awaitingVerification → restored`, plus `recoveryRequired`; fault fixtures pass.
- [x] **Single-writer broker and watchdog.** The launchd broker is the only controller writer and journal owner, with a 15 s lease, worker/watchdog-death and lease-expiry recovery, a readiness gate before a second publication, and confirmation only with external proof.
- [x] **Automatic recovery.** After a swap the controller waits for every USB function to re-register. The broker heals with bounded re-publication plus restarts of user-space function owners, using an on-device learned device profile ([`../../ipad/usb-auto-recovery.md`](../../ipad/usb-auto-recovery.md)).
- [x] **Device trials.** v11 5/5 (normal ×3, worker-kill, watchdog-kill) and v12 2/2 (normal, watchdog-kill) recovered without owner action and passed the strict external check. Accepted deviation: the live description keeps `AllowMultipleCreates=true`.
- [x] **U2 PASS.** Evidence in `docs/ipad/hardware-matrix.md`; procedure in `docs/ipad/usb-recovery.md`; device inventory in `docs/ipad/device-cleanup-ledger.md`.

## What the implementation settled

These are the decisions U2 made that later units inherit. The mechanism and its evidence live in [`../../ipad/usb-auto-recovery.md`](../../ipad/usb-auto-recovery.md).

- **Publish by cloning the live controller description** (`IOUSBDeviceDescriptionCreateFromController`), not by rebuilding from defaults. Rebuilding from defaults failed three designs (v1–v3). Settles the parent plan's KTD2 and KTD9 for this target.
- **The controller goes on bus only after every USB function re-registers.** A description swap races the old function instances their owners still hold, so a random one or two never register and the controller stays off bus. This was the root cause behind seven failed trial designs.
- **Recovery is bounded re-publication plus restarting the user-space owner of a function that failed to register.** Nothing else recovers a stuck controller: re-sending the description, `GoOffAndOnBus`, `ForceOffBus`, replugging, or changing host.
- **Device facts are learned on the device, never compiled in.** The broker learns product/build, the stock source digest, the live field count, USB IDs, healthy `bcdUSB`/`MPS0`, the function list and the function owners, and stores them privately. This is what lets other models and iOS builds qualify without code changes.
- **API success is never recovery.** A journal is confirmed only with the SHA-256 of a strict external check's output as proof; healing never confirms or clears it.
- **Accepted deviation:** the live registry description keeps `AllowMultipleCreates=true` as an extra field. The publication path requires it; the other fields equal the stock original. Recorded in the gate decision rather than claimed as exact byte restoration.
- **iOS behaviours worked around:** the broker needs an explicit `JetsamMemoryLimit` (the 18 MB default plus tweak injection killed it mid-recovery); Apple daemons started outside launchd are SIGKILLed; the device syslog streams over Wi-Fi even while USB is off bus, which is how the root cause was finally observed.

## Measured evidence

Recovered here on 2026-10-31 so the design rationale survives the doc condensation; raw files stay in ignored `build/ipad-hardware/`.

### Trial designs and why the current one was chosen

Each row is a separate signed broker build on its own boot. Every failed trial needed an owner-assisted restart; its journal was backed up and archived.

| Build | Starting live state | Object sent to `SetDescription` | Explicit `GoOffAndOnBus` | Worker close | External result |
|---|---|---|---|---|---|
| v1 | original 16 fields | defaults + controller, four live-only fields patched in | no | normal, after 3 s | two late arrivals; exact external comparison failed; USB later absent |
| v2 | original, new boot | same defaults path | no | normal, after 3 s | one termination, no arrival in 20 s |
| v3 | original, new boot | same defaults path | yes (1,000 ms) | normal, after 3 s | one termination, no arrival in 20 s |
| v4 | original, new boot | **controller clone** with original info values | yes (1,000 ms) | normal, after 3 s | two termination/arrival cycles; full same-boot USB/NCM, pairing, power passed |
| v5 | post-v4 17 fields | clone of that state, marker removed in memory only | yes | **worker exited immediately** | one termination, no arrival in 20 s |
| v7 | original, new boot | clone, readiness-gated recovery | yes | normal | no arrival; the gate correctly withheld the second publication |
| v4 repeat | original, new boot | identical to v4 | yes | normal | no arrival — **v4 was not reproducible** |
| v8 | original, new boot | clone + `restore-after-failure` | yes | normal | no arrival; the Wi-Fi re-publication also failed |
| v11 / v12 | original, new boot | clone + automatic function healing | yes | normal and fault modes | **7/7 recovered automatically** |

Two comparisons did the work. **v2 vs v3:** adding the bus cycle alone was insufficient. **v3 vs v4:** the only source-level difference was the constructor path, and only the clone path recovered — which is why KTD2's "prefer controller readback" is settled as clone-from-controller. The v4 repeat then showed that the clone path alone is not reliable either, which is what forced the root-cause hunt.

### Mac-side lifecycle timings (seconds after the 20-second monitor started)

| Build | Events |
|---|---|
| v1 | terminated 0.905; arrived 11.442; terminated 11.476; arrived 11.662 |
| v2 | terminated 0.818; no arrival |
| v3 | terminated 1.086; no arrival |
| v4 | terminated 0.665; arrived 4.125; terminated 4.160; arrived 4.397 |
| v5 | terminated 1.412; no arrival |
| v8 | terminated 1.011; no arrival |

Event count alone is not the verdict: v4's monitor also reported the pretrial registry object missing at the window end, because re-enumeration replaced it. The separate post-window descriptor, interface, NCM, pairing and power checks are what passed.

### Registry census, healthy versus failed

The comparison that located the cause. Captured twice in each state.

| State | IOService nodes | Class-edge groups | Direct `IOUSBDeviceInterface` children | Live `BcdUSBVersion`/`MPS0` | Controller |
|---|---|---|---|---|---|
| Healthy | 44 | 18 | 16 | 784 / 9 | configured, on bus, configuration 5 |
| Failed | 38–42 | 15–18 | 16 (all present) | 528 / 64 | disconnected, off bus, configuration 0 |

All 38 failed-state nodes had IOKit busy state 0, so nothing was stuck mid-attach. Relative to healthy, the failed tree lacked three `AppleUSBDeviceAudioController` clients, one `IOAccessoryPortUSB` and its `IOAccessoryPortUserClient`, and one of two `IOUSBDeviceInterfaceUserClient` instances — and which ones were missing **varied between failures**, which is what identified a race rather than a fixed dependency. The kernel log confirmed it directly: 14 or 15 of 16 `register function` lines per swap, with the missing names differing each time.

### Passing trials (v11, v12)

| Build / mode | Recovered after | Healing used |
|---|---|---|
| v11 normal #1 | 47 s | 1 re-publication + `audiomxd` restart |
| v11 worker-kill | 53 s | 3 re-publications |
| v11 watchdog-kill | 52 s | 3 re-publications |
| v11 normal #2 | 61 s | 2 re-publications + `audiomxd` restart |
| v11 normal #3 | 46 s | 2 re-publications |
| v12 normal | 72 s | 5 re-publications + `audiomxd` restart |
| v12 watchdog-kill | 29 s | 1 re-publication |

### Where the raw evidence is

| Evidence | Location |
|---|---|
| Per-trial directories (precheck, client output, lifecycle NDJSON, heal status, strict postcheck, confirmation, syslog) | `build/ipad-hardware/u2-trials/run-*` |
| Strict-check baseline (manifest SHA-256 `30693c83…18de`) and stock live reference | `build/ipad-hardware/u2-v9-trial-baseline/`, `u2-v4-repeat-baseline/` |
| Byte copies of every on-device U2 file, each journal, Mac SSH files and sources | `build/ipad-hardware/u2-wifi-restore-kit/<ns>/` |
| Censuses, provider and accessory readings, kickstart and owner-restart evidence | `build/ipad-hardware/u2-function-census/` |
| Current broker binary | `.mac2jb-u2-noop-trial-96296113`, SHA-256 `9629611372c6f570db18064a2cfcd077601f59a1b5a2a4644dbc3bdbefe37a3e` |
| Archived old-boot journal digests, failed-trial file hashes, the seven superseded broker binaries, and the dated trial-by-trial narrative | git history only (`docs/ipad/u2-usb-recovery-failure-analysis.md` and `device-cleanup-ledger.md` before `4a4c876`) |

## Refuted explanations

Do not re-investigate these; each was tested and ruled out during U2.

- A speed mismatch (`BcdUSBVersion/MPS0 528/64` is just the disconnected default).
- A lost `ptpd` launch event (`ptpd` attaches, then exits when no host is connected).
- Wired-accessory authorization (the fields are identical when healthy and failed).
- Type-C attach, role or power state.
- Device lock state.
- An early second restore call, and a readiness gate on its own.

## Limits of the pass

- Seven hardware trials, not the release plan's 30-cycle qualification (R6 at release scope).
- One v12 normal trial used the full re-publication bound; raising it or restarting known owners alongside re-publication is a tuning follow-up.
- Owner restarts for the kernel audio-2 functions are unvalidated (re-publication is the current remedy), as is whether an `accessoryd` restart helps the iAP port.
- Every publication so far has been a no-op. Changing the description's content is U3's work, planned in [`01-u3-hid-canary.md`](01-u3-hid-canary.md).
- Proven on the reference iPad only; other devices need their own qualification trials.

## Sources and Research

- Parent plan and Product Contract: [`01-hardware-feasibility.md`](01-hardware-feasibility.md).
- Mechanism, embedding notes and tests: [`../../ipad/usb-auto-recovery.md`](../../ipad/usb-auto-recovery.md).
- Operating runbook: [`../../ipad/usb-recovery.md`](../../ipad/usb-recovery.md). Gate decision: [`../../ipad/hardware-matrix.md`](../../ipad/hardware-matrix.md).
- Implementation: `ios/watchdog/`, `ios/usb/`. Tools and fixtures: `docs/plans/ipad-port/scripts/README.md`.
- Dated trial-by-trial history (v1–v12) is in git history, including the removed `docs/ipad/u2-usb-recovery-failure-analysis.md`.
