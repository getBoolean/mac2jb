---
title: iPad Read-Only Target Inventory (U1) - Plan
type: feat
date: 2026-10-31
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
parent_plan: docs/plans/ipad-port/01-hardware-feasibility.md
plan_order: 1a
execution_after: docs/plans/ipad-port/01-hardware-feasibility.md
---

# iPad Read-Only Target Inventory (U1) - Plan

**Status: PASS, 2026-10-30**, for R1–R3 and the U1-scoped R14 evidence decision. U1 of [the hardware feasibility plan](01-hardware-feasibility.md). The parent plan owns the Product Contract; this plan owned HOW and is kept as the completed record, including the measurement tables a later unit may need.

The U1 probe apps and their staged packages were removed from the device on 2026-10-31, and the U1 scripts were removed from the repository; both remain in git history. The raw reports stay in ignored `build/ipad-hardware/`.

## Goal

Learn what the target device's USB stack is and what it authorizes, without changing any USB state, so later units mutate from measured facts rather than from Mac-derived assumptions.

## Unit definition (as planned)

- **Requirements:** R1–R3 (plus the U1-scoped part of R14)
- **Dependencies:** none
- **Files:** `ios/probes/`, `ios/entitlements/`, `docs/ipad/hardware-matrix.md`, `ios/tests/ProbeResultTests.swift`
- **Approach:** build small signed probe variants that differ only by entitlement, run each separately, and record the raw `IOReturn` at every boundary rather than a pass/fail summary. Enumerate registry state, open and close requested user clients, read the live controller description through the private API, check CF type identities, and emit a redacted JSON report. Capture host-side USB lifecycle events while each probe runs; any re-enumeration fails the read-only-safety gate.
- **Verification:** every authorization boundary classified with its raw code; two consecutive runs per row with equal topology fingerprints; zero host-side lifecycle events; device-mode controller and acceptable power state on both cable orientations and both peers.

## Completion (2026-10-30)

- [x] **U1 PASS** for R1–R3 and the U1-scoped R14 evidence decision. Six authorization profiles each have two validated read-only rounds on Mac A/B and on owner-confirmed direct Switch 2 A/B. Six complete Mac USB lifecycle windows recorded zero target events and final presence. Both Switch orientations showed a configured, on-bus controller with external power.
- [x] Learned constraint carried forward: publication requires `com.apple.private.usbdevice.setdescription` with `platform-application` in a root launchd job; plain TrollStore app processes are SIGKILLed before `main`, and a SpringBoard launch (`uiopen --bundleid`) was the route that produced in-process reports.

## Authorization matrix (measured)

The load-bearing result for U3: **the interface-client profile opened all 32 existing function user clients; every other profile was denied.** Controller user-client opens are unsupported in every profile, which is why publication authority lives in the broker and not in a controller user client.

| Variant | Controller service found | Controller open | Live description and CF types | Matching function services | Verdict |
|---|---:|---|---|---|---|
| baseline (no entitlements) | 1 | Types `0` and `123` unsupported (`-536870201`) | Controller created and type matched; live description unavailable; description type-ID symbol missing | 16 observed; 32 opens denied (`-536870174`) | Two validated ordinary SpringBoard app rounds; physical role unattributed |
| setdescription | 1 | Types `0` and `123` unsupported (`-536870201`) | same as baseline | 16 observed; 32 opens denied (`-536870174`) | Only the set-description entitlement changed; it made no read-only open difference |
| platform-only | 1 | Types `0` and `123` unsupported | same as baseline | 16 observed; 32 opens denied | Two validated rounds on each Switch A/B orientation |
| platform + set-description | 1 | Types `0` and `123` unsupported | same as baseline | 16 observed; 32 opens denied | Two validated rounds on each Switch A/B orientation |
| controller-client (`IOUSBDeviceControllerUserClient` exception) | 1 | Types `0` and `123` unsupported | same as baseline | 16 observed; 32 opens denied | Profile insufficient for function opens |
| interface-client (`IOUSBDeviceInterfaceUserClient` exception) | 1 | Types `0` and `123` unsupported | same as baseline | 16 observed; **32 opens succeeded** | Existing function opens only; no new function was tested |

Choose the least-privileged profile that provides the read-only operations the next gate needs. Each profile was a separate executable and process; the two user-client exceptions were never combined to make a failed row pass.

## Peer and role matrix (measured)

Two consecutive probes per row, with host-side USB attach/detach capture during each run.

| Peer | Orientation | Topology equal | Device-mode controller | VBUS/charging | External re-enumeration | Verdict |
|---|---|---|---|---|---|---|
| Generic capture host (Mac) | A | Equal within each profile; platform fingerprints match Switch A | Yes, one observed | Charging, owner-observed | Zero target lifecycle events in bound 90-second windows | Complete scoped Mac A read-only row |
| Generic capture host (Mac) | B | Equal within each profile and to A | Yes, one observed | Charging, owner-observed | Zero target lifecycle events in bound 90-second windows | Complete scoped Mac B read-only row |
| Switch 2 direct cable | A | Equal within each profile; client fingerprints match Mac A | One controller; `configured`, `onbus=yes` | Owner observed not charging; same-insertion battery external=yes charging=no | No external Switch attach trace (not a U1 requirement) | Device-side row complete, operator peer attribution |
| Switch 2 direct cable | B | Equal within each profile; matches Mac B and Switch A | One controller; `configured`, `onbus=yes` | Owner observed not charging; same-insertion battery external=yes charging=no | No external Switch attach trace (not a U1 requirement) | Device-side row complete, operator peer attribution |

The topology fingerprint covers the target, controller and function topology, configuration digest, symbol availability, entitlements and raw user-client results, excluding capture time and physical labels. Equal fingerprints prove only that the accepted report contents match.

## Gate decision (R1–R3, R14)

| Requirement | Evidence | Decision |
|---|---|---|
| R1 exact inventory | Target tuple `iPad14,5` / `J620AP` / `T8112`, stock USB source SHA-256 `a0f63c8c…1792c5fa`, one controller, 16 functions, twice-equal default/live descriptions matching one stock configuration list; `configuration-string` absent at the device-tree root, recorded explicitly | Pass for read-only inventory |
| R2 authorization boundaries | The matrix above, with raw codes at every boundary | Pass for in-process authorization classification; no physical or external lifecycle claim |
| R3 direct role/power | Configured, on-bus controller with external power on both Switch 2 orientations; peer identity is owner-reported | Pass, device side |
| R14 evidence decision | Private reports, attestations, host-window bindings and stock-source snapshots retained | Pass for the U1 evidence decision |

## Evidence references

All paths are under ignored, owner-only `build/ipad-hardware/`; no raw device identifiers appear here. The validators named below were removed from the repository on 2026-10-31 and are in git history; they can recheck the retained files without contacting the device.

| Evidence | Private path or artifact group | Independent check |
|---|---|---|
| Stock configuration and R1 tuple | `stock-configuration/USBDeviceConfiguration.plist`; installed archives and `controller-descriptions/` | Stock source SHA-256 `a0f63c8c…1792c5fa` matched the configuration digest and the target tuple in all 16 ordinary and 32 earlier admitted-profile reports |
| Under-entitled authorization | `springboard-r2-{baseline,setdescription}-round-{1..8}.json`; `installed-springboard-r2-*-attestation.json` | `validate-springboard-r2-report.py` accepted all 16 app reports; per-profile fingerprints equal across eight rounds: baseline `9ea9d743…e9ced97`, set-description `2f22afd2…2d9e442f` |
| Mac A and B lifecycle windows | `host-lifecycle-springboard-r2-authorization-wifi/` and `…-wifi-a/` | Binding manifests `9367c589…8097dfd3` (B) and `85069725…403da69` (A) match their monitor and report hashes, a complete 90-second zero-event window, and final target presence |
| Direct Switch 2 attribution | `springboard-r2-switch2-b-owner-binding.json`, `springboard-r2-switch2-a-binding.json` | Bindings `286b85df…75fa90d` (B) and `7ddec0cf…58765f` (A) match the retained report hashes; A's same-insertion bus/power categories matched before and after its rounds |
| Earlier client/platform matrix | Eight `auxiliary-probe-…-wifi-control/` and `admission-probe-…-wifi-control/` directories with four `host-lifecycle-…/` companions | `validate-probe-stdout.py` and `validate-admission-probe-stdout.py` accepted all 32 reports in eight groups; two-run fingerprints matched; all four host bindings matched complete zero-event monitor records |

## What the implementation settled

- **Admission:** a plain TrollStore app executable is SIGKILLed before `main` on a direct SSH launch. A SpringBoard launch by exact bundle ID (`uiopen --bundleid`, not a bare ID) reaches the parser and produces reports. An entitled root launchd job also runs, which is the route the U2 broker uses.
- **Entitlement shape:** the only effective delta between the baseline and set-description profiles was set-description itself, and it changed no read-only outcome. Interface access requires the exact `IOUSBDeviceInterfaceUserClient` exception.
- **Trust-chain caveat:** macOS does not trust TrollStore's CoreTrust-bypass signing chain, so installed-code attestation here never claimed a Mac trust-chain verdict; it compared code bytes, CodeDirectory page hashes, entitlements, ownership and modes instead.
- **AppSync route unavailable:** a bounded full-database membership scan found AppSync Unified and appinst `not-observed` (ElleKit `installed`). Installing AppSync is a separate security-changing project and was not part of U1.
- **`ClientTruth.plist`** was backed up byte-for-byte with metadata and ACL before any install, and stayed unchanged throughout; the backup is retained privately.

## Limits of the pass

- Read-only inventory, authorization classification and role/power only. It establishes nothing about HID publication, descriptor restoration or Switch keyboard acceptance.
- Peer identity and cable orientation are owner observations; no independent Switch-side enumeration trace exists, and none was required by U1.
- `ExternalConnected` is a battery flag, not a direct VBUS measurement.
- Bound to the reference device and iPadOS build; another model or OS build needs its own U1 evidence.
- Report batches were unsigned, so summaries were labelled as local self-consistency checks rather than proof that two runs occurred.

## Sources and Research

- Parent plan and Product Contract: [`01-hardware-feasibility.md`](01-hardware-feasibility.md). Redacted gate summary: [`../../ipad/hardware-matrix.md`](../../ipad/hardware-matrix.md).
- Feasibility note that set the proof ladder: [`research/usb-hid-ipad-feasibility.md`](research/usb-hid-ipad-feasibility.md).
- Successor units: [`01-u2-usb-restoration.md`](01-u2-usb-restoration.md) (passed), [`01-u3-hid-canary.md`](01-u3-hid-canary.md) (next).
- The probe variants, validators, orchestrators and the per-round reports' validators are in git history before `2dc9649`; the detailed dated checkpoints are in `docs/ipad/hardware-matrix.md` before `4a4c876`.
