# iPad hardware gate matrix

Redacted gate decisions for the iPad port's hardware plan (`docs/plans/ipad-port/01-hardware-feasibility.md`). Raw reports and captures stay in ignored `build/ipad-hardware/`; this file holds only decisions, limits and hashes. Reference device: M2 iPad Pro 12.9" (6th gen), `iPad14,5` / `J620AP` / `T8112`, iPadOS 17.0 `21A329`, Dopamine rootless, TrollStore. Dated checkpoint history was condensed on 2026-10-31 (see git history).

## Unit status

| Unit | Decision | Evidence boundary |
|---|---|---|
| U1 read-only target inventory | **Pass (2026-10-30)** | R1–R3 and U1-scoped R14, below. Read-only inventory, authorization and role/power only. |
| U2 restoration journal and watchdog | **Pass (2026-10-31)** | Automatic same-boot recovery: v11 5/5 and v12 2/2 hardware no-op trials. Semantic external equivalence; the `AllowMultipleCreates` flag is an accepted deviation. Below. |
| U3 additive HID canary | Not tested | No HID function, descriptor, endpoint or report test yet. |
| U4 exclusive-HID fallback | Not tested | Conditional fallback only. |
| U5 network topology | Not tested | No paired 20-attempt exploit comparison. |
| U6 capability contract | Not tested | No signed final capability record. |

## U1 decision (2026-10-30): PASS for the read-only scope

The client, platform and ordinary baseline/set-description authorization profiles each have two validated reports on Mac A/B and on owner-reported direct Switch 2 A/B, with stable fingerprints. Six complete Mac USB lifecycle windows recorded zero target events and final presence. On Switch 2 the controller was configured, on bus and externally powered, without charging.

| Requirement | Evidence | Decision |
|---|---|---|
| R1 exact inventory | Target tuple, stock USB source (SHA-256 `a0f63c8c…1792c5fa`), one controller, 16 functions, twice-equal default/live descriptions matching one stock configuration list; `configuration-string` absent at the device-tree root. | Pass |
| R2 authorization boundaries | Ordinary in-process apps: controller opens unsupported (`-536870201`), function opens denied (`-536870174`); the set-description entitlement made no read-only difference. Publication needs `com.apple.private.usbdevice.setdescription` with `platform-application` in a root launchd job (plain apps are SIGKILLed before `main`). | Pass for classification |
| R3 direct role/power | Configured/on-bus with external power on both Switch 2 orientations; peer identity is owner-reported. | Pass (device side) |
| R14 evidence | Private reports, attestations, host-window bindings and stock-source snapshots retained in `build/ipad-hardware/`. | Pass |

## U2 decision (2026-10-31): PASS, automatic recovery

The broker journals the live description, publishes through the controller clone and heals automatically. After a description swap the controller waits for every USB function to re-register. The broker re-publishes a bounded number of times and restarts the user-space owner of a function that failed to register (see `usb-auto-recovery.md`). The healing covers a failed first enumeration, worker death, watchdog restart and lease expiry.

| Broker | Trials | Result |
|---|---|---|
| v11 `8fdb044f…` | normal ×3, worker-kill, watchdog-kill | 5/5 recovered without owner action in 46–61 s (1–3 re-publications, two with an `audiomxd` restart) |
| v12 `96296113…` (learned device profile) | normal, watchdog-kill | 2/2 recovered in 72 s (5 re-publications plus `audiomxd`) and 29 s (1 re-publication) |

Every trial then passed the strict external check against a twice-stable current-boot baseline (`u2-v9-trial-baseline`, manifest `30693c83…18de`):
- five raw configurations with all 23 resolved strings equal;
- equal host interfaces and device scalars;
- NCM driver binding and a packet reply;
- one USBMux device, valid pairing, and power.

Each journal was confirmed only with the SHA-256 of that check's output and re-checked with no journal.

**Accepted deviation:** the live registry description keeps `AllowMultipleCreates=true` as an extra field. The publication path requires it; the other fields equal the stock original. String-descriptor indexes may be renumbered while every resolved string stays equal.

**Limits:** these are seven hardware trials, not the release plan's 30-cycle qualification, and one trial used the full re-publication bound. Fixture coverage is in `docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-*.py`.
