# M2 iPad target findings

This document records observations from the physical iPad used for the hardware-feasibility work. It intentionally omits the device UDID, serial number, network addresses, SSH key material, and other unique identifiers. Raw command output should remain outside Git when it contains any of those values.

Last updated: 2026-10-28

## Target identity

| Field | Observed value | Evidence status |
|---|---|---|
| Product family | iPad Pro 12.9-inch (6th generation) | Identified from the model tuple |
| SoC | Apple M2 | Identified from the model tuple |
| ProductType | `iPad14,5` | Observed from the connected device |
| Board identifier | `J620AP` | Observed from the connected device |
| Platform | `T8112` | Observed from the connected device |
| Port family | Thunderbolt / USB 4 | Model capability; live USB role remains unproven |
| iPadOS | 17.0 (`21A329`) | Observed from the connected device |

These observations supersede the original M1/T8103 planning assumption. Findings must not be generalized to another ProductType or OS build.

## Connection and power

| Observation | Result | Interpretation |
|---|---|---|
| Physical connection | USB | The current evidence session used a direct USB connection |
| `BatteryIsCharging` | `true` | The device reported that its battery was charging during the query |
| `ExternalConnected` | `true` | The device reported an external power connection during the query |

The power properties do not establish USB host/device data role, controller selection, cable orientation behavior, or compatibility with the Switch. Those remain U1 gate work.

## Read-only SSH access

| Observation | Result |
|---|---|
| Account | `mobile` |
| Numeric user ID | `501` |
| Authentication | Public-key authentication succeeded with batch mode enabled |
| Password policy | OpenSSH was configured by the device owner to require a key |
| Reported machine value | `iPad14,5` |
| Reported product version | `17.0` |

SSH commands can still cause ordinary authentication, process, and accounting logs even when their payload is read-only. No command should be described as producing literally zero writes at the operating-system level.

## Jailbreak package observations

A read-only package query found:

| Package | Version |
|---|---|
| `dopamine-basebin-link` | `1.0.0` |
| `libkrw0-dopamine` | `2.0.4` |
| `libroot-dopamine` | `1.0.1` |

These package versions establish the presence of Dopamine-related rootless components. They do not establish the exact installed Dopamine application build or the TrollStore build; both remain unknown.

## Available inspection tools

The following paths were resolved with read-only `command -v` queries under a fixed PATH:

| Tool | Result |
|---|---|
| `ioreg` | `/usr/sbin/ioreg` |
| `grep` | `/var/jb/usr/bin/grep` |
| `find` | `/var/jb/usr/bin/find` |
| `plutil` | Not found on the inspected PATH |

The missing `plutil` result means only that it was not found in the reviewed PATH. It does not prove that no equivalent utility or differently located binary exists.

## Command-safety procedure

Every future command or script executed on the iPad must follow this sequence:

1. Draft the exact on-device payload with no placeholders.
2. Submit that payload to an adversarial safety review.
3. Show the reviewed payload, verdict, intended output, and residual risks to the device owner.
4. Obtain explicit approval through the native execution approval prompt.
5. Execute only the approved payload and record whether it ran, failed locally, or was aborted before dispatch.
6. Record the redacted result and avoid committing unique device identifiers or secrets.

Unless the device owner explicitly authorizes otherwise, iPad commands must be observational and read-only. SSH/process logging is an acknowledged residual effect. A command rejected or changed by review must be reviewed and approved again.

## Execution register

| Payload purpose | Device execution | Result |
|---|---|---|
| Verify key-only SSH and basic target values | Executed | UID `501`, machine `iPad14,5`, product version `17.0` |
| Query Dopamine/TrollStore-related packages | Executed | Three Dopamine-related packages found; exact app builds unresolved |
| Read charging state | Executed | `BatteryIsCharging=true` |
| Read external-power state | Executed | `ExternalConnected=true` |
| Resolve `ioreg`, `plutil`, and `find` | Executed | Paths/status recorded above |
| Resolve trusted `grep` path | Executed | `/var/jb/usr/bin/grep` |
| First query of allowlisted `IOUSBDeviceController` properties | **Not executed** | Initial approval dispatch was aborted; no registry result was obtained |
| Query allowlisted `IOUSBDeviceController` properties | Executed | No allowlisted lines observed; pipeline exited `1`, so controller properties were not observed or the query failed |
| Query numeric `IOUSBDeviceInterface` properties | Executed | No allowlisted numeric lines observed; pipeline exited `1`, so interface properties were not observed or the query failed |
| Check `configuration-string` presence without emitting its value | **Not executed** | Native approval dispatch was aborted; no device-tree result was obtained |

The registry queries filtered both `ioreg` output streams through exact property-name and value-shape allowlists. Their empty output is inconclusive because each pipeline exposes `grep`'s status rather than `ioreg`'s status; it must not be interpreted as proof that no matching controller or interface exists.

## Repository-side probe status

The U1 inventory implementation exists locally and has passed repository-side checks for its Swift result model, arm64 iOS 17 cross-build, signed entitlement variants, and mutation-call audit. Its controller and interface inventory now records separate user-client open outcomes, and topology fingerprints include both authorization surfaces. This proves buildability and the intended read-only code boundary; it does not prove runtime authorization, ABI compatibility, controller topology, or non-re-enumeration on the iPad.

`IOUSBDeviceDescriptionCreateFromDefaultsAndController` is known to participate in iOS default-configuration loading, but the current evidence does not establish its calling convention. The probe resolves its symbol without invoking it rather than guessing a private ABI.

No probe binary has been copied to or executed on the iPad under the current read-only authorization. Copying a binary, creating a report, changing entitlements, or deleting the temporary authorized key would be a device write and requires separate explicit authorization.

## Open findings required for U1

- Allowlisted controller and interface registry properties.
- Presence-only observation of the device-tree `configuration-string`, without recording its raw value.
- Exact Dopamine and TrollStore application builds.
- Active device-mode controller, controller ancestry, and available user-client classes.
- Runtime symbol availability and harmless CF type checks from each signed probe variant.
- Least-privileged read-only user-client authorization outcomes.
- Direct-cable data role and power behavior for both USB-C orientations with a generic capture host and the Switch.
- Two consecutive topology-equivalent observations per role row.
- External confirmation that the read-only probe causes no disconnect or re-enumeration.

Until those observations are complete, U1 remains pending and descriptor-changing work remains blocked.
