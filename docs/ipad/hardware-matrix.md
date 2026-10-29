# iPad hardware feasibility matrix

The release gate is **plausible but unproven** until the exact M2 iPad Pro target (`iPad14,5` / `J620AP` / `T8112`) on iPadOS 17.0 completes this matrix. Repository builds and fixtures do not substitute for target-device evidence.

## Read-only inventory probe

Build and test the four signed probe variants on an Apple-silicon Mac:

```sh
bash scripts/ipad-hardware/collect-inventory.sh test
bash scripts/ipad-hardware/collect-inventory.sh build
```

The build writes ignored artifacts to `build/ipad-hardware/`:

| Variant | Entitlements | Purpose |
|---|---|---|
| `baseline` | None | Find the first service or user-client denial without private authority |
| `setdescription` | `com.apple.private.usbdevice.setdescription` | Separate controller-description authority from user-client access |
| `controller-client` | One exact controller user-client exception plus platform status | Test `IOUSBDeviceControllerUserClient` without granting interface access |
| `interface-client` | One exact interface user-client exception plus platform status | Test `IOUSBDeviceInterfaceUserClient` without granting controller access |

The probe resolves mutation symbols for capability reporting, but its audit rejects direct calls to USB-description, bus-cycle, command, and registry-write APIs. It only enumerates registry state, opens and closes requested user clients, reads the current controller description through the historical private API, checks CF type identities, and writes a redacted JSON report.

Copy the variants to a root-owned directory on the jailbroken iPad. Run each binary directly, or copy the repository layout and use `collect-inventory.sh run-local`. Supply stable labels for the physical cable and peer; the report stores only their SHA-256 digests.

```sh
./mac2jb-ios-probe-baseline \
  --soc T8112 \
  --port-family thunderbolt-usb4 \
  --dopamine-build DOPAMINE_BUILD \
  --trollstore-build TROLLSTORE_BUILD \
  --peer-kind capture-host \
  --peer-id CAPTURE_HOST_LABEL \
  --cable-id CABLE_LABEL \
  --orientation a \
  --power-state OBSERVED_POWER_STATE \
  --client-type 0 \
  --output /var/jb/var/mobile/Library/mac2jb-probe/capture-host-a-baseline-1.json
```

The connected target is the M2 iPad Pro 12.9-inch (6th generation), `iPad14,5` / `J620AP` / `T8112`, with a `thunderbolt-usb4` port family. Do not reuse its capability record for another ProductType or OS build.

## Authorization matrix

Run the following on a generic capture host before any descriptor mutation work. Record the raw `IOReturn`, the probe's outcome classification, and whether the signed entitlement was observed at runtime.

| Variant | Controller service found | Controller open | Live description and CF types | Matching function services | Verdict |
|---|---:|---:|---:|---:|---|
| baseline | Pending | Pending | Pending | Pending | Pending target run |
| setdescription | Pending | Pending | Pending | Pending | Pending target run |
| controller-client | Pending | Pending | Pending | Pending | Pending target run |
| interface-client | Pending | Pending | Pending | Pending | Pending target run |

Choose the least-privileged profile that provides the read-only operations needed for the next gate. Do not combine the two user-client exceptions to make a failed row pass.

## Peer and role matrix

Use the selected least-privileged profile with one known-good data cable. Perform two consecutive probes for every row. Capture USB attach/detach events on the generic host while the probe runs; any re-enumeration fails the read-only-safety gate.

| Peer | Orientation | Run 1 | Run 2 | Topology equal | Device-mode controller | VBUS/charging | External re-enumeration | Verdict |
|---|---|---|---|---:|---:|---|---:|---|
| Generic capture host | A | Pending | Pending | Pending | Pending | Pending | Pending | Pending |
| Generic capture host | B | Pending | Pending | Pending | Pending | Pending | Pending | Pending |
| Switch keyboard screen | A | Pending | Pending | Pending | Pending | Pending | N/A to capture; observe attach only | Pending |
| Switch keyboard screen | B | Pending | Pending | Pending | Pending | Pending | N/A to capture; observe attach only | Pending |

Compare consecutive reports on the Mac:

```sh
bash scripts/ipad-hardware/collect-inventory.sh compare RUN_1.json RUN_2.json
```

The comparison uses `topologyFingerprint`, which excludes capture time and physical-label hashes while including the target, controller/function topology, configuration digest, symbol availability, entitlements, and raw user-client authorization results.

## U1 gate decision

U1 passes only when:

- the authorization matrix identifies each missing symbol, missing service, denied user client, ABI mismatch, or successful read-only boundary;
- both peers and both cable orientations expose the expected device-mode controller and an acceptable observed power state;
- two consecutive runs per role row have the same topology fingerprint; and
- the generic host capture shows no disconnect or re-enumeration caused by any probe run.

Until those conditions are recorded, U2 restoration and every descriptor-changing experiment remain blocked. Keep raw reports and captures outside Git. Commit only this redacted matrix after replacing the pending cells with evidence references and pass/fail outcomes.
