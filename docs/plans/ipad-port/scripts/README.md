# iPad port scripts

All iPad hardware tools live in [`ipad-hardware/`](ipad-hardware/): `host/` runs on the Mac, `device/` holds payloads that host tools stream to the device over pinned SSH (never copied to it), and `tests/` holds Mac-only fixtures. Run tools from the repository root. Read `docs/ipad/README.md` and the repository skill before running anything against a device; `docs/ipad/usb-recovery.md` is the operating runbook.

Only the tools for the current workflow are kept. The historical U1 probes, the version-specific U2 trial/stage/archive/confirm tools (v1–v10) and the Python broker prototype were removed on 2026-10-31; they are in git history. The broker itself is Swift, in `ios/watchdog/` and `ios/usb/`.

## Build and diagnostics

| Tool | Effect |
|---|---|
| `./build-u2-noop-trial-binary.py` | Build a separate signed native U2 no-op-trial binary on the Mac only. |
| `./diagnose-ipad-ssh-transport.py` | Classify the pinned iPad SSH transport without opening a remote session. |

## Host tools

### Connection and host keys

| Tool | Effect |
|---|---|
| `host/backup-clienttruth-over-root-ssh.py` | Save a private, verified ClientTruth.plist backup over pinned root SSH. |
| `host/canonicalize-usb-known-hosts.py` | Canonicalize SSH host keys observed through the pinned physical USB tunnel. |
| `host/check-pinned-ssh-while-app-closed.py` | Check pinned USB SSH for both iPad accounts while ChatGPT is fully quit. |
| `host/check-pinned-wireless-ssh.py` | Check target iPad SSH over Wi-Fi against the existing pinned USB host key. |
| `host/classify-current-usb-ssh-host.sh` | Redacted classifier for the current Ed25519 host-key scan over pinned USB. |
| `host/classify-usb-known-hosts.py` | Classify a private ssh-keyscan capture without emitting key material. |
| `host/diagnose-usb-recognition.py` | Classify Mac-side iPad USB recognition without contacting or changing it. |
| `host/discover-pinned-ipad-wifi.py` | Find the target iPad's Wi-Fi address without exposing it in output. |
| `host/exact-link-no-replace.py` | Create one exact-path hard link without command-line directory semantics. |
| `host/pin-current-usb-ssh-host.sh` | Establish a new local SSH host-key pin from the physically bound USB target. |
| `host/reconstruct-pinned-known-hosts.py` | Reconstruct an earlier known-hosts file from the same current public keys. |
| `host/restore-pinned-known-hosts.sh` | Restore the previously reviewed localhost SSH host-key pin after /tmp loss. |
| `host/save-private-ipad-wifi-address.py` | Store the target iPad's Wi-Fi IPv4 privately for later headless SSH checks. |
| `host/start-usb-ssh-tunnel.sh` | Start the local USB-to-SSH transport used by the reviewed iPad probes. |

### Trials, recovery and broker deployment

| Tool | Effect |
|---|---|
| `host/backup-u2-wifi-restore-kit.py` | Back up everything a later Wi-Fi SSH USB restore needs into one private Mac kit. |
| `host/confirm-u2-after-heal-wifi.py` | Advance a healed U2 journal and confirm it only after external checks pass. |
| `host/recover-u2-over-wifi.py` | Standard response when a U2 trial loses Mac USB: back up, capture, then one Wi-Fi restore. |
| `host/recover-u2-restart-function-owner-wifi.py` | Restart the userspace owner of the one unregistered USB function, then observe. |
| `host/recover-u2-until-registered-wifi.py` | Bounded re-publication until every USB function registers (Wi-Fi only). |
| `host/replace-u2-broker-wifi.py` | Swap one allowlisted U2 broker for another over pinned root Wi-Fi SSH (usage: OLD NEW). |
| `host/run-u2-noop-trial-auto-heal-wifi.py` | One auto-heal no-op U2 trial (normal | worker-kill | watchdog-kill) on any staged broker. |
| `host/u2-usb-lifecycle-monitor.swift` | Passive Mac USB arrival/termination monitor for a target vendor/product (used by trials). |
| `host/u2-usb-return-observer.py` | Passively observe a target iPad's Mac USB return from an absent state. |
| `host/u2_broker_profile.py` | Fetch the broker's on-device learned USB device profile over pinned root Wi-Fi SSH. |
| `host/u2_trial_support.py` | Shared helpers for the current U2 host tools (no device writes here). |

### Strict external check and its capture helpers

| Tool | Effect |
|---|---|
| `host/capture-u2-host-interfaces.py` | Capture the Mac-visible iPad USB interface descriptor tree privately. |
| `host/capture-u2-host-usb-scalars.py` | Capture private Mac IOUSB device scalars for the U2 before/after comparison. |
| `host/capture-u2-private-baseline.py` | Save a private, read-only U2 baseline for the exact connected iPad. |
| `host/capture-u2-raw-configs.py` | Save external raw USB configuration descriptors without opening the iPad. |
| `host/capture-u2-trial-baseline.py` | Capture a twice-stable private external baseline for auto-heal trials on the current boot. |
| `host/check-u2-external-current.py` | Recheck the live iPad/Mac U2 baseline without changing either device. |
| `host/check-u2-host-ncm-link.py` | Classify the Mac link state of the iPad's bound USB NCM interface. |
| `host/check-u2-host-network-function.py` | Classify whether the connected iPad has an active Mac USB network driver. |
| `host/check-u2-power-wifi.py` | Read the iPad battery's external-power flags over pinned Wi-Fi SSH. |
| `host/check-u2-recovered-current.py` | Compare the current iPad/Mac USB state with the new-boot U2 reference. |
| `host/check-u2-strict-external.py` | Strict external USB check: compare the current device/Mac USB state with a pinned private baseline. |
| `host/check-u2-trial-current.py` | Full read-only external USB check against the current-boot trial baseline. |
| `host/diagnose-u2-live-description-wifi.py` | Compare the current iPad live USB dictionary with private U2 originals. |
| `host/diagnose-u2-recovery-stage.py` | Classify the current U2 recovery stage without changing the iPad. |
| `host/diagnose-u2-semantic-descriptors.py` | Compare U2 Mac USB observations without sending a USB request. |
| `host/probe-u2-ncm-packet-flow.py` | Verify one bounded packet round trip over the iPad USB NCM link. |
| `host/probe-u2-readonly-string-descriptors.py` | Run the pinned Mac nonexclusive USB string-descriptor probe. |
| `host/u2-readonly-raw-config-descriptors.c` |  |
| `host/u2-readonly-string-descriptors.c` |  |
| `host/u2-string-semantics.py` | Compare USB configuration descriptors by resolved string values. |

### Read-only device probes (pinned)

| Tool | Effect |
|---|---|
| `host/read-u2-accessory-ports-wifi.py` | Hash-pin and validate one read-only XDCI IOAccessoryPort census over root Wi-Fi SSH. |
| `host/read-u2-controller-state-keys-wifi.py` | Run the pinned read-only controller CurrentState key classifier over Wi-Fi. |
| `host/read-u2-journal-state-wifi.py` | Read the broker journal phase and file SHA-256 over pinned root Wi-Fi SSH (read-only). |
| `host/read-u2-lock-state-wifi.py` | Hash-pin and validate one read-only XDCI device lock state over root Wi-Fi SSH. |
| `host/read-u2-provider-job-state-wifi.py` | Hash-pin and validate one read-only XDCI launchd provider job state over root Wi-Fi SSH. |
| `host/read-u2-typec-property-keys-wifi.py` | Run the exact read-only Type-C property-key scan over pinned root Wi-Fi. |
| `host/read-u2-typec-scalar-state-wifi.py` | Read one bounded Type-C/XDCI scalar snapshot through pinned root Wi-Fi. |
| `host/read-u2-usb-function-providers-wifi.py` | Hash-pin and validate one read-only USB function-provider job/process listing over root Wi-Fi SSH. |
| `host/read-u2-usb-role-classes-wifi.py` | Run the bounded read-only USB-role IOService class scan over pinned Wi-Fi. |
| `host/read-u2-usb-service-candidates-wifi.py` | Run the exact read-only USB service classifier over pinned root Wi-Fi SSH. |
| `host/read-u2-xdci-child-census-wifi.py` | Hash-pin and validate one read-only XDCI child census over root Wi-Fi SSH. |
| `host/read-u2-xdci-function-census-wifi.py` | Hash-pin and validate one read-only XDCI per-node function census over root Wi-Fi SSH. |
| `host/read-u2-xdci-parent-power-wifi.py` | Run a hash-pinned, read-only XDCI ancestor power probe over pinned Wi-Fi. |
| `host/read-u2-xdci-property-keys-wifi.py` | Run the bounded read-only XDCI ancestor property-key probe over pinned Wi-Fi. |

## Device payloads

| Tool | Effect |
|---|---|
| `device/u1-readonly-clienttruth-backup-metadata.py` | Stream bounded metadata and digest for a private ClientTruth backup. |
| `device/u1-readonly-controller-description-copy.py` | Copy the controller's existing default and live descriptions without USB writes. |
| `device/u1-readonly-power-source-state.py` | Classify iPad battery external-power and charging flags without writes. |
| `device/u2-noop-trial-client.py` | Drive the auto-heal broker through one bounded no-op trial (job label substituted by the runner). |
| `device/u2-readonly-accessory-ports.py` | Bounded read-only census of IOAccessoryPort services anywhere in the registry. |
| `device/u2-readonly-controller-state-keys.py` | List bounded USB controller CurrentState key names without changing it. |
| `device/u2-readonly-lock-state.py` | Bounded read-only device lock/screen state. |
| `device/u2-readonly-native-journal-state.py` | Classify only the native U2 journal phase and file hash, without writes. |
| `device/u2-readonly-provider-launch-plists.py` | Bounded read-only export of fixed Apple USB-function launchd job plists. |
| `device/u2-readonly-ptpd-job-state.py` | Bounded read-only launchd state for the USB function provider jobs. |
| `device/u2-readonly-restore-kit-export.py` | Bounded read-only export of every mac2jb U2 file needed for a Wi-Fi restore. |
| `device/u2-readonly-typec-property-keys.py` | List bounded Type-C transport and XDCI property names/types only. |
| `device/u2-readonly-typec-scalar-state.py` | Read one bounded Type-C transport and XDCI scalar-state snapshot. |
| `device/u2-readonly-usb-function-providers.py` | Bounded read-only listing of candidate USB function provider jobs and processes. |
| `device/u2-readonly-usb-role-classes.py` | Discover USB role-related IOService class pairs without reading values. |
| `device/u2-readonly-usb-service-candidates.py` | List bounded USB-related launchd labels and processes without changing them. |
| `device/u2-readonly-xdci-child-census.py` | Bounded read-only IOService child census of the sole XDCI controller. |
| `device/u2-readonly-xdci-function-census.py` | Bounded read-only per-node census of the sole XDCI controller subtree. |
| `device/u2-readonly-xdci-parent-power.py` | Read two XDCI ancestor power scalars and the controller's bus state. |
| `device/u2-readonly-xdci-property-keys.py` | List bounded USB XDCI and ancestor property names/types, without values. |
| `device/u2-replace-broker.py` | Replace one allowlisted U2 broker with another, keeping any active journal. |
| `device/u2-wifi-restore-request.py` | Ask the staged U2 broker for exactly one restore after a host-observed USB failure. |
| `device/u2_target_snapshot.py` | Read the exact iPad identity and live USB description for the watchdog. |

## Tests (Mac-only)

| Tool | Effect |
|---|---|
| `tests/test-ipad-canonicalize-usb-known-hosts.py` | Hermetic checks for USB-bound SSH host-key canonicalization. |
| `tests/test-ipad-classify-usb-known-hosts.py` | Hermetic checks for redacted USB host-key classification. |
| `tests/test-ipad-current-usb-host-classifier.py` | Hermetic checks for the USB host-key classification wrapper. |
| `tests/test-ipad-current-usb-host-pin.py` | Hermetic checks for USB-bound current host-pin publication. |
| `tests/test-ipad-exact-link-no-replace.py` | Hermetic checks for exact-path, no-replace host-pin publication. |
| `tests/test-ipad-host-pin-restorer.py` | Hermetic checks for the host-pin restoration wrapper. |
| `tests/test-ipad-reconstruct-pinned-known-hosts.py` | Hermetic checks for private known-hosts reconstruction. |
| `tests/test-ipad-ssh-transport-diagnostic.py` | Hermetic tests for the no-session SSH transport diagnostic. |
| `tests/test-u2-device-profile.py` | Compile and run the Mac-only on-device profile learning tests. |
| `tests/test-u2-function-healer.py` | Compile and run the Mac-only USB function-registration healer policy tests. |
| `tests/test-u2-native-auto-heal.py` | Prove the broker heals unregistered USB functions automatically (Mac fixture). |
| `tests/test-u2-native-readiness-gate.py` | Prove worker death cannot issue a second USB call before readiness. |
| `tests/test-u2-native-service-fixture.py` | Fault-test the native watchdog socket loop with a fake Mac controller. |
| `tests/test-u2-native-settled-recovery.py` | Verify the real watchdog waits before restoring after worker death on Mac. |
| `tests/test-u2-native-wifi-restore.py` | Prove `restore-after-failure` republishes once only when USB is lost. |
| `tests/test-u2-recovered-current.py` | Exercise the fail-closed live and Mac interface rules of the U2 checker. |
| `tests/test-u2-string-descriptors.py` | Exercise the Mac string-probe envelope parser without a USB device. |
| `tests/test-u2-string-semantics.py` | Test value-based USB string equivalence without a connected device. |
| `tests/test-u2-target-pairing.py` | Mac-only fixture for the U2 USB/network target and pairing gate. |

Run one with `python3 docs/plans/ipad-port/scripts/ipad-hardware/tests/<name>.py`. The `test-u2-native-*`, `test-u2-device-profile` and `test-u2-function-healer` tests compile the real Swift broker sources against fakes.
