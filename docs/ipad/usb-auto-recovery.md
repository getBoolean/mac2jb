# Automatic USB recovery after a description swap

How the iPad port recovers its USB device connection, without a reboot, after it replaces the USB device description. It covers the mechanism, the detection signal, the healing algorithm and how to embed it in the TrollStore app or a jailbreak tweak. Target: M2 iPad (`iPad14,5`, `AppleT8112USBXDCI`), iPadOS 17 build `21A329`, Dopamine rootless. Evidence and dates are in [the failure analysis](u2-usb-recovery-failure-analysis.md).

## Mechanism

`IOUSBDeviceControllerSetDescription` makes the kernel tear down and recreate every USB function nub (`IOUSBDeviceController::createUSBDevice`). Each function must then register with the controller (`IOUSBDeviceController::gated_registerFunction: register function <name>`). **The controller goes on bus only after all functions have registered.**

A swap races the old function instances that their owners still hold. Each swap therefore leaves a random one or two functions unregistered, and the controller stays `Disconnected / OnBus=no / SelectedConfiguration=0` indefinitely. Observed losers:

| Function | Owner of the registration | Observed failure |
|---|---|---|
| `IapOverUsbHid` | kernel `IOAccessoryPortUSB` (client: `accessoryd`) | `Can't reserve port ID 2 - port ID already reserved!` |
| `USBAudio2Control` / `StreamIN` / `StreamOUT` | kernel `AppleUSBDeviceAudioController` | `USB Sound assertion … AppleUSBDeviceAudioController.cpp` |
| `Valeria` | `IOUSBDeviceInterfaceUserClient` opened by **`audiomxd`** | missing client |

Nothing else recovers a stuck controller: re-sending the description, `GoOffAndOnBus`, `ForceOffBus`, replugging the cable or changing host. A reboot always recovers because boot registers every function cleanly. Restarting `audiomxd` re-registered `Valeria`, and the controller came on bus at once with a registry identical to a healthy boot (2026-10-31).

`ptpd` (PTP) is **not** a cause. It may crash during the swap, and its relaunched instance attaches normally. It waits 10 s for a host and then exits, so PTP lacks a client whenever no host is connected.

## Detection (no logs needed)

A function that failed to register has **no IOService client under its `IOUSBDeviceInterface` nub**. This matched the kernel `register function` log exactly in every capture. `MAC2JBUSBCopyUnservedFunctions` (`ios/usb/USBRestoreControllerShim.c`) walks the exact controller's children, read-only, and returns the `USBDeviceFunction` names of client-less nubs. `PTP` is excluded as host-dependent. "Configured" means `CurrentState` `DeviceState=Configured`, `OnBus=true` and `SelectedConfiguration>0` (`MAC2JBUSBCopyConfiguredState`).

## Algorithm

`USBFunctionRegistrationHealer` (`ios/watchdog/USBFunctionRegistrationHealer.swift`) is pure policy over a probe protocol:

```
loop:
  wait up to settleSeconds (6 s) for configured  -> done
  missing = unserved functions - {PTP}
  if missing is non-empty and every function has a user-space owner
       and no owner has used its restarts (2):  restart those owners; loop
  else if republications < 3:                    re-publish the original description; loop
  else:                                          give up (journal retained)
```

Kernel-owned gaps need a re-publication, which recreates all nubs. When only user-space-owned functions remain, the healer restarts their owners rather than re-publishing, because a re-publication would start a new race. Owner map: `Valeria` → `com.apple.audiomxd`. Restart: `launchctl kickstart -k system/<label>` when `launchctl` exists. Otherwise SIGKILL the process by name, and launchd relaunches the on-demand daemon (`USBFunctionOwnerRestarter.swift`).

## Broker integration (implemented, v9)

`NativeUSBWatchdogService` runs the healer automatically:
- after its readiness gate times out on a first publication (worker-death and normal recovery paths);
- after `restore-after-failure` (the reply ends with the heal summary);
- on demand with the socket command `heal`, with `heal-status` reporting the last summary.

Re-publications go through `USBRestoreCoordinator.recoverAfterExternalFailure`, which journals them and refuses while configured. If healing succeeds without a re-publication, `acceptConfiguredOriginal` records `awaitingVerification`, because the no-op already published the journaled original. **Healing never confirms or clears the journal**; that still needs the host's external proof.

Build: `docs/plans/ipad-port/scripts/ipad-hardware/build-u2-noop-trial-binary.py --v9-auto-heal`.

## Embedding in the TrollStore app or a tweak

Reuse three pieces unchanged: the C shim (`USBRestoreControllerShim.c/.h`), `USBFunctionRegistrationHealer.swift` and `USBFunctionOwnerRestarter.swift`. Provide a probe whose `republish()` publishes your app's description, or the original on failure, through the same clone path.

- **Privileges:**
  - `SetDescription` needs `com.apple.private.usbdevice.setdescription` together with `platform-application`. A plain TrollStore app process was SIGKILLed before `main`, but a root launchd job with those two entitlements runs (U2 admission findings).
  - **TrollStore:** do the USB work in the app's root helper, spawned with `spawnRoot`, signed with those entitlements.
  - **Jailbreak:** ship a launchd daemon like the v9 broker. A tweak injected into another process won't have the entitlement.
- **Owner restart:** TrollStore has no `launchctl`, so the restarter's SIGKILL fallback applies. The helper must run as root to signal `audiomxd`.
- **Memory:** a launchd daemon gets an 18 MB inactive jetsam limit by default, and jailbreak tweak injection (ElleKit, Choicy) adds to it. The v8 broker was killed after about three re-publications. Set `JetsamProperties` (`host/update-u2-v8-jetsam-wifi.py` applies `JetsamMemoryLimit 96`). For TrollStore, keep the helper short-lived: one heal per spawn.
- **Ordering:**
  1. Publish.
  2. Run `heal()` before reporting success.
  3. Expose the outcome to the UI.

  Keep the bounded limits; an unbounded loop can starve memory and leave the controller mid-swap.
- **Watchdog requirement:** keep a journaled original description and a supervised restore path, as `docs/plans/ipad-port/01-hardware-feasibility.md` requires. The healer complements the watchdog; it doesn't replace it.
- **Observability:** the kernel and daemon logs stream over Wi-Fi even while USB is down (`idevicesyslog -n`). `host/recover-u2-over-wifi.py` and the trial runner record them to a private `syslog.txt`.

## Tests

- `tests/test-u2-function-healer.py`: policy replay of the observed registration patterns (6 scenarios).
- `tests/test-u2-native-auto-heal.py`: the real broker on the Mac file-backed fixture, covering:
  - an owner-only gap healed with no re-publication;
  - a kernel gap healed by one re-publication then an owner restart;
  - a bounded give-up after 3 re-publications;
  - the `restore-after-failure` path;
  - the journal left in `awaitingVerification`.
- The existing service, readiness-gate, settled-recovery and Wi-Fi-restore fixtures still pass.

## Status and open items

- **Hardware result (2026-10-31):** a v9 no-op trial lost USB on its first publication and **recovered automatically**, with `healed republications=3 owner-restarts=none`. External checks passed and the journal was confirmed. The manual owner-restart remedy also worked once (`host/recover-u2-restart-function-owner-wifi.py com.apple.audiomxd`).
- The trial used the full republication bound; consider `maxRepublications` 5 now that the jetsam limit is 96 MB. One run is not a reliability figure; repeat trials are needed.
- Hardware scripts: `host/transition-u2-v8-to-v9-wifi.py` (stage v9 over an unresolved journal), `host/run-u2-native-noop-trial-v9-wifi.py` (trial plus a 90 s heal window and one Wi-Fi `heal` fallback), `host/confirm-u2-after-heal-wifi.py` (heal, external checks, confirm).
- Still unvalidated on hardware: an owner map entry for the audio-2 kernel functions (re-publication is the current remedy), and whether `accessoryd` restarts help the iAP port.
- U2 still requires an automated no-op round trip, a full external USB/NCM/descriptor comparison and journal confirmation.
