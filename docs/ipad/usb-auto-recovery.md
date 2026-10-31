# Automatic USB recovery after a description swap

How the iPad port recovers its USB device connection, without a reboot, after it replaces the USB device description. It covers the mechanism, the detection signal, the healing algorithm, the on-device learned profile, and how to embed this in the TrollStore app or a jailbreak tweak. Reference device: M2 iPad (`iPad14,5`, `AppleT8112USBXDCI`), iPadOS 17.0 `21A329`, Dopamine rootless. Operating procedure: [runbook](usb-recovery.md).

## Mechanism

`IOUSBDeviceControllerSetDescription` makes the kernel tear down and recreate every USB function nub (`IOUSBDeviceController::createUSBDevice`). Each function must then register with the controller (`IOUSBDeviceController::gated_registerFunction: register function <name>`). **The controller goes on bus only after all functions have registered.**

A swap races the old function instances that their owners still hold. Each swap therefore leaves a random one or two functions unregistered, and the controller stays `Disconnected / OnBus=no / SelectedConfiguration=0` indefinitely. Observed losers on the reference iPad:

| Function | Owner of the registration | Observed failure |
|---|---|---|
| `IapOverUsbHid` | kernel `IOAccessoryPortUSB` (client: `accessoryd`) | `Can't reserve port ID 2 - port ID already reserved!` |
| `USBAudio2Control` / `StreamIN` / `StreamOUT` | kernel `AppleUSBDeviceAudioController` | `USB Sound assertion … AppleUSBDeviceAudioController.cpp` |
| `Valeria` | `IOUSBDeviceInterfaceUserClient` opened by **`audiomxd`** | missing client |

Nothing else recovers a stuck controller: re-sending the description, `GoOffAndOnBus`, `ForceOffBus`, replugging the cable or changing host. A reboot always recovers because boot registers every function cleanly.

`ptpd` (PTP) is not a cause. It may crash during the swap, and its relaunched instance attaches normally. It waits 10 s for a host and then exits, so PTP lacks a client whenever no host is connected.

## How it was found (summary)

Over seven failed trial designs (v1–v8), each recovered only by a reboot, these hypotheses were tested and refuted:
- the description constructor path;
- timing of the second restore;
- a readiness gate on its own;
- `ForceOffBus`;
- a speed mismatch;
- `ptpd`'s launch;
- wired-accessory authorization;
- Type-C state.

The deciding evidence came from two sources:
- **The live network syslog** (`idevicesyslog -n`, which works with USB down). It showed 14 or 15 of 16 `register function` lines per swap, with the missing ones varying.
- **Healthy-versus-failed registry censuses.** The missing clients matched the unregistered functions exactly.

Restarting `audiomxd` registered the last function and brought USB back on the same boot. The broker then automated the remedy, which passed 7/7 hardware trials, including worker-kill and watchdog-kill. Full dated history is in git (`docs/ipad/u2-usb-recovery-failure-analysis.md` before 2026-10-31).

## Detection (no logs needed)

A function that failed to register has **no IOService client under its `IOUSBDeviceInterface` nub**. This matched the kernel `register function` log in every capture. `MAC2JBUSBCopyUnservedFunctions` (`ios/usb/USBRestoreControllerShim.c`) walks the exact controller's children, read-only, and returns the `USBDeviceFunction` names of client-less nubs. Host-dependent functions (`PTP`) are excluded. "Configured" means `CurrentState` `DeviceState=Configured`, `OnBus=true` and `SelectedConfiguration>0` (`MAC2JBUSBCopyConfiguredState`).

## Algorithm

`USBFunctionRegistrationHealer` (`ios/watchdog/USBFunctionRegistrationHealer.swift`) is pure policy over a probe protocol:

```
loop:
  wait up to settleSeconds (6 s) for configured  -> done
  missing = unserved functions - host-dependent functions
  if missing is non-empty and every function has a user-space owner
       and no owner has used its restarts (2):  restart those owners; loop
  else if republications < 5:                    re-publish the original description; loop
  else:                                          give up (journal retained)
```

Kernel-owned gaps need a re-publication, which recreates all nubs. When only user-space-owned functions remain, the healer restarts their owners rather than re-publishing, because a re-publication would start a new race. Owners come from the learned device profile. A launchd label is restarted with `launchctl kickstart -k system/<label>`; without `launchctl` (TrollStore), the process is SIGKILLed by name and launchd relaunches the on-demand daemon (`USBFunctionOwnerRestarter.swift`).

## Device profile: learned on the device

No device data is compiled in or committed per device. On its first start on a given product and OS build, while the controller is configured, every non-host-dependent function is served, and no journal exists, the broker **learns a profile** (`ios/watchdog/USBDeviceProfile.swift`) and stores it as root-owned 0600 `device-profile.json` in its state directory. It re-learns after an OS update under the same conditions; until then it refuses to publish. The profile records:

- `productType`, `osBuild`;
- the stock `USBDeviceConfiguration.plist` SHA-256 and size, or none if the device has no such file;
- the stock live field count, with any `AllowMultipleCreates` flag stripped;
- USB vendor/product IDs and healthy `bcdUSB`/`MPS0`;
- the function list;
- the owners.

An owner is a function whose direct client is an `IOUSBDeviceInterfaceUserClient`. The broker takes the process from `IOUserClientCreator` and the launchd label from `launchctl list` when available (`MAC2JBUSBCopyFunctionClients`). The only built-in rule is iOS-wide: `PTP` is host-dependent. The profile contains no serials or UDIDs. Host tools read it with the broker's `profile` command (`host/u2_broker_profile.py`). On the reference iPad it learned 16 functions, `Valeria → audiomxd` (`com.apple.audiomxd`), PTP host-dependent, `784/9`, and IDs `0x05ac/0x12ab`.

## Broker integration

`NativeUSBWatchdogService` runs the healer automatically:
- after its readiness gate times out on a first publication (worker-death and normal recovery paths);
- after a watchdog restart or lease expiry, at most 3 start-up heals per journal so a crashing broker cannot re-publish forever;
- after `restore-after-failure`, whose reply ends with the heal summary.

Socket commands: `heal`, `heal-status`, `profile`. Re-publications go through `USBRestoreCoordinator.recoverAfterExternalFailure`, which journals them and refuses while configured. If healing succeeds without a re-publication, `acceptConfiguredOriginal` records `awaitingVerification`, because the no-op already published the journaled original. **Healing never confirms or clears the journal**; that needs the host's external proof.

Build: `docs/plans/ipad-port/scripts/ipad-hardware/build-u2-noop-trial-binary.py --v12-learned-profile`,
or `--v13-additive-function` for the build that can also append a function.

## Restoring a description that is not a no-op

A publication that appends a function changes the restore contract, and getting
this wrong is costly to diagnose. The clone path refuses to publish unless the
live description equals the journaled original apart from `AllowMultipleCreates`
and the two scalars an earlier trial changed. After an appending publication the
live description legitimately differs by the appended interface, so an unmodified
restore is refused and the journal falls to `recoveryRequired` — which on the
device looks exactly like the controller refusing to restore, rather than like
the shim refusing.

So the restore path is told what to take off: the broker records the appended
function's name and configuration on the journal **record** when it publishes,
and the restore strips exactly that name before the equality check. The record,
not the recipe, carries it, so the recipe's digest and its field and
configuration counts stay what every host tool and the external check already
expect. Those two fields are optional and absent on an older journal.

Two rules keep the strip from becoming a way to lose an interface:

- the strip is refused unless the name is the **last** element of that
  configuration's interface list, so nothing else can be dropped;
- a refused strip is followed by exactly one plain restore of the journaled
  original, which the clone-equality check refuses unless the bus already
  carries that original. That is what recovers a publication whose controller
  call failed with nothing written, and it cannot remove a foreign interface,
  because a bus carrying one fails both the strip and the retry.

`acceptConfiguredOriginal` also refuses while the record still names an appended
function: healing can bring the controller on bus with no re-publication, but
that path's premise is that the bus carries the journaled original, which is
false until the appended function has come off.

## Embedding in the TrollStore app or a tweak

Reuse unchanged: the C shim (`USBRestoreControllerShim.c/.h`), `USBDeviceProfile.swift`, `USBFunctionRegistrationHealer.swift` and `USBFunctionOwnerRestarter.swift`. Provide a probe whose `republish()` publishes your app's description, or the original on failure, through the same clone path. An app that appends anything to the description must also carry the restore rules above, or its own restore will be refused.

- **Privileges:**
  - `SetDescription` needs `com.apple.private.usbdevice.setdescription` together with `platform-application`. A plain TrollStore app process was SIGKILLed before `main`; a root launchd job with those two entitlements runs.
  - **TrollStore:** do the USB work in the app's root helper (`spawnRoot`), signed with those entitlements, and store the profile in the helper's private state.
  - **Jailbreak:** ship a launchd daemon like the broker. A tweak injected into another process won't have the entitlement.
- **Owner restart:** TrollStore has no `launchctl`, so the SIGKILL fallback applies. The helper must run as root.
- **Memory:** a launchd daemon gets an 18 MB inactive jetsam limit by default, and jailbreak tweak injection (ElleKit, Choicy) adds to it. A broker without a limit was killed after about three re-publications. Set `JetsamProperties` (`JetsamMemoryLimit 96`). Under TrollStore, keep the helper short-lived: one heal per spawn.
- **Ordering:**
  1. Learn or load the profile.
  2. Publish.
  3. Run `heal()` before reporting success.
  4. Expose the outcome to the UI.

  Keep the bounded limits.
- **Watchdog requirement:** keep a journaled original description and a supervised restore path. The healer complements the watchdog; it doesn't replace it.
- **Observability:** kernel and daemon logs stream over Wi-Fi while USB is down (`idevicesyslog -n`). The recovery tools record them to a private `syslog.txt`.

## Tests

All Mac-only, in `docs/plans/ipad-port/scripts/ipad-hardware/tests/`:
- `test-u2-device-profile.py`: learning from the reference census, TrollStore without `launchctl`, refusing unhealthy or unserved state, bad names, store permissions.
- `test-u2-function-healer.py`: policy replay of the observed registration patterns.
- `test-u2-native-auto-heal.py`: the real broker on the file-backed fixture, covering:
  - an owner-only gap;
  - a kernel gap healed by re-publication then an owner restart;
  - a bounded give-up after 5 re-publications;
  - a watchdog restart;
  - `restore-after-failure`;
  - the journal left in `awaitingVerification`.
- The service, readiness-gate, settled-recovery and Wi-Fi-restore fixtures.

## Status and open items

- **Hardware:** v11 5/5 trials (normal ×3, worker-kill, watchdog-kill) and v12 2/2 (normal, watchdog-kill) recovered automatically in 29–72 s and passed the strict external check (see [hardware matrix](hardware-matrix.md)).
- **Tuning:** one v12 normal trial used all 5 re-publications. Options are a higher bound (memory allows it) or restarting known owners alongside re-publication.
- **Unvalidated:** owner restarts for the kernel audio-2 functions (re-publication is the current remedy), and whether an `accessoryd` restart helps the iAP port.
- **Other devices:** each needs its own qualification trials. Lightning devices are a stretch goal pending U3 HID results.
