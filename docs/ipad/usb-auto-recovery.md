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

## A registered nub with no driver cannot be re-matched from user space

A nub can come back and its kernel driver still not attach: after one
publish-and-restore cycle the device was left with two
`AppleUSBDeviceAudioController` instead of three, on a bus whose descriptor was
byte-identical to stock. There is no user-space call that re-runs matching on
one existing service, so a publication - which destroys and recreates every nub,
and matches them afresh - remains the only remedy. The evidence, against
xnu-10002.1.13 (the iOS 17 era) and the current SDK headers:

- `IOServiceRequestProbe` exists on iOS (it is exported by `IOKit.tbd` although
  the header marks it unavailable to public iOS clients) and its MIG routine
  does no privilege or MACF check at all - it forwards straight to
  `IOService::requestProbe`, whose generic implementation **returns
  `kIOReturnUnsupported`** (`IOService.cpp`). Only a family that overrides it
  does anything, and what it does is family-defined. It is a bus *rescan*
  request, not a matching request: nothing in IOKit turns it into
  `startMatching`. Call it on a nub if you want the measurement; never on the
  controller, where a family rescan is precisely what recreates every nub.
- `IORegistryEntrySetCFProperty`/`SetCFProperties` reach
  `IORegistryEntry::setProperties`, default `kIOReturnUnsupported`, behind a
  MACF hook and a `IORegistryEntryAllowableSetProperties` filter. Even when a
  family accepts a property, setting one never starts a matching pass.
- The `IOCatalogue` route is the only generic re-match (`IOCatalogue::addDrivers`
  with matching, which calls `IOService::catalogNewDrivers` and does
  `startMatching` on every already-registered service of the personality's
  provider class). It is unreachable in practice: `is_io_catalog_send_data`
  requires the `kIOCatalogManagement` entitlement and, for a task without it,
  **returns `kIOReturnSuccess` without doing anything** - so a success from
  `IOCatalogueSendData` proves nothing. An exactly duplicate personality is
  skipped as a dup and starts no matching at all, so forcing a pass would mean
  leaving a modified personality in the kernel catalogue until reboot.
  `IOCatalogueTerminate(kIOCatalogServiceTerminate)` is administrator-gated,
  compiled out under `SECURE_KERNEL`, and acts on a whole class - it would
  terminate all 16 function nubs.

Tools: `host/rematch-u2-driverless-function-wifi.py` (`--explain-census`,
`--inspect`, `--probe FUNCTION`) over `device/u3-rematch-driverless-function.py`.
`--explain-census` is the part to rely on: it says whether a census difference
is a missing **function nub** (the description on the bus is wrong; the device
still needs restoring) or only a missing kernel child driver or on-demand client
(nothing a host can see in the descriptor). Retained censuses show the audio
drivers, the `ptpd` and `audiomxd` clients and the accessory port coming and
going on a device whose description is unchanged, so the healthy 44-node census
is only a reference for a controller that is configured and attached to a host.

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
- after `restore-after-failure`, whose reply ends with the heal summary;
- on an explicit `heal` during a live publication, which the additive build
  accepts while a worker is registered and the lease has not expired. There is
  no automatic trigger for this one: a live publication is something a host is
  watching, so the broker only heals it when asked.

Socket commands: `heal`, `heal-status`, `profile`, and in the additive build
`renew-lease`.

**Two kinds of re-publication, and the distinction is the whole point.**
*Restoring* - an expired lease, a dead worker, a watchdog restart, an explicit
`restore` or `restore-after-failure` - publishes the bare journaled original
through `recoverAfterExternalFailure`, because the bus coming back matters more
than anything appended surviving. *Continuing* - a `heal` while the lease is
live - publishes the original **plus** the recorded appended function in one
write, through `republishIntended`. Before this existed, the only mechanism that
brought the bus back was also the one that deleted the function under test, so
no appending trial could ever be observed; see `hardware-matrix.md`.

`republishIntended` makes no journal write: the phase stays `published`, the
recipe stays the restore target, and because the record already names the
function a crash either side of the call still restores correctly. If healing
succeeds without a re-publication, `acceptConfiguredOriginal` records
`awaitingVerification`. **Healing never confirms or clears the journal**; that
needs the host's external proof.

**The renewable lease.** A publication's lease is granted in quanta of 30 s and
`renew-lease` moves the deadline forward, never past a total cap of 180 s per
publication. The cap is enforced in the coordinator, not the journal, because
the journal would need a new schema field for the grant time and host tools
parse that record; the anchor lives in broker memory only, so a restarted broker
cannot renew and the journaled deadline is what applies. Renewal is refused once
a lease has expired - a dead lease is not revivable, because the watchdog may
already be restoring it. The host drives it every 10 s, giving three attempts
per quantum, and renews immediately before `heal` because the broker is
single-threaded and cannot answer while it heals.

Build: `docs/plans/ipad-port/scripts/ipad-hardware/build-u2-noop-trial-binary.py --v12-learned-profile`
for the conservative rollback artifact, which has neither `publish-hid` nor
`renew-lease` compiled in, or `--v17-renewable-lease` for the current additive
build.

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

The continuing re-publication reuses the same two mechanisms in one call. It
asks the shim to strip the appended name and then append it again, so the
clone it publishes is the journaled original plus that one function; and because
an earlier heal round may already have restored the stock description, it
accepts both live shapes — name still present and stripped, or already absent
and simply appended. Any other difference from the original is still refused.
Trying the stripping form first is safe because every refusal it can raise is
decided while comparing the in-process clone, before `SetDescription` is
reached, so a rejected first attempt has written neither controller nor bus.

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
