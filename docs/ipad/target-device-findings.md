# iPad target findings

Current state and the durable findings for the iPad port's hardware work. Dated investigation logs were condensed on 2026-10-31; the full history is in git (`git log -- docs/ipad`).

## Current state

*Single source of truth for what is true now. Replace this block (do not append below it) after every device action. The repository skill holds procedure only and never status.*

- **As of:** 2026-11-01, after a trial whose bus cycle left USB down and whose recovery path is exhausted.
- **Gates:** U1 passed. U2 passed. **U3 in progress and now in doubt** - see the bus-stability lesson below.
- **USB: DOWN and not recoverable from the Mac.** `usbmux count=0`, `raw-ipad=no`, controller `DeviceState=disconnected OnBus=no SelectedConfiguration=0`. **Pinned Wi-Fi SSH is healthy as `mobile` and `root`**, so the device is reachable and nothing is at risk; only the USB data path is gone.
- **Recovery already attempted, all of it:** one `recover-u2-over-wifi.py` (restore issued, `api=success`, `mac-arrival=no`); `recover-u2-until-registered-wifi.py`, four attempts, each reporting `registered=16/16 missing=none usb=absent`; `recover-u2-restart-function-owner-wifi.py` for `com.apple.audiomxd` (which newly registered `Valeria`) and for `com.apple.accessoryd`; then all three allowlisted owners kickstarted again in the **`user/501`** domain, which is where they actually live - the tool uses `system/`, which launchd warns about and which is why an earlier attempt of mine was a no-op. Also ~4 minutes of simply waiting. The controller never came back on bus. Per `usb-recovery.md` step 4 this is the owner-restart point.
- **Journal: retained at `awaitingVerification`** (sha256 `89f046eb713ef39ab7663becc67a766b13fe67630f6387b28b7c934b72bd829e`). After a reboot it becomes unresolvable and must be retired with `host/archive-u2-old-boot-journal-wifi.py`, which exists for exactly this.
- **Measured while USB was down: 4 of 16 nubs driverless** - `PTP`, `IapOverUsbHid`, `USBAudio2Control`, `USBAudio2StreamOUT`; the other 12 served. `PTP` being driverless is expected in this state, because `ptpd` attaches and then exits when no host is connected (see the refuted-causes list), and the audio and iAP drivers plausibly behave the same way. **So "driverless" partly reflects the absence of a host rather than a fault, which makes the healer's unserved-function signal circular while USB is down:** the controller will not go on bus until its functions are served, and some are not served until a host is present. Do not read a driverless count taken off bus as the cause of being off bus.
- **The healer's own view disagrees with the census, and that is the clue:** every attempt reports `registered=16/16 missing=none` from the registry while the broker's heal reports functions missing. The nubs exist; some have no driver attached. The controller goes on bus only when every function is *served*, so an orphaned nub holds the whole bus down - the same fault class as the single `AppleUSBDeviceAudioController` orphan, and a publication is the only known lever for it.
- **On device:** broker `dev.mac2jb.u2.additivev19` (binary `.mac2jb-u2-noop-trial-eddb506f`), 600 s publication cap, tweak injection off by default, jetsam limit raised to 96 MB at runtime (`device/u3-set-broker-memory-limit.py`, needed after every broker restart). Canary `.mac2jb-u3-hid-canary-0b886c24`. Details: [device inventory](device-cleanup-ledger.md).
- **Product goal:** every jailbroken or TrollStore-capable USB-C iPad and iPhone; Lightning is a stretch goal. This iPad is the reference device.
- **Next step:** owner-assisted reboot and re-jailbreak, then retire the old-boot journal, re-capture the baseline, and re-pin the strict check. Before another additive trial, settle whether the controller can hold a stable bus presence at all with a 17th function - two trials showed it arriving transiently (328 s then 45 ms; 531 s then 39 ms) and absent at the window end, but in both the runner was killing the lease holder, so that evidence is not safe.

## Reference device

M2 iPad Pro 12.9-inch (6th generation), `iPad14,5` / `T8112`, iPadOS 17.0 (`21A329`), Dopamine 3 rootless with TrollStore. USB device controller `AppleT8112USBXDCI`. Stock live USB description: 16 fields, 9 configurations, 16 functions, five host-visible configurations, USB IDs `0x05ac/0x12ab`, `bcdUSB 0x0310`, `MPS0 9`. Pinned Wi-Fi SSH works as `mobile` and `root` while the iPad is attached to the Mac or the Switch.

## What is proven

- **U1 (read-only inventory and authorization):** passed for R1–R3 and the scoped R14 decision; summary in the [hardware matrix](hardware-matrix.md).
- **U2 (restoration journal and watchdog):** the broker journals the live description, publishes through the controller clone, and recovers automatically. 5/5 v11 trials (normal ×3, worker-kill, watchdog-kill) and 2/2 v12 trials (normal, watchdog-kill) lost Mac USB on publication and recovered without owner action in 29–72 s. Each then passed the strict external check and was confirmed.
- **Mechanism:** see [automatic recovery](usb-auto-recovery.md).

## Durable lessons

- **Off bus after a swap.** After `SetDescription` the controller goes on bus only when all functions re-register, and each swap leaves a random one or two unregistered. Nothing else recovers it: re-sending, `GoOffAndOnBus`, `ForceOffBus`, replugging, a different host. Bounded re-publication plus restarting the user-space owner of the remaining function does.
- **API success is not recovery.** Only external Mac checks prove USB came back.
- **A lease is only as long as its shortest holder, and renewal must reach every one of them.** The broker's lease is renewable to a 180 s cap, but the worker holding it capped its *own* clock at 15 s with a `min()` and the host never passed a budget, so the worker expired first on every run. Its exit closes the lease socket, and a closed worker socket is what makes the broker restore - so broker-side renewal working perfectly changed nothing. When a window has to outlast the 29-72 s bus return, the worker's lease, its enumeration wait, its interface wait and the host's report deadline all have to move together; any one left at the old ceiling ends the window by itself. A test asserting only "the wait cannot outlive the lease" is satisfied by exactly this bug.
- **A bus cycle costs ~328 s off bus, not 29-72 s, and the device flaps afterwards.** Measured 2026-11-01 from the lifecycle monitor on a trial that cycled the bus after an additive publication: `terminated` at 1.15 s, `arrived` at **328.22 s**, `terminated` again 45 ms later, `arrived` at 328.45 s, then `missing-at-window-end` at 540 s. The 29-72 s figure is for a plain description change; an explicit `GoOffAndOnBus` with an extra function present is four to ten times worse, because the controller returns to the bus only when *all* functions re-register and each attempt loses one or two to the race, so the healer republishes and each republication takes it off bus again. Size every bound from 328 s, not from 72 s, and expect the device to come and go for minutes afterwards.
- **An observer bounded by the lease cannot see a published function on the bus.** The device takes 29-72 s to return to the bus after a description change, the lease caps at 30 s, and the healer's remedy re-publishes the journaled original, which removes anything appended. Any gate that needs to observe a changed description on the bus needs a renewable lease and a heal path that restores the intended description, or it measures a restored stock device and reports a confident falsehood.
- **Refuted causes, not to be re-investigated:**
  - a speed mismatch (`BcdUSBVersion/MPS0 528/64` is just the disconnected default);
  - a lost `ptpd` launch event (`ptpd` attaches, then exits when no host is connected);
  - wired-accessory authorization (the fields are identical when healthy and failed);
  - Type-C attach or power;
  - lock state.
- **iOS behaviours to work around:**
  - **The broker is jetsam-killed, and the plist cannot stop it.** Measured 2026-11-01 on the running v17 broker: `phys_footprint = 6.19 MB` against `jetsam memory limit (active, soft) = 6 MB` and `(inactive, hard) = 6 MB`, with `last exit reason = JETSAM_REASON_MEMORY_PERPROCESSLIMIT` and `runs = 3`. It sits *over* its own ceiling, so it dies whenever the system reclaims and certainly when a publication allocates. The job plist sets `JetsamProperties = {JetsamMemoryLimit: 96, JetsamPriority: -49}`, and launchd ignores both: it reports priority 40 and the generic `daemon` category limits. iOS takes a daemon's jetsam properties from its own configuration keyed by label, so a third-party job plist cannot raise them - the earlier note that "the plist sets JetsamMemoryLimit" was wrong. 37 tweak dylibs are injected through ElleKit, and that was the whole of it: setting `_MSSafeMode` and `_SafeMode` in the job's own environment took the footprint from **6.22 MB to 1.41 MB** against the same 6 MB limit, with over 4 MB of headroom and no kills. No entitlement and no system change was needed - only this one job's plist, reversibly (`device/u3-set-broker-injection.py --apply|--revert`). Keep injection off for any broker that publishes; a broker with it on cannot complete a publication reliably.
    - Consequence for every earlier result: a trial that lost the broker mid-publication looks exactly like a broker that refused a command. An empty reply, rather than `ERR rejected`, is the signature - the process was gone. Check `launchctl print`'s run count and last exit reason before diagnosing anything else.
  - iOS launch constraints SIGKILL Apple daemons started outside launchd, so `ptpd` can't be run by hand.
  - The live description keeps `AllowMultipleCreates=true` after any publication (an accepted deviation).
- **Debugging without USB:** the iPad's syslog streams over Wi-Fi even while USB is off bus (`idevicesyslog -n`). The recovery tools record it, reconnecting when the stream drops.
  - Measured 2026-10-31: on two HID trials the stream stopped about two seconds after publication with no reconnect marker, losing the bus cycle, the heal re-publications and the restore. The reconnect loop is not reliable as written, so treat a short syslog as a capture gap rather than device silence.
- **Sandbox false negatives:** a restricted sandbox can falsely report SSH, usbmux or local-network failure. Rerun with normal permissions before diagnosing the iPad.
- **USB data vs power:** charging or a raw USB node does not prove a USB data connection.

## Evidence locations (private, ignored `build/ipad-hardware/`)

- Trials: `u2-trials/run-v11-*`, `u2-trials/run-v12-*`, and earlier `run-*`. Each holds the precheck, client output, lifecycle, heal status, strict postcheck, confirmation and syslog.
- Strict-check baseline: `u2-v9-trial-baseline/` (manifest SHA-256 `30693c83…18de`). The stock live reference is `u2-v4-repeat-baseline/`.
- Restore kits (byte copies of every on-device U2 file, journals, SSH files and sources): `u2-wifi-restore-kit/<ns>/`.
- Census and diagnostics: `u2-function-census/`. U1 reports and attestations: the remaining `build/ipad-hardware/` directories.
