# iPad target findings

Current state and the durable findings for the iPad port's hardware work. Dated investigation logs were condensed on 2026-10-31; the full history is in git (`git log -- docs/ipad`).

## Current state

*Single source of truth for what is true now. Replace this block (do not append below it) after every device action. The repository skill holds procedure only and never status.*

- **As of:** 2026-10-31, after the first trial of the renewable-lease build (v17).
- **Gates:** U1 passed. U2 passed. **U3 in progress:** the device side works end to end, but no host has yet been observed enumerating the appended function. Every host-side result so far is **void, not negative** - no trial has been positioned to see one.
- **USB:** healthy. `usbmux=one`, `interfaces=equal`, `scalars=equal`, packet reply, live description back to the original. Pinned Wi-Fi SSH healthy.
- **Journal: RETAINED at `awaitingVerification`** (sha256 `2e686910b5093cde4c1275d541e7986d9d308de6d3309871cb67329a96f42cc5`). The strict external check passes, but `confirm-u2-after-heal-wifi.py` refuses because the function census is 43 nodes against the healthy reference's 44: one `AppleUSBDeviceAudioController` under `USBAudio2StreamIN` never re-matched. `launchctl kickstart -k system/com.apple.audiomxd` did **not** restore it. Corrected: the two retained degraded censuses were both captured while the controller read `DeviceState=disconnected OnBus=no SelectedConfiguration=0`, so they do **not** show a configured device recovering, and nothing retained does. The 43-node state on a *configured* controller is genuinely anomalous, not a known transient. The 44-node reference is also not a boot invariant - the same classes appear at 6, 5 and 3 across retained captures of a device whose description never changed - so it is valid only for a configured, host-attached controller. **A trial cannot start until this clears, because it requires `journal=absent`.** A reboot is the remaining remedy and needs the owner's authorisation.
- **Last trial:** v17, mode full, aborted. The publication succeeded and `Mac2jbCanary` registered with the controller, but the **lease expired before the bus cycle**: the broker took `recoverIfLeaseExpired()` and auto-healed, which restored the original and moved the journal out of `published`, so `cycle-bus` was refused. Host-side lease renewal is driven every 10 s and passes the offline fixture against the real broker socket, so why it failed on device is open. Evidence under the ignored `build/ipad-hardware/u2-trials/hid-v17-1793488540808803000-52a3bfa7/` - syslog only, because that build wrote its renewal log on the success path alone (since fixed).
- **On device:** the renewable-lease broker `dev.mac2jb.u2.additivev17` (binary `.mac2jb-u2-noop-trial-2d1c7582`) is the only broker with a plist, loaded and answering; it adds `renew-lease` and an additive heal. The canary is staged at `.mac2jb-u3-hid-canary-1be9112f` (root 0755), the build whose wait polls the pipe size instead of writing reports. Earlier broker binaries (`11f63007`, `bbc4946f`, `f8e17bbd`, `71cf7b63`, `96296113`, `8fdb044f`) and the canary `18c2c760` are retained with no plist as rollback targets. Details: [device inventory](device-cleanup-ledger.md).
- **Product goal:** every jailbroken or TrollStore-capable USB-C iPad and iPhone; Lightning is a stretch goal. This iPad is the reference device; other devices learn their own profile.
- **Next step:** clear the journal (owner-authorised reboot, then confirm), then re-run U3.9 with the canary rebuilt at `c9f95bb9` staged. The renewal fault is understood and fixed: the worker, not the broker's lease, was expiring. Corrected from the earlier record: the lease did **not** expire, and `republishIntended`'s configured guard was **not** what refused the preserving heal - the controller was off bus, so that guard passed, and the phase check failed because the worker's death had already moved the journal. The healer never republishes over a working connection anyway, so that guard stays.

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
