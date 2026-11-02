# iPad target findings

Current state and the durable findings for the iPad port's hardware work. Dated investigation logs were condensed on 2026-10-31; the full history is in git (`git log -- docs/ipad`).

## Current state

*Single source of truth for what is true now. Replace this block (do not append below it) after every device action. The repository skill holds procedure only and never status.*

- **As of:** 2026-11-01, after the v20 boot-session cut-over (owner reboot). **Device is clean and trial-ready on the fixed broker; the `boot_session` bug is fixed and proven on-device.**
- **Gates:** U1 passed. U2 passed. **U3 R9 (open + full operation matrix) PASSED device-side.** The one open U3 question is unchanged: the host does not enumerate the 17-function composite (see "Composite enumeration" below). The HID canary is not re-run in this cut-over.
- **Device:** rebooted and re-jailbroken. Live boot token `2b869028…` (was `81aaff35…`-class before; tv_sec changed, reboot confirmed). SSH and network pairing healthy. USB up; the bus carries the restored stock original (6 host-visible interfaces in config 5, **no HID interface**).
- **Broker:** swapped **v19 → v20** (`dev.mac2jb.u2.additivev20`, binary `.mac2jb-u2-noop-trial-df0ac6a4`). v20 is v19's behaviour rebuilt from the tv_sec-only source. Stable: `pid=1106 runs=1 last-exit=none footprint=3.17MB`, jetsam raised to **96 MB** at runtime (the injection tool still prints the static 6 MB plist field), injection **disabled** (safe-mode present) — publication-ready. v19's binary/plist retired by the swap.
- **Journal:** the previous boot's `awaitingVerification` journal was archived (`restore-journal.oldboot-981dba20`) and the active name unlinked; **journal=absent**. Nothing was confirmed or restored — a reboot makes a USB description moot, so the bytes were retired, not resolved.
- **Baseline + strict check:** old baseline retired to `u2-v9-trial-baseline.oldboot-970d8d30`; fresh baseline captured this boot, manifest `c545419e…`, pinned in `host/check-u2-trial-current.py`. The strict external check now **passes clean**: `boot=same live=original configs=5 interfaces=equal scalars=equal network=equal usbmux=one pairing=valid journal=absent`.
- **`boot_session` bug — FIXED and deployed.** `sha256(kern.boottime)` hashed the whole `timeval` including `tv_usec`, which time-sync rewrites without a reboot (proven earlier: tv_sec fixed, tv_usec drifted). Now derived from **tv_sec only** (first 8 bytes) at all four sites and in the deployed v20 broker (commits `147bb66`, `15c4699`). Proof it works end-to-end: the strict check reports `boot=same` where the drifted derivation reported `reference boot changed`. Regression test `tests/test-u2-boot-session-derivation.py`.
- **Composite enumeration (unchanged open question):** in the configure-only v19 trial the device-side HID selector matrix all returned `0x00000000` (the private HID ABI works as the macOS reference predicted), **but the Mac enumerated no device at all** while the 17-function composite was live (`host enumerates no device`, every control-request `not-observed`) — reads as the host rejecting the whole composite config descriptor, not a per-interface fault. Offline parse of the captured `raw-configs.bin` cleanly yields only config 1 (3 endpoints); the "config 5 = 10 endpoints" figure came from `host-interfaces.json`, so the endpoint-exhaustion/collision hypothesis is **plausible but unconfirmed** and needs a live config-descriptor read during a composite hold (now unblocked). Evidence under ignored `build/ipad-hardware/u2-trials/hid-v19-…`.
- **On device:** broker `dev.mac2jb.u2.additivev20`. Canary `.mac2jb-u3-hid-canary-0b886c24` staged (sha256 `0b886c24…`), previously exercised open-only and configure-only. Details: [device inventory](device-cleanup-ledger.md).
- **Product goal:** every jailbroken or TrollStore-capable USB-C iPad and iPhone; Lightning is a stretch goal. This iPad is the reference device.
- **Next step (decision pending):** the device is trial-ready. Choose between (1) investigating why the host rejects the composite config descriptor — a live, read-only config-descriptor capture during a composite hold to test the endpoint hypothesis — versus (2) pivoting to the exclusive-HID fallback (parent plan U4), which publishes only the HID function and so presents a single-interface descriptor the host is far more likely to enumerate.

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
