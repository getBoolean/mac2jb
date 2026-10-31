# iPad target findings

Current state and the durable findings for the iPad port's hardware work. Dated investigation logs were condensed on 2026-10-31; the full history is in git (`git log -- docs/ipad`).

## Current state

*Single source of truth for what is true now. Replace this block (do not append below it) after every device action. The repository skill holds procedure only and never status.*

- **As of:** 2026-10-31, after the first device trial of a changed USB description.
- **Gates:** U1 passed. U2 passed. **U3 in progress:** a changed description recovers automatically on this device; no HID interface has been configured, opened or typed yet.
- **USB:** healthy. Strict external check passes with no journal. Pinned Wi-Fi SSH healthy.
- **Last trial:** published the stock description plus one appended function with nothing configuring it. Mac USB dropped and returned with no owner action in 51 s after three bounded re-publications and no owner restarts; the strict check passed, the journal was confirmed on that check's output and cleared, and the restored description carries no appended function. Evidence under the ignored `build/ipad-hardware/u2-trials/run-v13-normal-publish-hid-…/`.
- **On device:** the appending-capable broker `dev.mac2jb.u2.additivev13` (binary `.mac2jb-u2-noop-trial-71cf7b63`) is the only broker with a plist, loaded and answering. Its state directory holds the lock, socket and the learned `device-profile.json`, still schema 2 with an empty added-function section and 16 functions. The keyboard canary is staged at `.mac2jb-u3-hid-canary-53c00afe` (root, 0755) and has never been run. The earlier broker binaries `.mac2jb-u2-noop-trial-96296113` and `.mac2jb-u2-noop-trial-8fdb044f` are retained with no plist as rollback targets. No active journal. Details: [device inventory](device-cleanup-ledger.md).
- **Product goal:** every jailbroken or TrollStore-capable USB-C iPad and iPhone; Lightning is a stretch goal. This iPad is the reference device; other devices learn their own profile.
- **Next step:** the next device gate — publish, then match the appended function's interface and open its user client with the interface-class entitlement only, recording the raw result at each step. If no matching service appears or the open is denied, that is the plan's stop condition and the exclusive-HID fallback becomes the question.

## Reference device

M2 iPad Pro 12.9-inch (6th generation), `iPad14,5` / `T8112`, iPadOS 17.0 (`21A329`), Dopamine 3 rootless with TrollStore. USB device controller `AppleT8112USBXDCI`. Stock live USB description: 16 fields, 9 configurations, 16 functions, five host-visible configurations, USB IDs `0x05ac/0x12ab`, `bcdUSB 0x0310`, `MPS0 9`. Pinned Wi-Fi SSH works as `mobile` and `root` while the iPad is attached to the Mac or the Switch.

## What is proven

- **U1 (read-only inventory and authorization):** passed for R1–R3 and the scoped R14 decision; summary in the [hardware matrix](hardware-matrix.md).
- **U2 (restoration journal and watchdog):** the broker journals the live description, publishes through the controller clone, and recovers automatically. 5/5 v11 trials (normal ×3, worker-kill, watchdog-kill) and 2/2 v12 trials (normal, watchdog-kill) lost Mac USB on publication and recovered without owner action in 29–72 s. Each then passed the strict external check and was confirmed.
- **Mechanism:** see [automatic recovery](usb-auto-recovery.md).

## Durable lessons

- **Off bus after a swap.** After `SetDescription` the controller goes on bus only when all functions re-register, and each swap leaves a random one or two unregistered. Nothing else recovers it: re-sending, `GoOffAndOnBus`, `ForceOffBus`, replugging, a different host. Bounded re-publication plus restarting the user-space owner of the remaining function does.
- **API success is not recovery.** Only external Mac checks prove USB came back.
- **An observer bounded by the lease cannot see a published function on the bus.** The device takes 29-72 s to return to the bus after a description change, the lease caps at 30 s, and the healer's remedy re-publishes the journaled original, which removes anything appended. Any gate that needs to observe a changed description on the bus needs a renewable lease and a heal path that restores the intended description, or it measures a restored stock device and reports a confident falsehood.
- **Refuted causes, not to be re-investigated:**
  - a speed mismatch (`BcdUSBVersion/MPS0 528/64` is just the disconnected default);
  - a lost `ptpd` launch event (`ptpd` attaches, then exits when no host is connected);
  - wired-accessory authorization (the fields are identical when healthy and failed);
  - Type-C attach or power;
  - lock state.
- **iOS behaviours to work around:**
  - The broker gets the default 18 MB jetsam limit, and jailbreak tweak injection (ElleKit, Choicy) adds to its memory, so the plist sets `JetsamMemoryLimit`.
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
