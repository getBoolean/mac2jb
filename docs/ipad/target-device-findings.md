# iPad target findings

Current state and the durable findings for the iPad port's hardware work. Dated investigation logs were condensed on 2026-10-31; the full history is in git (`git log -- docs/ipad`).

## Current state

*Single source of truth for what is true now. Replace this block (do not append below it) after every device action. The repository skill holds procedure only and never status.*

- **As of:** 2026-10-31, after the v12 broker trials and the script/doc cleanup.
- **Gates:** U1 passed. **U2 passed** (automatic USB recovery; see [hardware matrix](hardware-matrix.md)). **U3 (HID canary) is next.**
- **USB:** healthy. The strict external check (`host/check-u2-trial-current.py --expect-journal=absent`) passes. Pinned Wi-Fi SSH healthy.
- **On device:** only the v12 broker `dev.mac2jb.u2.nooptrialv12` (binary `/var/jb/usr/libexec/.mac2jb-u2-noop-trial-96296113`, JetsamMemoryLimit 96) and its state directory `/var/jb/var/lib/mac2jb-u2-native/` (lock, socket, learned `device-profile.json`), the retained v11 binary `.mac2jb-u2-noop-trial-8fdb044f` (no plist), and the SSH `authorized_keys`. No active journal. Details: [device inventory](device-cleanup-ledger.md).
- **Product goal:** every jailbroken or TrollStore-capable USB-C iPad and iPhone; Lightning is a stretch goal. This iPad is the reference device; other devices learn their own profile.
- **Next step:** U3 HID canary on top of the v12 broker. Tuning follow-up: one v12 normal trial used all 5 re-publications.

## Reference device

M2 iPad Pro 12.9-inch (6th generation), `iPad14,5` / `T8112`, iPadOS 17.0 (`21A329`), Dopamine 3 rootless with TrollStore. USB device controller `AppleT8112USBXDCI`. Stock live USB description: 16 fields, 9 configurations, 16 functions, five host-visible configurations, USB IDs `0x05ac/0x12ab`, `bcdUSB 0x0310`, `MPS0 9`. Pinned Wi-Fi SSH works as `mobile` and `root` while the iPad is attached to the Mac or the Switch.

## What is proven

- **U1 (read-only inventory and authorization):** passed for R1–R3 and the scoped R14 decision; summary in the [hardware matrix](hardware-matrix.md).
- **U2 (restoration journal and watchdog):** the broker journals the live description, publishes through the controller clone, and recovers automatically. 5/5 v11 trials (normal ×3, worker-kill, watchdog-kill) and 2/2 v12 trials (normal, watchdog-kill) lost Mac USB on publication and recovered without owner action in 29–72 s. Each then passed the strict external check and was confirmed.
- **Mechanism:** see [automatic recovery](usb-auto-recovery.md).

## Durable lessons

- **Off bus after a swap.** After `SetDescription` the controller goes on bus only when all functions re-register, and each swap leaves a random one or two unregistered. Nothing else recovers it: re-sending, `GoOffAndOnBus`, `ForceOffBus`, replugging, a different host. Bounded re-publication plus restarting the user-space owner of the remaining function does.
- **API success is not recovery.** Only external Mac checks prove USB came back.
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
- **Sandbox false negatives:** a restricted sandbox can falsely report SSH, usbmux or local-network failure. Rerun with normal permissions before diagnosing the iPad.
- **USB data vs power:** charging or a raw USB node does not prove a USB data connection.

## Evidence locations (private, ignored `build/ipad-hardware/`)

- Trials: `u2-trials/run-v11-*`, `u2-trials/run-v12-*`, and earlier `run-*`. Each holds the precheck, client output, lifecycle, heal status, strict postcheck, confirmation and syslog.
- Strict-check baseline: `u2-v9-trial-baseline/` (manifest SHA-256 `30693c83…18de`). The stock live reference is `u2-v4-repeat-baseline/`.
- Restore kits (byte copies of every on-device U2 file, journals, SSH files and sources): `u2-wifi-restore-kit/<ns>/`.
- Census and diagnostics: `u2-function-census/`. U1 reports and attestations: the remaining `build/ipad-hardware/` directories.
