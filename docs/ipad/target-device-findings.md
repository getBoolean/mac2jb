# iPad target findings

Current state and the durable findings for the iPad port's hardware work. Dated investigation logs were condensed on 2026-10-31; the full history is in git (`git log -- docs/ipad`).

## Current state

*Single source of truth for what is true now. Replace this block (do not append below it) after every device action. The repository skill holds procedure only and never status.*

- **Project disposition:** Closed by the owner as a failed experiment on 2026-11-02. Reopened by the owner on 2026-11-17 for direct USB keyboard work, with each device action authorized individually.
- **Switch 2 and the bus cycle (2026-11-17).** The owner's third standalone run (23:23) on the Switch 2: the Switch enumerated the keyboard after the publication (canary `host=enumerated max-packet=8`), then the command's explicit `cycle-bus` (GoOffAndOnBus) left the controller at `HardwareLinkState Compliance`, `SelectedConfiguration 0`; every write returned `0xE0000001` for 60 s and nothing was typed. The stock restore could not re-enumerate either until the owner replugged the cable (then `U0`, SuperSpeed+, configuration 1; restore verified and cleared on the iPad). Confounded: the owner unplugged and replugged the cable during this run to see whether the Switch would read a keyboard, so the failed writes and the Compliance state may come from that replug rather than from the cycle. The run therefore does not establish that the cycle breaks the Switch link. `ipad2jb` now skips the cycle by default anyway (`--cycle` restores it), because it should be unnecessary: the keyboard function registers only after the canary configures it, so the controller is not on bus before the host can see a complete keyboard.
- **As of 2026-11-18: one self-contained binary.** `ios/ipad2jb/ipad2jb.c` (about 385 lines) replaces the broker, canary and Python command: it saves the stock description to `/var/jb/var/lib/ipad2jb/stock-description.plist`, publishes the single `Standard Keyboard` configuration built from the host-selected one, configures the Keyboard function (class 3/1/1, HID and report descriptors, 8-byte interrupt-IN pipe, buffer, commit), completes every class request with selector 9, waits for the host to poll, settles 3 s, types with 30 ms pacing, and republishes the saved description (up to four attempts, waiting for all functions and a host-selected configuration). An interrupted run is restored by the next run. Entitlements: `com.apple.private.usbdevice.setdescription`, the `IOUSBDeviceInterfaceUserClient` user-client exception, `platform-application`. Owner-confirmed on the Switch 2 (typed `ipad2jb`); a second run after removing the broker stack also exited 0. The broker, canary and their state are no longer on the iPad.
- **As of 2026-11-17: the iPad types on the Switch 2 (owner-observed).** `ipad2jb` (run over SSH, cable on the Switch 2, configuration 1, `[AppleUSBMux, Keyboard]`, no bus cycle) typed `ipad2jb`; the owner saw it on the Switch and the canary reported `14 of 14` reports collected and `stop=completed`, followed by a restore verified on the iPad. The fix was answering class requests: canary `fb69bc5c` serves them through a notification port on a dispatch queue and completes each with selector 9 (`{1, length, buffer address, 0, token}`, as `vendor/libusbd/src/plat/macos/impl.c` does), instead of registering a bare port and letting the kernel stall them. The Switch sent SET_PROTOCOL to boot protocol (`21 0b 0000`), SET_IDLE (`21 0a`), then about 550 SET_REPORT LED output reports (`21 09 0200 0001`); stalled, it selected the configuration but never polled the keyboard, while macOS tolerated the stalls.
- **Switch 2 selects but never polls the keyboard (owner runs 23:29 and 23:32, cable untouched).** With `[AppleUSBMux, Keyboard]` as the sole configuration, the Switch 2 selected it (canary `max-packet=8`) but never polled the interrupt endpoint: 240 writes timed out (`0xE00002D6`) in 60 s, both without the bus cycle and with `--cycle` (which completed with the link back at `U0`). Restores were verified on the iPad both times. macOS polled the same configuration after a re-enumeration. Candidate causes: the Switch not handling a composite device whose interface 0 is vendor-specific, or the Switch abandoning the keyboard when the iPad stalls SET_IDLE/SET_PROTOCOL (the canary does not service class requests). `ipad2jb --keyboard-only` publishes the configuration with the Keyboard interface alone to separate the two.
- **Standalone command (2026-11-17).** `sudo ipad2jb [TEXT]` (`/var/jb/usr/bin/ipad2jb`, source `device/ipad2jb.py`) runs the whole sequence on the iPad with no Mac and confirms the journal after an on-device check (owner-approved for standalone use). The owner's first two runs on the Switch 2 failed for three fixed reasons: (1) the command closed the canary's input before `communicate()`, which on the iPad's Python 3.9.9 raises "I/O operation on closed file"; the command died and the canary was killed by the broken output pipe before typing; (2) it did not send `heal` for a `recoveryRequired` journal; (3) the broker's restore verifier required exact equality with the journaled description, but the controller rewrites `BcdUSBVersion`/`MPS0` from the link speed (journaled 528/64 while the Switch link reported USB 2; live 784/9 after SuperSpeed+), so it rejected a correct restore. Broker v23 (`/var/jb/usr/libexec/ipad2jb/usb-broker`, label `dev.ipad2jb.usbbroker`) accepts those two fields when they equal the learned healthy pair; it was installed with `--ipad-check` (iPad-side USB checks instead of Mac USB) and cleared the stuck journal on the iPad. Runs save their log to `/var/jb/var/log/ipad2jb/last-run.txt`. The Switch 2 selects configuration 1 (the Mac selects 5). Only `ipad2jb/usb-broker`, `ipad2jb/keyboard-canary` and the command remain on the iPad.
- **As of 2026-11-17: the iPad is a working USB keyboard to the Mac, and the runner's HID proof passes (trial 11).** Trial 11 (`hid-v22-1794976600626372000-6509561e`, broker v22 `publish-sole-configuration`, canary `0b8fdd15` with `--hold-until-released yes`, signed listen-only reader) reported `enumeration=pass`, `reports=reports-recorded` (the exact 12-report `MAC2JB` sequence after 84 neutral reports), `publication-after-read=live` and `hid-proof=pass`. The runner still exits 1 because the post-restore strict check requires the iPad in the Mac's `usbmuxd` network list, which has been missing since a Mac restart (pinned Wi-Fi SSH works; the owner re-enabled "Show this iPad when on Wi-Fi" and replugged); the restore itself was confirmed by `confirm-u2-after-heal-wifi.py`. Trial 8 (owner saw `MAC2JB` typed in TextEdit): In trial 8 (`hid-v22-1794974364635909000-94e8f298`, broker v22 `publish-sole-configuration`, canary `478ac8e0`, `--shared-reader=yes`) the owner saw `MAC2JB` typed into a focused TextEdit window. Before it the owner added Mac privacy approvals: Input Monitoring for the rebuilt reader binary and an approval step reported only as "added" (possibly the accessory approval). Trials 3-7 delivered the same reports to the Mac but no text appeared; the trial-7 kernel log shows macOS's external-HID restriction (`HIDRMDeviceState: Unknown`) at the moment of typing (see below). The listen-only reader recorded 12 reports, all neutral, because its report cap (12) filled with the canary's settle-period neutral reports before the typing; the runner therefore reports `hid-proof=fail`. Fixed afterwards: the reader now counts all-zero reports before the first key press (`leading-neutral=N`) instead of recording them, and keeps everything from the first key press on. The capture wrapper now signs the reader with the Mac's Apple Development identity and identifier `dev.mac2jb.u2-hid-report-reader` and installs it at the fixed path `build/ipad-hardware/u2-hid-report-reader-signed` (source digest in a `.source-sha256` stamp), so one Input Monitoring grant survives rebuilds; without an identity it falls back to the unsigned, digest-named binary. Earlier evidence (trials 3-4): Trial 3 (`hid-v22-1794959186135659000-5a00a65a`) used broker v22 `publish-sole-configuration 5 AppleUSBMux,Keyboard` and canary `368617ca`. The canary delivered all 12 boot-keyboard reports plus the neutral report (`write result=0 transferred=8` each; `reports written=12 stop=completed neutral=delivered`). An interrupt-IN transfer completes only when the host polls it. Independently, the Mac unified log at 17:46:52.364 records `WindowServer … Service added: IOHIDService name:AppleUserHIDEventDriver primaryUsagePage:0x1 primaryUsage:0x6 transport:USB` with `vendorID 1452 productID 4779` (the iPad, 0x05ac/0x12ab), and macOS attached `IOHIDKeyboardFilter` to it. The service was removed at 17:46:58.148 by the stock restore. The Mac report reader was refused Input Monitoring (`permission-denied`, not seized), so the canary text `MAC2JB` was delivered to the focused Mac window as real keystrokes; the runner's `hid-proof` is therefore `void` by its own rule, not a failure of enumeration. USB restored with no reboot; the restore was confirmed only on `confirm-u2-after-heal-wifi.py` evidence; journal absent; device clean on stock with broker v22 idle.
- **Trial 5 and runner timing (2026-11-17).** Trial 5 (`hid-v22-1794968354700670000-5b68aea0`, after a Mac restart) repeated the device result (12 reports and the neutral report delivered) and the reader's seize refusal. Its post-trial strict check then failed with `USB target absent or ambiguous on network`: Mac USB was healthy, but the Mac's `usbmuxd` stopped listing the iPad as a network (Wi-Fi sync) device, while pinned Wi-Fi SSH stayed up. The restore was confirmed with `confirm-u2-after-heal-wifi.py`, whose external checks do not use the network listing; journal absent. The strict check, and therefore the next trial's preflight, fails until the iPad reappears in `idevice_id -n`. Separately, about nine of each trial's ten minutes were the passive lifecycle monitor's fixed 600 s window. The monitor now stops on SIGTERM and still flushes every event and its summary (`stopReason`), and the runner signals it as soon as the trial body (which already waits for USB to return) ends; `--window-seconds` remains an optional cap.
- **Host-side capture of the typed sequence (trial 9, 2026-11-17).** With the signed listen-only reader (`--shared-reader=yes`), trial 9 (`hid-v22-1794975404029333000-b6b6e3bd`, canary `478ac8e0`) recorded exactly the canary's 12 reports, Shift+M, A, C, 2, Shift+J, Shift+B each followed by a release (`0200100000000000` ... `0200050000000000`), after `leading-neutral=84` settle-period reports, with no permission error. The runner still reports `hid-proof=void`: its descriptor capture runs after the report capture, by which time the canary had finished its 1 s post-typing hold and the publication was gone (`publication-not-live-after-read`); and the strict check fails on the missing network listing.
- **Event-driven hold and descriptor parsing (trial 10, 2026-11-17).** Canary `0b8fdd15` holds the keyboard after typing until the runner closes its input (`--hold-until-released yes`, cap 120 s); in trial 10 (`hid-v22-1794976149740351000-be9588b9`) the publication stayed live through the capture (`publication-after-read=live`) and the reader again recorded the 12-report sequence (`leading-neutral=86`). The capture then reported `report-descriptor-missing` because its ioreg patterns only accepted whitespace-indented lines; with several HID devices attached, macOS draws the iPad's node with `|` tree characters, so its properties were never parsed. The patterns now allow them, and the parser reads an attached USB keyboard's 59-byte descriptor. The strict check still fails on the missing network listing.
- **Why the typed text does not appear on the Mac (trials 6-7, 2026-11-17).** The owner saw no `MAC2JB` in a focused TextEdit window. The Mac kernel log for trial 7 (`hid-v22-1794972720052734000-548b7c6a`) shows the host side working up to input delivery: `AppleUserUSBHostHIDDevice` started (it logged the stalled SET_PROTOCOL `21 0b`), `AppleUserHIDEventDriver` parsed the report descriptor (`keyboard: 236`, `led: 3`) and identified `iPad usagePage: 1 usage: 6 vid: 1452 pid: 4779`. It also logged `HIDRM: External device detected, state = Unknown`, and then `HIDRMDeviceState: Unknown` about a dozen times between 21:32:26.49 and 26.84, the window in which the canary typed its 12 reports. WindowServer's `com.apple.HIDRMServiceFilter` (matching USB transport) failed to initialize for the device. The likely reading is that macOS's external-HID restriction (HIDRM) held back input from an unapproved external keyboard; this is inferred from the log, not from Apple documentation. Separately, the listen-only reader (`--shared-reader=yes`, binary `u2-hid-report-reader-8bd3b1473a5b362e`) opened the device but the kernel logged `u2-hid-report-re is not entitled for IOHIDLibUserClient keyboard access ... client not privileged`, so it received no reports: keyboard-report privilege is checked for the client binary itself, and the rebuilt binary has no Input Monitoring grant. The 3 s settle and pacing added for trial 6 were based on a timing hypothesis that the HIDRM evidence supersedes.
- **Why the 2026-11-02 trials failed (verified).** `IOUSBDeviceController::createUSBDevice` (IOUSBDeviceFamily, 21A329) inserts one function nub per interface name from **every** configuration into a pending `OSDictionary` at controller `+0x168`; `gated_registerFunction` removes each registering name and calls `startUSBStack` only when the dictionary is empty. In every v13-v21 HID trial the trial function registered but at least one stock function from another configuration (`IapOverUsbHid`, `Valeria`, `USBAudio2*`) did not, so no `startUSBStack` was logged while a trial description was live. No kernel driver match is needed for a userspace-backed function: `Keyboard` registered from the canary's user client every time.
- **Working recipe (durable).** (1) Publish a description with a single configuration in Apple's `standardKeyboard` shape (`{Description "Standard Keyboard", Interfaces [AppleUSBMux, Keyboard], DefaultConfiguration true}`, device scalars kept), so the controller waits only on `AppleUSBMux` and `Keyboard`; trial 1 showed `createUSBDevice: configuration: Standard Keyboard`, both registrations, `startUSBStack`, and `SetConfiguration 0 -> 1` within 0.3 s. (2) Keep the runner's post-commit bus cycle: the host must re-read the configuration after the canary sets class 3 and the HID descriptors. After it, the Mac sends SET_IDLE (`21 0a`) and SET_PROTOCOL (`21 0b 0001`), which the device stalls because the canary does not service class commands; macOS proceeds anyway. (3) Do not type until the host polls: the canary offers the all-zeros neutral report, retrying on timeout `0xE00002D6`, abort `0xE00002EB` and not-enumerated `0xE0000001` for up to 60 s, and types only after one is collected. Trial 1 typed immediately and timed out; trial 2 exited on the bus-cycle abort about 6 s before the Mac started polling.
- **Open items.** (a) Host capture: trial 4 (`hid-v22-1794962581077628000-7e4e05e8`, after the owner granted T3 Code Input Monitoring) repeated trial 3 on the device (12 reports and the neutral report delivered) and again ended `permission-denied`, so `MAC2JB` was typed into the focused Mac window a second time. Run afterwards from the same agent session with no keyboard published, the same reader binary passes `IOHIDCheckAccess` (granted) and `IOHIDManagerOpen` and reports `no-matching-device`, so the refusal is the exclusive `IOHIDDeviceOpen(kIOHIDOptionsTypeSeizeDevice)` on the keyboard. Seizing a keyboard on macOS generally needs root, which an Input Monitoring grant does not supply; this was not tested directly because the only keyboard available is the owner's. A seized capture needs the reader to run as root, or the test must accept shared (non-seized) recording with the keystrokes also reaching the focused window. The raw-descriptor helper also reported `unavailable` in all three runs; it runs after the publication ends, so the enumeration capture needs to run inside the publication window. (b) Service SET_IDLE/SET_PROTOCOL and GET_REPORT in the canary instead of stalling. (c) Other hosts (Switch 2, Windows/Linux, iPhone/iPad hosts) and other targets are untested. (d) The publication lasts only as long as the canary holds its lease; a persistent keyboard mode needs a long-lived worker and its own restore policy.
- **Next step (owner decision).** Choose how the host capture runs: as root (seized, nothing typed into apps) or shared with a scratch text window focused (recorded and typed). Either is one more authorized trial. The device result does not depend on it.
- **Superseded 2026-11-02 status (kept for history):** **Direct-HID path STOPPED. Userspace approach: failed (does not enumerate). Kernel-gadget route (R16): SOURCE-ONLY FAIL; stopped before device reads.** The candidate matrix found no mechanism that is simultaneously volatile, source-supported for same-boot removal by an independent surviving owner, capable of actual USB-function binding, and capable of later carrying caller-owned HID reports. The strongest retained stock candidate is `IapOverUsbHid` bound by `IOAccessoryPortUSB`, but no retained source exposes a caller-owned keyboard descriptor/report path. Catalogue addition lacks bounded removal evidence; public kernel-code precedents are target-specific or boot-image-based and stop short of a removable USB-function driver; a match-only patch supplies no function behavior. An independent read-only review reached the same verdict and identified no target read that could resolve those missing design properties. The next read-only target-profile gate therefore has no eligible candidate and does not run. No device action, kernel read/write, patch, apply/remove, recovery drill, or per-build kernel profile was performed. This is **not proof of impossibility**: future source or private implementation evidence can reopen the gate by satisfying the matrix's explicit conditions. 
- **Prior settled verdict (userspace approach): direct iPad HID via the private-API SetDescription + function + userspace user-client configuration did not enumerate in the five recorded trials on this controller.** Five trials (3× `Mac2jbCanary` composite/exclusive, 2× stock `Keyboard`) all failed to enumerate; the stock-name avenue is tested and behaves identically to the invented name. The stored-description restore recovered the device every time with no reboot.
- **Stock `Keyboard` trials (2026-11-02) — tested, does not change the outcome.** Published `config 5 = [AppleUSBMux, Keyboard]` (the interface list from the stock `standardKeyboard` profile) twice. The trial builder replaced the selected configuration’s Interfaces array inside the existing device description. Apple’s named profile defines a single default configuration. These runs establish the outcome for the edited configuration 5; they do not establish what loading the complete named profile would do. First run was confounded by the audio re-registration race (`heal-gave-up missing=USBAudio2Control,USBAudio2StreamOUT`; recovery via `recover-u2-over-wifi` restarted `audiomxd`, no reboot). The **clean retry** (`hid-v21-1793633727440254000-ce073524`) handled the race — `heal=healed owner-restarts=com.apple.audiomxd` — and the device **still did not enumerate** (`usb=absent`, `not-enumerated`). In both, `Keyboard` registered and the canary opened + configured it exactly as `Mac2jbCanary` (`open=0x0`, all ops `0x0`, `aborted-by=255`, `max-packet=0`). So a stock function name, configured by the canary as a bare userspace interface, is no different from an invented one. The only residual untested variant — publish `[AppleUSBMux, Keyboard]` **without** the canary opening it, to let a kernel keyboard driver (if one exists) bind it — is low value: no iOS kernel keyboard-gadget driver is known, and if one bound it, it would source its own reports, so we still could not inject `MAC2JB`.
- **Gates:** U1 passed. U2 passed. **U3 R9 (open + full operation matrix) PASSED device-side** (the private HID ABI works — interface opens, class/descriptors/pipe/commit all succeed). **U3.9 (generic-host enumeration) FAILS via the userspace approach on this device**. The capture establishes failure to observe the expected keyboard. It did not trace the controller’s driver-matching outcome.
- **Trials (all non-enumerating; not a count ceiling, not the name):** v19 composite configure-only (`hid-v19-…-b292a59c`), v20 composite full mode (`hid-v20-…-a5516521`), v21 usbmux-preserving full mode `[PTP, AppleUSBMux, Mac2jbCanary]` (`hid-v21-…1793612112…`), and two stock-`Keyboard` runs `[AppleUSBMux, Keyboard]` (`…1793616615…` confounded by the audio race; `…1793633727…` clean, audio healed, still `usb=absent`). 3-interface configs failed like the 7-interface composite (not a count ceiling), and the stock name failed like the invented one (not a name/definition problem) — consistent with the `createUSBDevice` kernel-match mechanism above.
- **External research (2026-11-02, web; sources in the research log) — best mechanism for the on-bus failure, and no prior art.** No public project has made a jailbroken/TrollStore iPhone or iPad act as a USB **device-mode** HID keyboard to an external host; all "iOS keyboard" results are the reverse direction, Bluetooth, or external hardware. The one primary iOS-gadget RE source (Synacktiv, *"iOS: a journey in the USB networking stack,"* 2024) states that **`IOUSBDeviceController::createUSBDevice` matches each interface of the selected configuration to an in-kernel IOKit driver** before bringing the configuration on bus. This is the most likely explanation for our `goOnBus: not on bus`: stock functions enumerate because each has a **kernel driver match** *and* a userspace backend (PTP+ptpd, audio+audiomxd); the canary supplies only a userspace `IOUSBDeviceInterface` user client with **no kernel driver to bind**, so `createUSBDevice` cannot build that interface and the config never goes on bus — even though the ABI staging calls return `0x0`. The macOS PoC had to ship a **kext** to defeat exactly this `createUSBDevice` entitlement/matching path and ran the publish "from a kernel thread." So the earlier "not a kernel-driver requirement" phrasing is itself too strong: a function needs a kernel-side match to enumerate; a pure-userspace custom function does not. Implication: the only userspace-reachable path is **repurposing a stock, already-kernel-matched function** (no one is known to have coerced one into arbitrary HID reports); a custom HID function most likely needs a kernel driver/match, the large mechanism.
- **Kernel-code prior art corrects one overbroad claim, but does not supply the missing HID driver.** Google Project Zero's [KTRW](https://github.com/googleprojectzero/ktrw) genuinely loaded `ktrw_gdb_stub.ikext` on A11 iPhones: dynamically on iOS 12 after an A11-only KTRR bypass, and by preboot kernelcache insertion through checkra1n/pongoOS on iOS 13.3. Its demonstrated kext has an empty `IOKitPersonalities` dictionary, starts a debugger thread, and directly takes over the Synopsys USB2 OTG controller; it is not an IOKit-matched USB gadget function. [KCMod](https://github.com/skr0x1c0/kcmod) replaces a kernelcache fileset for Apple Security Research Device work. The newer [insert_kext](https://github.com/mowisec/insert_kext) demonstrates injected code and registration of a stock `IOService` object on an arm64e research kernelcache, but explicitly does **not** define a driver/personality: a custom class would require correctly PAC-signed vtable entries. These are real exceptions to "iOS loads no third-party kexts," but none is an ordinary-jailbreak loader for this M2/iPadOS 17 target, none demonstrates a third-party `IOUSBDevice*` personality, and none has produced USB HID device-mode enumeration. The durable conclusion is narrower: **third-party iOS kernel code has public precedent under exceptional, target-specific research/boot conditions; a modern arm64e IOKit USB-gadget driver on this target remains unproven.**
- **Restore mechanism — validated on device.** The U4 stored-description restore (`MAC2JBUSBSetStoredDescriptionOrPublish`, pushes the exact journaled stock bytes, no clone-and-compare) recovered the device to stock after the v21 interface-list publication with **no reboot** (`USBMUX query=ok count=1`, `raw-ipad=yes current-configuration=5`). The earlier worry that an interface-list restore might need a reboot did not materialize here. Autonomous heal for an interface-list record fails safe (restores stock, never republishes the trial shape).
- **Broker/journal:** now `dev.mac2jb.u2.additivev21` (binary `.mac2jb-u2-noop-trial-81889579`, interface-list publish + stored-description restore, behind `MAC2JB_U4_INTERFACE_LIST`), idle, jetsam raised to 96 MB, injection disabled. Reached by swaps v19→v20→v21; the device swap tool now verifies bootout by the service being gone, not launchctl's exit code (a healthy daemon exits nonzero on SIGTERM). Journal absent.
- **`boot_session` bug — FIXED and deployed.** `sha256(kern.boottime)` hashed the whole `timeval` including `tv_usec`, which time-sync rewrites without a reboot. Now derived from **tv_sec only** at all four sites and the deployed broker (commits `147bb66`, `15c4699`). The strict check reports `boot=same` where the drifted derivation reported `reference boot changed`. Regression test `tests/test-u2-boot-session-derivation.py`.
- **Baseline:** fresh baseline captured this boot, manifest `c545419e…`, pinned in `host/check-u2-trial-current.py`. Old baseline retired to `u2-v9-trial-baseline.oldboot-970d8d30`; the cut-over old-boot journal archived at `restore-journal.oldboot-981dba20`.
- **Product goal:** every jailbroken or TrollStore-capable USB-C iPad and iPhone; Lightning is a stretch goal. This iPad is the reference device.

## Stock USB driver declarations in build 21A329

The Apple restore IPSW for iPadOS 17.0 selects the shared
`kernelcache.release.iPad14,3_4_5_6` for `iPad14,5`. The decompressed
kernel collection has SHA-256
`1c9673343820d2294a4958dc47d24f67d1811ca1b4c2a7300e09e6e1252e8b10`.
Its embedded prelink dictionary contains 298 entries and 1,062 entries under
`IOKitPersonalities`. Fifteen personalities explicitly identify a
`USBDeviceFunction`. None names `Keyboard`. The `IAP USB Port` personality
in `com.apple.iokit.IOAccessoryPortUSB` explicitly matches
`IOUSBDeviceInterface` with `USBDeviceFunction = IapOverUsbHid`.
This declaration does not describe the HID usages seen by the host.

PTP, a known working stock function, is also absent from those fifteen
literal matches. The static catalogue therefore cannot rule out every other
ownership mechanism. It also cannot establish that lack of a matching kernel
personality caused the failed Keyboard trials. The unresolved comparison is
how the shipping PTP backend acquires its interface and whether the firmware
contains a corresponding stock producer for Keyboard.

Across all kernel catalogue properties, the exact value Keyboard occurs
26 times. Of these, 22 declare HIDDefaultBehavior on IOHIDInterface
providers (13 AppleHIDKeyboardEventDriver, nine AppleEmbeddedKeyboard).
Four declare Accessory Category on IOUSBHostInterface providers handled by
AppleUSBTopCaseHIDDriver. These classify keyboard inputs or attached
accessories. None of those entries declares a device-side keyboard producer.

The full restore filesystem supplies a concrete PTP launch path.
`System/Library/LaunchDaemons/com.apple.ptpd.plist` declares an IOKit
launch event matching an `IOUSBDeviceInterface` whose `USBDeviceFunction`
is `PTP`, and runs `/usr/libexec/ptpd -t usb`. Among the plists examined
directly under `System/Library/LaunchDaemons`, PTP was the only launch event
with the literal `USBDeviceFunction` property. The system USB configuration
plist contains `standardKeyboard`. No corresponding Keyboard launch event
was found in that directory. This comparison identifies a launch trigger;
it does not trace subsequent endpoint ownership or exclude an already-running
process.

The board-specific DeviceTree.j620ap.im4p in the same restore archive
sets configuration-string to stdMuxPTPEthValIDA for both usb-drd0 and
usb-otg0. The rsm node specifies standardMuxOnly. No configuration-string
in the parsed tree selects standardKeyboard. This identifies the shipping
board defaults; runtime selection and report ownership are separate questions.

The production USBDeviceConfiguration.bundle contains two distinct call
patterns. Its add-interface routine reads the current controller description,
looks for a matching configuration, and can set a preferred configuration.
Elsewhere the bundle builds a description from defaults and the controller
and can publish that description. Selecting an entry in the current
description therefore cannot be assumed to load an arbitrary profile from
the catalogue. The bundle's USB imports concern controller configuration;
the inspected calls provide no evidence of a keyboard report producer.
This is static call-site evidence. The branch taken during a trial is unknown.

## Accessory HID report format and shared-cache coverage

The stock raw configuration baseline advertises a 208-byte HID report
descriptor. The configuration capture holds the length, not the report
descriptor bytes. Independently, the build 21A329 IOAccessoryPortUSB kernel
extension contains two parsable HID application collections of 96 and 208
bytes. Both declare vendor-defined usage page 0xff00, usage 1, and keep that
page through the end of the collection. Neither declares keyboard input.
The 208-byte sequence has 21 report IDs and SHA-256
`900fc1696e0d575469facc1b83008e711121c965d477f9a4839364f6ce680103`.
The length match and stock driver declaration support an accessory-specific
format. Exact on-wire identity remains unverified.

The 54 SystemOS arm64e shared-cache files inspected contain no literal
ASCII standardKeyboard or IapOverUsbHid. The cache string search attributes
USBDeviceFunction to CoreMedia, which also contains Valeria and
IOUSBDeviceInterface. The PTP positive control resides in the standalone
ptpd executable, outside this cache. These checks narrow literal-name
ownership hypotheses but cannot exclude dynamic lookup or a standalone
producer. GameControllerFoundation's similarly named USB interface diagnostic
appears alongside racing-wheel discovery and interface iteration.

A root-filesystem scan of 2,466 standalone Mach-O files (arm64 and universal
magic values; one filesystem entry unreadable) recovered the PTP positive
control. Seven images contained the ASCII USBDeviceFunction or
IOUSBDeviceInterface string: ptpd, lockdownd, idamd, audiomxd, dmd,
USBEthernetSharing and AppleIDAMDriver. None contained standardKeyboard or
IapOverUsbHid; neither literal appeared in any scanned Mach-O. In lockdownd,
the standalone Keyboard string sits with Language, Locale and other
international settings. Its USB diagnostics occur separately. Co-occurrence
in that binary supplies no evidence of keyboard report production. This scan
covers literal strings and does not trace indirect library calls.

The separate AppOS image (078-27668-719.dmg) contains 943 regular,
non-symlink files. None contains standardKeyboard, USBDeviceFunction,
IOUSBDeviceInterface or IapOverUsbHid as ASCII, UTF-16LE or UTF-16BE.

A byte-signature search finds two Generic Desktop Keyboard application
collections in /usr/sbin/bluetoothd. The 115-byte and 90-byte collections
both use the Keyboard/Keypad usage page and contain input and output items. This was the
only hit for the contiguous six-byte keyboard collection prefix among the
2,466 root-filesystem Mach-O files scanned. The same prefix was absent
from the kernel collection and the SystemOS system and DriverKit arm64e
cache files. The accessory collection prefix independently mapped to
IOAccessoryPortUSB twice in the kernel collection. These controls establish
coverage for that encoding; other encodings and dynamically built descriptors
remain possible. No link between the bluetoothd descriptors and the USB
Keyboard interface was established.

Disassembly resolves three direct code references to the two bluetoothd
descriptor prefixes. The constructed buffers have lengths 207 and 182 bytes.
Parsing those lengths reaches balanced collection boundaries in both cases.
Each contains three top-level application collections: Keyboard, Consumer
Control, and vendor-defined page 0xff00 usage 6. The previously measured
115 and 90 bytes are the lengths of the first collections only. One caller selects among the three descriptor builders and passes the
returned object to the same setup routine. That routine uses the object
while obtaining a device handle and registers IOHIDUserDevice get/set
report callbacks on the resulting handle. This traces a local virtual HID
consumer of the descriptors. No corresponding external USB gadget consumer
has been identified.

## Interpreting the stock Keyboard host capture

In the clean retry, the Mac lifecycle monitor recorded departure at +1.05 s. The enumeration capture at approximately +476 s recorded a live publication, no keyboard interface and zero reports. The first later USB arrival was at +561.24 s, after the last recorded lease renewal at approximately +476 s. The lifecycle events alone identify neither a keyboard interface nor a report descriptor. The archived result therefore establishes failure during the observed publication; it does not identify the exact internal stage that prevented enumeration. The driver-matching explanation draws on the published controller architecture. The trial did not directly trace a failed driver match. A fixed stock keyboard descriptor would also suffice if an existing producer could supply its input reports.

The clean retry's two device-side connection completions were 30 ms apart
at 09:44:57 local time (approximately +562 s from the host monitor start).
They cluster with the late host arrival at +561.24 s, well after the +476 s
live-publication check. Neither completion establishes keyboard enumeration.
The restore boundary cannot be inferred from the last lease renewal alone.

The trial-era host capture helper required configuration value 5 even when it
reads other valid configuration descriptors. Its caller converted validation
errors, timeouts and helper errors to an absent envelope, reported as
not-enumerated. A device exposing only configuration value 1 could therefore
receive this label despite enumerating. The previous trials retained
configuration 5, and the clean retry also had a separate lifecycle monitor.
The current observer reads every advertised configuration and propagates helper errors. Stock recovery still requires configuration 5.

The native raw-descriptor reader identifies its target by exact USB product
name. A device that reappears with a different name can escape that reader.
The separate lifecycle monitor uses vendor and physical port location after
initial identification, providing an independent check when those stay
stable. A configuration-1 parser fixture does not exercise live target matching.

The host capture's control-request fields are inferred from registry state
by `control_requests()` in `host/capture-u2-hid-enumeration.py`. They do
not timestamp setup packets, replies or stalls. The retained evidence tree
contains no files with pcap, pcapng or usbtrace extensions. A stock-versus-
Keyboard comparison can establish a difference in enumeration outcome but
cannot locate the first failed on-wire transaction using those fields.


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
