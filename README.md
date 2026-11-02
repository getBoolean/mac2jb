# mac2jb

> **Failed experiment — iPad/iPhone port closed, 2026-11-02.** This repository
> retains the experiment and its findings for reference. Direct USB HID did not
> enumerate on the reference M2 iPad Pro running iPadOS 17.0 across five userspace
> trials. Source review found no kernel gadget candidate meeting the project's
> reversibility requirements, so the later kernel and Switch validation gates
> were not run. There is no working iPad/iPhone port. See the
> [gate findings](docs/ipad/hardware-matrix.md) and
> [kernel candidate assessment](docs/plans/ipad-port/research/kernel-gadget-candidate-matrix.md).
> This result is limited to the investigated approaches and target; it does not
> establish impossibility on every device. The original macOS instructions are
> retained below.

an all-in-one ns2 jailbreaking tool for mac.

## what you need

- an apple silicon mac with macos 14 or newer.
- a switch 2 on firmware 23.0.1 (earlier versions should also work), with smilebasic full version 4.4.9 or demo 4.4.6.
- more than 20 mib free in the game's save. keep the game on internal storage.
- a usb-c data cable and both devices connected by ethernet to the same network.
- the switch's usb keyboard setting set to us english.

[block console updates before testing](https://consolemods.org/wiki/Switch:Blocking_OFW_Updates#90DNS).

## set up the usb driver

the bundled driver is unsigned. mac startup security and sip must permit unsigned
kernel extensions. if the driver already works with your partial/custom sip
configuration, keep that setup. otherwise, follow these steps from the
[published readme](https://github.com/cpypwn/mac2jb/blob/main/README.md).

### 1. configure macos recovery

1. shut down the mac.
2. hold the power button until loading startup options appears.
3. select options → continue. authenticate with an administrator account if asked.
4. open utilities → startup security utility. select your startup disk and click security policy.
5. select reduced security.
6. tick allow user management of kernel extensions from identified developers.
7. confirm the changes, authenticate if asked, then close startup security utility.
8. open utilities → terminal and enter:

   ```sh
   csrutil disable
   ```

9. follow the confirmation and administrator prompts, then choose apple menu → restart.
10. back in macos, open terminal and enter:

    ```sh
    csrutil status
    ```

    for this route, confirm it reports `System Integrity Protection status: disabled.`
    an existing working partial/custom configuration can report a different status.

### 2. install and load the usb driver

1. extract the supplied v0.5.0 zip and open `mac2jb.app`.
2. if macos blocks the app, open system settings → privacy & security and choose open anyway if offered, then reopen the app.
3. click install & load driver… and approve the administrator prompt.
4. if prompted, open system settings → privacy & security and allow the driver.
5. accept the restart prompt or choose apple menu → restart.
6. reopen mac2jb and wait for the driver check. continue when the driver is loaded and no driver-install restart is pending.

refresh driver status to check it; each reinstall creates a new restart requirement.
disabling sip reduces macos protection. mac2jb does not change these settings.
fully re-enabling sip with this unsigned driver has not been verified and may
stop it working after a kernel-collection rebuild. see
[apple's startup-security guidance](https://support.apple.com/en-euro/guide/mac-help/mchl768f7291/27/mac/27)
and [sip documentation](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection).

### 3. check usb power direction

a loaded driver does not confirm that the cable is connected correctly.
the switch should supply power to the mac; the mac should not charge the switch.
if power is flowing the wrong way, unplug the usb-c cable from the switch,
wait about 1 second, then plug it back into the switch. check that the switch
is now supplying power to the mac.

## type and save the new bootstrap

replace your previous bootstrap, including the one from build 516.
choose your host in developer options; changing hosts requires
typing and saving that host's matching bootstrap. see [developer options](#developer-options).

1. open smilebasic → make a program with an empty editor in slot 0.
2. open first time setup in mac2jb. tick the demo checkbox only for demo 4.4.6.
3. start typing and wait until it finishes. the app defaults are 10 ms per key, 1 second between commands and 1 second before load confirmation for both full and demo versions; timing remains adjustable.
4. press x on the switch controller to return to direct mode.
5. confirm that direct mode has an empty command prompt, then click type save command. mac2jb types the command for your selected edition and presses enter once.
6. confirm saving on the switch. overwrite the existing ns2 file if prompted. after saving finishes, confirm saving in mac2jb.

the skip option is for a complete copy of this build's bootstrap already in slot 0.
the commands below remain available if you prefer to save manually.

### full version

save with:

```basic
SAVE "NS2"
```

mac2jb loads it with `LOAD "TXT:NS2"` and accepts its confirmation.

### demo version

save every line in slot 0 with this command:

```basic
PRGEDIT 0:C$="":FOR I=0 TO PRGSIZE(0)-1:C$=C$+PRGGET$() :NEXT:SAVEV "TXT:NS2",C$
```

the closed `PRGGET$()` call reads one line and advances to the next, so the loop
is needed to collect the entire bootstrap. see the [smilebasic reference](https://sup4.smilebasic.com/en/doku.php?id=reference%3ASource_Code_Operation).

with the demo box ticked, mac2jb loads it using:

```basic
PRGEDIT 0:LOADV "TXT:NS2" OUT C$:PRGSET C$
```

mac2jb types this command and presses enter, waits 1 second, then presses enter
again to accept ok before sending run.

## jailbreak

1. restart the switch and open smilebasic → make a program → direct mode.
2. connect usb and ethernet. select the mac's wired network address in mac2jb.
3. tick the demo checkbox if you use the demo; leave it off for the full version.
4. confirm the switch is ready, then click jailbreak.
5. keep smilebasic focused and wait for 4/4 verification before choosing a homebrew app.

## homebrew

choose one app per held session:

- gpubrewlauncher: hello world, froggy road and ftpd-sb. ftpd-sb uses ftp port 5000.
- hblauncher v0.2.0: the original gpu app launcher, also with ftpd-sb on ftp port 5000.
- izlauncher: the iz2s console launcher and file exchange through the current held rpc session, including demo via BermTheSequel.
- ouncecake: exports your own games' unencrypted content over ftp port 2121.
- stremio: requires stremio installed on the mac. leave the manual add-on field empty to use account add-ons.

stremio sends larger video and menu frames through a dedicated tcp receiver in
the existing held session. small frames that fit one rpc write keep the existing
path. audio and session control still use rpc. the mac must remain connected;
the receiver stops if a complete frame cannot be confirmed.

for extra launcher apps, copy the complete compatible app folder into the current
session's `vendor/GPUBrewLauncher/apps/` or `vendor/HBLauncher/apps/` directory
for the launcher you selected, then refresh its app list.
keep your originals elsewhere; each new session has a fresh app library.

## finish or retry

close any ftp connection, choose finish session and wait for cleanup.
restart the switch before another attempt. never send remove twice in the same smilebasic session.
if typing stops partway through, inspect and clear the partial input before retrying.
saving the bootstrap does not preserve a live jailbreak connection.

## developer options

- choose pepsipu, kurumuz or BermTheSequel as the host. type and save the selected
  host's matching bootstrap before running it. pepsipu uses the original
  nine-argument pairing command and does not support held rpc; kurumuz and
  BermTheSequel support held rpc. demo automation uses BermTheSequel.
- in additional tools, run host only starts the selected host without typing
  commands. checking hold rpc after success shows homebrew directly below it;
  launch buttons become available after 4/4 verification and a held connection.
- rpc already held is also in additional tools. select the original run folder
  for a host still running on this mac, then connect. mac2jb verifies its live
  connection before enabling homebrew. disconnecting leaves the original host
  running. remote hosts and ssh are not supported.
- live keyboard forwards keys while its capture area is focused. connect it,
  paste text into the text field and click send text to send a string at the
  configured key delay. send up to 16 kib of printable us keyboard characters,
  tabs and line breaks; each line break sends enter. no extra enter is added at the end.
  stop keyboard cancels a transfer and releases keys.
- usb & timing lets you select a controller and adjust typing delays. defaults
  are 10 ms per key, 1 second between commands and 1 second before load confirmation.

## build from source

on an apple silicon mac, install xcode command line tools, cmake and the official
node v24.22.1 macos arm64 or universal executable, then run:

```sh
bash scripts/check.sh
make gui
build/mac2jb.app/Contents/MacOS/mac2jb --self-test
```

this uses the existing build workflow and produces `build/mac2jb.app`, including
its offline runtime and source archive. if node is elsewhere, set `NODE_BINARY`
to its absolute executable path. the build prepares pinned homebrew dependencies
when needed. the self-test checks the packaged runtime without sending console
commands. the full macos fixture and node check list is in
[the build workflow](.github/workflows/build.yml).

## help and source

use the console and session logs to investigate failures.
[driver provenance](drivers/README.md) · [third-party notices](packaging/NOTICE.md) · [license](LICENSE)

## credits

- [pepsipu](https://gitlab.com/pepsipu) — [ns2jb](https://gitlab.com/pepsipu/ns2jb), the original switch 2 exploit and filesystem research.
- [kurumuz](https://gitlab.com/kurumuz) — [ns2jb](https://gitlab.com/kurumuz/ns2jb), compatibility updates.
- [BermTheSequel](https://gitlab.com/BermTheSequel) — [ns2jb2](https://gitlab.com/BermTheSequel/ns2jb2), the default host and demo support.
- [shinyquagsire](https://github.com/shinyquagsire23) — [libusbd](https://github.com/shinyquagsire23/libusbd) and [macos_usb_gadget_poc](https://github.com/shinyquagsire23/macos_usb_gadget_poc), usb device emulation and macos gadget-driver work.
- [misshexa66](https://github.com/misshexa66) — [ouncecake](https://github.com/misshexa66/OunceCake), game-content export.
- [ravensclawx](https://github.com/ravensclawx) — [hblauncher](https://github.com/ravensclawx/HBLauncher), the smilebasic gpu app launcher and sdk.
- [niftynova](https://github.com/NiftyNova) — [gpubrewlauncher](https://github.com/NiftyNova/GPUBrewLauncher), the updated gpu app launcher.
- [byizmysh](https://github.com/byizmysh) — [iz2s-platform](https://github.com/byizmysh/IZ2S-Platform), the izlauncher console shell.

see the bundled notices, licenses and upstream documentation for attribution and reuse terms.
