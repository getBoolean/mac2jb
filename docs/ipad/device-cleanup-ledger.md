# iPad device inventory and cleanup ledger

Every persistent change the port has made to the reference iPad, and the private Mac artifacts that go with it, with cleanup conditions. Rewritten on 2026-10-31 after the leftover cleanup; earlier rows for removed items are in git history. Record any new persistent change here before or as it is made.

## On the iPad (verified 2026-10-31)

| Path | Purpose | Cleanup condition |
|---|---|---|
| `/var/mobile/.ssh/authorized_keys`, `/var/jb/var/mobile/.ssh/authorized_keys`, `/var/jb/var/root/.ssh/authorized_keys` | Pinned Mac key for `mobile` and `root` SSH, the only connection path the tools use. | Keep while any hardware work continues. To revoke, remove only the mac2jb key line, then delete the Mac key and pins below. |
| `/var/jb/usr/bin/ipad2jb` (root 0755, SHA-256 `20795715a918d7c46940ffa8d811e18c4a7646d515dc772bf3a47eeb7e7e23f2`; built from `ios/ipad2jb/ipad2jb.c` by `ios/ipad2jb/build.sh`, ad-hoc signed with `ios/ipad2jb/ipad2jb.entitlements`, installed by `host/install-ipad2jb-command-wifi.py`) | The only mac2jb/ipad2jb program on the iPad: `sudo ipad2jb [TEXT]` publishes the single-configuration keyboard, answers class requests, types, and restores the stock description. The broker (`dev.ipad2jb.usbbroker`), the canary, the broker state folder `/var/jb/var/lib/mac2jb-u2-native/` (journal absent) and `/var/jb/var/log/ipad2jb/` were removed on 2026-11-18 after a restore kit. | Remove the binary and `/var/jb/var/lib/ipad2jb/` when no longer wanted. |
| `/var/jb/var/lib/ipad2jb/` (root) | `ipad2jb` keeps `stock-description.plist` here only during a run, so an interrupted run is restored by the next one. Empty between runs. | Remove with the binary. |
| `/var/jb/var/lib/mac2jb-u2-native/restore-journal.oldboot-981dba20` (SHA-256 `981dba200fa4382666081a3dc886655a3b172c96486166194d9ee51fdceb5c57`) | The previous boot's `awaitingVerification` journal, retired on the 2026-11-01 reboot cut-over: archived under this fixed name and the active name unlinked. A reboot makes its restore target moot, so it was never confirmed or restored. | Remove after a hash check once the device phase is done; the bytes also live in the newest Wi-Fi restore kit. |

Not changed by the port: `ClientTruth.plist` (SHA-256 `3cee287f…` equals its private backup), system files and the stock USB configuration. All TrollStore test apps, staged `.tipa` files, U1 helper files, older broker binaries, old-boot journal archives and the `mac2jb-u2-native-watchdog` package were removed on 2026-10-31 after exact hash checks.

## On the Mac (private, not in git)

| Path | Purpose | Cleanup condition |
|---|---|---|
| `~/.ssh/mac2jb-ipad/` (identity, `known_hosts` pin, private Wi-Fi address; mode 0600) | Pinned SSH to the iPad. The host tools check the SHA-256 of the identity and the pin. | Keep. If the host key changes, re-pin with `host/pin-current-usb-ssh-host.sh` and the known-hosts tools. |
| `~/.ssh/mac2jb-ipad/backups/clienttruth-before-toolbox-2026-10-30/` | Original `ClientTruth.plist` bytes, metadata and ACL. | Keep while TrollStore installs might happen. |
| `build/ipad-hardware/u2-wifi-restore-kit/<ns>/` | Byte copies of every on-device U2 file, journals, Mac SSH files and repo sources. The newest kit holds everything removed in the 2026-10-31 cleanup. **Contains a private key copy.** | Keep through U3. Delete old kits only after the newest one is verified against its manifest. |
| `build/ipad-hardware/u2-trials/`, `u2-function-census/`, `u2-v9-trial-baseline/`, `u2-v4-repeat-baseline/`, other `build/ipad-hardware/` directories | Trial evidence, the strict-check baseline, the stock live reference, and U1 reports and attestations. | Keep as evidence; never commit. |
