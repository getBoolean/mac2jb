# iPad device inventory and cleanup ledger

Every persistent change the port has made to the reference iPad, and the private Mac artifacts that go with it, with cleanup conditions. Rewritten on 2026-10-31 after the leftover cleanup; earlier rows for removed items are in git history. Record any new persistent change here before or as it is made.

## On the iPad (verified 2026-10-31)

| Path | Purpose | Cleanup condition |
|---|---|---|
| `/var/mobile/.ssh/authorized_keys`, `/var/jb/var/mobile/.ssh/authorized_keys`, `/var/jb/var/root/.ssh/authorized_keys` | Pinned Mac key for `mobile` and `root` SSH, the only connection path the tools use. | Keep while any hardware work continues. To revoke, remove only the mac2jb key line, then delete the Mac key and pins below. |
| `/var/jb/usr/libexec/.mac2jb-u2-noop-trial-96296113` (v12 broker, SHA-256 `9629611372c6f570db18064a2cfcd077601f59a1b5a2a4644dbc3bdbefe37a3e`) and `/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nooptrialv12.plist` (RunAtLoad, KeepAlive, JetsamMemoryLimit 96) | The running auto-heal broker: the only U2 controller writer. | Keep for U3. To retire: with no active journal, `launchctl bootout system/dev.mac2jb.u2.nooptrialv12`, then remove the exact binary and plist. |
| `/var/jb/var/lib/mac2jb-u2-native/` (root 0700): `broker.lock`, `broker.sock`, `device-profile.json` (learned profile, root 0600, no private IDs), and `restore-journal.json` only while a trial is unresolved | Broker state. | Keep with the broker. Deleting `device-profile.json` with no journal makes the broker re-learn it. Never delete an unresolved journal; back it up and archive it on a new boot. |
| `/var/jb/usr/libexec/.mac2jb-u2-noop-trial-8fdb044f` (v11 broker, SHA-256 `8fdb044ff8840084e27e896432de060deecd6cdc9d27913b9ae3f379077b3736`), no plist | Rollback target for `host/replace-u2-broker-wifi.py --replace v12 v11`. | Remove after a hash check once v12 has been in use for U3. |

Not changed by the port: `ClientTruth.plist` (SHA-256 `3cee287f…` equals its private backup), system files and the stock USB configuration. All TrollStore test apps, staged `.tipa` files, U1 helper files, older broker binaries, old-boot journal archives and the `mac2jb-u2-native-watchdog` package were removed on 2026-10-31 after exact hash checks.

## On the Mac (private, not in git)

| Path | Purpose | Cleanup condition |
|---|---|---|
| `~/.ssh/mac2jb-ipad/` (identity, `known_hosts` pin, private Wi-Fi address; mode 0600) | Pinned SSH to the iPad. The host tools check the SHA-256 of the identity and the pin. | Keep. If the host key changes, re-pin with `host/pin-current-usb-ssh-host.sh` and the known-hosts tools. |
| `~/.ssh/mac2jb-ipad/backups/clienttruth-before-toolbox-2026-10-30/` | Original `ClientTruth.plist` bytes, metadata and ACL. | Keep while TrollStore installs might happen. |
| `build/ipad-hardware/u2-wifi-restore-kit/<ns>/` | Byte copies of every on-device U2 file, journals, Mac SSH files and repo sources. The newest kit holds everything removed in the 2026-10-31 cleanup. **Contains a private key copy.** | Keep through U3. Delete old kits only after the newest one is verified against its manifest. |
| `build/ipad-hardware/u2-trials/`, `u2-function-census/`, `u2-v9-trial-baseline/`, `u2-v4-repeat-baseline/`, other `build/ipad-hardware/` directories | Trial evidence, the strict-check baseline, the stock live reference, and U1 reports and attestations. | Keep as evidence; never commit. |
