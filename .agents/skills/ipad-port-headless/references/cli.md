# CLI reference for headless mac2jb iPad work

Durable usage and known limits only. Results of runs belong in `docs/ipad/target-device-findings.md`. Script paths are relative to `docs/plans/ipad-port/scripts/ipad-hardware/`; read a script's header for its exact arguments and effect before running it.

## Mac tools

| CLI | Use and limits |
|---|---|
| `/usr/bin/dns-sd` | Used by `host/discover-pinned-ipad-wifi.py`: passive `_companion-link._tcp` browse, resolves one iPad-named service, saves the address only after the host pin and both account UIDs pass. Prints no address. |
| `/opt/homebrew/bin/idevice_id` | `-l` prints a unique ID: capture/filter it privately. Require exactly one intended physical device before a write. `-n` may list more network identities than USB targets; select by the target's chip prefix (the tools use `00008112-` for the reference iPad), never print it. |
| `/opt/homebrew/bin/idevicesyslog -n -u <id>` | Streams the device syslog over the network, **even while USB is off bus**. The recovery tools record it to private `syslog.txt` with automatic reconnect; look for `register function`, `createUSBDevice`, `gated_registerFunction`. |
| `/opt/homebrew/bin/iproxy` | Only through `host/start-usb-ssh-tunnel.sh` (USB port 22 -> `127.0.0.1:2222`, foreground). Confirm with `lsof -nP -iTCP:2222 -sTCP:LISTEN`; never start a second tunnel on an occupied port. |
| `/usr/bin/ssh`, `/usr/bin/scp` | Use `ssh_options()` from `host/backup-clienttruth-over-root-ssh.py` plus `-o HostKeyAlias=[127.0.0.1]:2222 -o AddressFamily=inet -T -p 22` for Wi-Fi (`mobile@` or `root@` the private address); port 2222 through the verified tunnel for USB. Prefer host runners that read the private address without printing it. No default identities; the private key never leaves the Mac. |
| `/opt/homebrew/bin/afcclient` | USB Media staging when SSH is unavailable: `afcclient --udid <private USB UDID>`, never `--network`. Interactive; use its `help`. Remote root is `/var/mobile/Media`. Check destination absent, transfer only repo scripts/public artifacts, read back byte-for-byte, record in the ledger. Never transfer a private key. |
| `/opt/homebrew/bin/idevicedebug` | `run <bundle-id>` needs a developer disk image, which was unavailable; exit `255` is not an app result. |
| `xcrun devicectl` | The physical iPad was listed unpaired and launch failed. Do not confuse its same-model simulator record with the wired iPad. |
| `ldid -e`, `codesign` | `ldid -e <private installed Mach-O copy>` reads effective entitlements. `codesign --verify` rejects TrollStore's trust chain (it does not claim Apple trust there). Broker builds are signed by `build-u2-noop-trial-binary.py`. |
| Go (`/opt/homebrew/bin/go`) | Owner preference for new host scripts when it fits. Build with `GOCACHE="$PWD/build/ipad-hardware/go-cache"`. |
| Mac USB host tools | `uhubctl`/`usbreset` are not installed and hub power switching is unverified. Do not reset the whole Mac host controller: shared hubs carry the external workspace drive. |

## iPad tools (rootless Dopamine, `/var/jb`)

| CLI | Use and limits |
|---|---|
| `/var/jb/usr/bin/uiopen --bundleid <id>` | Requests a SpringBoard launch by exact bundle ID. Bare IDs take its URL branch. Exit 0 means the request was accepted, not that the app finished. |
| `python3`, `sudo`, `stat`, `timeout`, `sha256sum` | Present. `stat` is GNU: `stat -c '%u:%g:%a' <path>`. Run stdin Python with `-I -S -B`. Direct pinned root SSH replaces `sudo` for root work. |
| `uicache` | Mutates app registration: needs an explicit plan and ledger entry. |
| `id`, `perl`, GNU `tar`, `grep`, `find` | `id -u` confirms the account privately. Prefer pinned Python scripts over Perl. Read-only archives use root-relative operands (`tar -C / -cf - var/jb/...`); never extract or use absolute operands speculatively. Use `grep`/`find` only on fixed bounded roots so private paths stay out of chat and Git. |
| `/usr/sbin/ioreg` | Returned `137` under `mobile`; use the pinned `host/read-u2-*-wifi.py` probes for controller evidence. |
| `launchctl` (`/var/jb/bin/launchctl`) | `print`/`list` are read-only. `kickstart -k`, `bootout` and `bootstrap` change daemons: use only through the repo tools. iOS launch constraints SIGKILL Apple daemons started outside launchd. |
| `dpkg-query` | Only through bounded on-device scripts; never emit the raw package database. |
| `jbctl trustcache` | `info` is read-only. `add` has no per-hash rollback and `clear` is global: never use either as a fix or connectivity check. |
| Not found | `plutil`, `plistutil`, `log`, `syslog`, `dmesg` were absent at checked paths; `appinst` not observed. Scoped observations, not proof of global absence. |

## Repo tool families

The full index is in `docs/plans/ipad-port/scripts/README.md`.

- **Control channel:** `host/check-pinned-wireless-ssh.py`, `host/discover-pinned-ipad-wifi.py`; host-key re-pinning with `host/pin-current-usb-ssh-host.sh` and the known-hosts tools.
- **USB/usbmux:** `host/diagnose-usb-recognition.py`, `host/start-usb-ssh-tunnel.sh`, `host/check-pinned-ssh-while-app-closed.py`.
- **Read-only probes:** `host/read-u2-*-wifi.py` with matching `device/u2-readonly-*.py`, plus the learned profile via `host/u2_broker_profile.py`.
- **Strict external check:** `host/check-u2-trial-current.py`, wrapping `host/check-u2-strict-external.py` against a per-boot baseline from `host/capture-u2-trial-baseline.py`. A pass is evidence only; these scripts never confirm or clear a journal.
- **Trials and recovery:** `host/run-u2-noop-trial-auto-heal-wifi.py`, `host/confirm-u2-after-heal-wifi.py`, `host/recover-u2-*.py`, `host/backup-u2-wifi-restore-kit.py`, `host/replace-u2-broker-wifi.py`.
- **Cable moves:** tools that need the device on the Mac cable refuse otherwise. Moving the cable between the Mac and the Switch 2 needs the owner and a fresh SSH/target check.
