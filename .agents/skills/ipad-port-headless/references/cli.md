# CLI reference for headless mac2jb iPad work

Durable usage and known limits only. Results of runs belong in `docs/ipad/target-device-findings.md`. Script paths are relative to `docs/plans/ipad-port/scripts/ipad-hardware/`; read a script's header for its exact arguments and effect before running it.

## Mac tools

| CLI | Use and limits |
|---|---|
| `/usr/bin/dns-sd` | Used by `host/discover-pinned-ipad-wifi.py`: passive `_companion-link._tcp` browse, resolves one iPad-named service, saves the address only after the host pin and both account UIDs pass. Prints no address. |
| `/opt/homebrew/bin/idevice_id` | `-l` prints a unique ID: capture/filter it privately. Require exactly one intended physical device before a write. `-n` may list more network identities than USB targets; pin the sole USB identifier rather than requiring a global network singleton. |
| `/opt/homebrew/bin/iproxy` | Only through `host/start-usb-ssh-tunnel.sh` (USB port 22 -> `127.0.0.1:2222`, foreground). Confirm with `lsof -nP -iTCP:2222 -sTCP:LISTEN`; never start a second tunnel on an occupied port. |
| `/usr/bin/ssh`, `/usr/bin/scp` | Use `ssh_options()` from `host/backup-clienttruth-over-root-ssh.py` plus `-o HostKeyAlias=[127.0.0.1]:2222 -o AddressFamily=inet -T -p 22` for Wi-Fi (`mobile@` or `root@` the private address); port 2222 through the verified tunnel for USB. Prefer host runners that read the private address without printing it. No default identities; the private key never leaves the Mac. |
| `/opt/homebrew/bin/afcclient` | USB Media staging when SSH is unavailable: `afcclient --udid <private USB UDID>`, never `--network`. Interactive; use its `help`. Remote root is `/var/mobile/Media`. Check destination absent, transfer only repo scripts/public artifacts, read back byte-for-byte, record in the ledger. Never transfer a private key. |
| `/opt/homebrew/bin/idevicedebug` | `run <bundle-id>` needs a developer disk image, which was unavailable; exit `255` is not an app result. |
| `xcrun devicectl` | The physical iPad was listed unpaired and launch failed. Do not confuse its same-model simulator record with the wired iPad. |
| `ldid -e`, `codesign` | `ldid -e <private installed Mach-O copy>` reads effective entitlements. `codesign --verify` rejects TrollStore's trust chain; use the repo's TrollStore-aware installed-archive validators instead (they do not claim Apple trust). |
| Go (`/opt/homebrew/bin/go`) | Build standalone runners with `GOCACHE="$PWD/build/ipad-hardware/go-cache" /opt/homebrew/bin/go build -o build/ipad-hardware/<name> <script>.go`. Verify Go availability and build/signing constraints before choosing it for an iPad payload. |
| Mac USB host tools | `uhubctl`/`usbreset` are not installed and hub power switching is unverified. Do not reset the whole Mac host controller: shared hubs carry the external workspace drive. |

## iPad tools (rootless Dopamine, `/var/jb`)

| CLI | Use and limits |
|---|---|
| `/var/jb/usr/bin/uiopen --bundleid <id>` | Requests a SpringBoard launch by exact bundle ID. Bare IDs take its URL branch. Exit 0 means the request was accepted, not that the app finished. |
| `python3`, `sudo`, `stat`, `timeout`, `sha256sum` | Present. `stat` is GNU: `stat -c '%u:%g:%a' <path>`. Run stdin Python with `-I -S -B`. Direct pinned root SSH replaces `sudo` for root work. |
| `uicache` | Mutates app registration: needs an explicit plan and ledger entry. |
| `id`, `perl`, GNU `tar`, `grep`, `find` | `id -u` confirms the account privately. Prefer pinned Python scripts over Perl. Read-only archives use root-relative operands (`tar -C / -cf - var/jb/...`); never extract or use absolute operands speculatively. Use `grep`/`find` only on fixed bounded roots so private paths stay out of chat and Git. |
| `/usr/sbin/ioreg` | Returned `137` under `mobile`; use the repo's attested/pinned probes for controller evidence. |
| `dpkg-query` | Only through a bounded on-device filter script (e.g. `device/u1-readonly-appsync-package-membership.sh`); never emit the raw package database. |
| `jbctl trustcache` | `info` is read-only. `add` has no per-hash rollback and `clear` is global: never use either as a fix or connectivity check. |
| Not found | `plutil`, `plistutil`, `log`, `syslog`, `dmesg` were absent at checked paths; `appinst` not observed. Scoped observations, not proof of global absence. |

## Host check families

- `host/check-pinned-wireless-ssh.py`, `host/discover-pinned-ipad-wifi.py` - control channel.
- `host/diagnose-usb-recognition.py`, `host/check-pinned-ssh-while-app-closed.py` - USB/usbmux; require exactly one target.
- `host/check-u2-*` - external USB/NCM/pairing/power comparisons against private baselines. A pass category is evidence only; these scripts never confirm or clear a journal.
- `host/read-u2-*-wifi.py` with matching `device/u2-readonly-*.py` - pinned read-only controller/Type-C/XDCI probes.
- Wrappers that need the iPad on the Mac cable (USB lifecycle windows, raw descriptor captures) refuse to run otherwise; moving the cable between Mac and Switch 2 needs the owner and a fresh SSH/target check.
