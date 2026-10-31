# iPad USB restoration runbook

How to run, verify and recover USB description changes on an iPad with the auto-heal broker. All paths are relative to the repository root; tools live in `docs/plans/ipad-port/scripts/ipad-hardware/` (`host/` runs on the Mac, `device/` payloads are streamed over pinned SSH). The current device state is in [target findings](target-device-findings.md); the mechanism is in [automatic recovery](usb-auto-recovery.md).

## Before anything

1. `python3 …/host/check-pinned-wireless-ssh.py`: require `pinned-inputs=ok mobile=ok root=ok`. If the address is stale: `host/discover-pinned-ipad-wifi.py`.
2. `python3 …/host/diagnose-usb-recognition.py`: require `USBMUX query=ok count=1` when USB should be up.
3. Broker idle and profile learned: `python3 -c "import runpy;print(runpy.run_path('…/host/u2_broker_profile.py')['fetch']())"`. If the broker has no profile, it learns one on its next start while USB is healthy and no journal exists.
4. Before any controller write, make a backup kit: `host/backup-u2-wifi-restore-kit.py`. It saves byte copies of every on-device U2 file, the active journal, the Mac SSH files and sources to private `build/ipad-hardware/u2-wifi-restore-kit/<ns>/`.

## Run a no-op trial

`python3 …/host/run-u2-noop-trial-auto-heal-wifi.py --broker v12 normal|worker-kill|watchdog-kill`

The runner does the preflight (including the strict external check), a backup kit, network syslog recording and the passive Mac lifecycle monitor, then one client run. It waits up to 120 s for the broker to heal by itself, then runs the strict external check, `host/check-u2-trial-current.py --expect-journal=awaitingVerification`. Only if that passes does it send `confirm <sha256(check output)>`, then re-check with no journal. Evidence goes to `build/ipad-hardware/u2-trials/run-<broker>-<mode>-…/`.

The strict check compares against `build/ipad-hardware/u2-v9-trial-baseline/`, which is bound to one boot. After a reboot, capture a fresh one with no journal active: `host/capture-u2-trial-baseline.py` (twice-stable). Then update the manifest digest in `host/check-u2-trial-current.py`.

## If USB does not come back

The broker already heals automatically: bounded re-publication plus owner restart, after a failed first enumeration, worker death, watchdog restart or lease expiry. If it gives up (`heal-status` reports `heal-gave-up`):

1. `host/recover-u2-over-wifi.py`, **once**. It refuses unless SSH works, the Mac sees no device and the controller is unconfigured. It backs up first, records the failed-state readers and network syslog, sends one `restore-after-failure` (which also heals), and backs up the changed journal.
2. If still absent, read the recorded `syslog.txt` for `register function` lines; the unregistered functions are also visible via `host/read-u2-xdci-function-census-wifi.py` as nubs with no client.
   - Kernel-owned functions missing: `host/recover-u2-until-registered-wifi.py` (bounded re-publication).
   - Only a user-space-owned function missing: `host/recover-u2-restart-function-owner-wifi.py com.apple.audiomxd` (or the owner the profile names).
3. Never confirm or clear the journal without the strict external check. Use `host/confirm-u2-after-heal-wifi.py`: it sends `heal`, checks USB, pairing, the controller and the census against the healthy reference, then confirms.
4. If nothing works, ask the owner for a restart and re-jailbreak; a reboot always restores USB. On the new boot, verify SSH and USB, make a backup kit, capture a new trial baseline, and resolve the old journal before the next trial.
   - A guarded old-boot archive needs a fresh tool. The previous version-specific ones are in git history, e.g. `archive-u2-v8-old-boot-journal-wifi.py`.

## Replace the broker

Build: `python3 …/build-u2-noop-trial-binary.py --v12-learned-profile` (Mac only, signed with platform and set-description entitlements). Deploy: `python3 …/host/replace-u2-broker-wifi.py --replace OLD NEW`. It makes a backup kit first and swaps an allowlisted broker, keeping any journal unchanged. Add new brokers to the allowlists in `host/replace-u2-broker-wifi.py` and `device/u2-replace-broker.py`.

## Rules

- Never `StrictHostKeyChecking=no`, default identities or an unpinned target.
- API success or `awaitingVerification` is not recovery; only external Mac checks prove it.
- Do not repeat a recovery action that already failed on the same boot.
- Do not reset the whole Mac USB host controller: the workspace drive shares it.
- Record every device action in the findings Current state and every persistent change in the [inventory](device-cleanup-ledger.md).
