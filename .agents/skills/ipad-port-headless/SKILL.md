---
name: ipad-port-headless
description: Use when doing any mac2jb iPad hardware work - connecting to the target M2 iPad over Wi-Fi SSH or USB, running device probes or host checks, U1/U2/U3 gate work, USB description publication or restore trials, recovering lost USB data, attestation, staging, or device cleanup. Not for other iOS devices.
---

# Headless mac2jb iPad work

**SKILL MAINTENANCE:** This file is the canonical skill. `.claude/skills/ipad-port-headless/SKILL.md` is a pointer stub for Claude Code that repeats only this frontmatter `name` and `description` (needed for discovery) and tells the agent to read this file. When editing this frontmatter, update the stub's frontmatter to match. Keep all other content here only; do not copy it into the stub or replace the stub with a symlink.

This skill holds durable procedure and rules only. **It never holds device status, trial results, or stop points.** Record those in the docs below; the top "Current state" block of `docs/ipad/target-device-findings.md` is the single source of truth for what is true now.

## Before any device action

Work from the repository root (find it by its `docs/plans/ipad-port/scripts/ipad-hardware` tree if it moved). Check `git status --short` and preserve unrelated edits.

Read, in order:

1. `docs/ipad/target-device-findings.md` - the **Current state** block at the top: target, boot/journal state, what is forbidden right now, next step.
2. `docs/ipad/usb-recovery.md` - USB restore and recovery runbook (required before any U2/controller action).
3. `docs/ipad/device-cleanup-ledger.md` - every persistent iPad/Mac change and its cleanup condition.
4. As needed: `docs/ipad/u2-usb-recovery-failure-analysis.md`, `docs/ipad/hardware-matrix.md`, the active section of `docs/plans/ipad-port/01-hardware-feasibility.md`.

If the current-state block forbids an action, it stays forbidden until the owner authorizes that specific action, even if an older paragraph elsewhere seems to allow it.

## Hard rules

- **Authorization:** the owner authorized read-only runs and reversible persistent iPad changes for this port, each recorded in the cleanup ledger before or as it is made. Before any iPad write or process launch, state its risk to device data, stability, and SSH/USB access; require an exact target, a way to inspect the result, and a plausible reversal. No authorization extends to other devices or destructive system changes.
- **USB controller:** do not call `SetDescription`, bus cycles, force-off, `restore`, confirm/clear/delete a journal, or reboot headlessly unless the current-state block and the owner explicitly allow that exact action. API success or `awaitingVerification` is not USB recovery; only external Mac checks prove it. Never send a confirmation receipt for a failed trial.
- **Privacy:** never print, paste, or commit the Wi-Fi address, device IDs/UDIDs, serials, private keys, raw host pins, raw profiles, or unredacted reports. Private evidence goes only under ignored `build/ipad-hardware/`; Git gets hashes and redacted conclusions.
- **Pinned SSH only:** use the identity and known-hosts pin in `/Users/boolean/.ssh/mac2jb-ipad/` via the repo host runners. Never `StrictHostKeyChecking=no`, agent/default keys, or an unpinned target.
- **Sandbox false negatives:** a restricted sandbox can falsely report SSH, usbmux, or local-network failure. Rerun the same read-only check with normal host/network permission before treating it as device evidence.
- **Leave the host USB stack alone:** do not quit ChatGPT, restart `usbmuxd`, kill a USB client, change USB configuration, reset the whole Mac host controller, or guess a hub port merely to make a probe run.
- **Pinning failure stops work:** if discovery or host-key pinning fails, stop; never accept a new host key or fall back to default identities.
- **System plists:** verify the live `ClientTruth.plist` against its private backup before and after any install or cleanup; never blindly replace a concurrently changed system plist.
- **Scripts:** put every device payload and host runner under `docs/plans/ipad-port/scripts/ipad-hardware/` with a plain-language effect description. Do not paste large one-off programs into NewTerm. Prefer Go for new host scripts when it fits; keep working attested Python/Swift scripts unless a concrete need justifies change. Bound output and runtime.
- **Physical facts are owner-observed:** cable side (no-logo = A, logo = B), peer (Mac vs Switch 2), and power are owner inputs. Charging or a raw IOUSB node does not prove a USB data connection; Wi-Fi access proves nothing about USB role. Choose a new evidence label only after side and power are observed. Switch 1 observations never substitute for Switch 2 rows.
- **Evidence names:** never reuse an existing evidence label or overwrite private evidence; never reinstall, refresh icon caches, or remove SSH keys merely to retry.
- **Reviews:** the owner dropped mandatory adversarial reviews; still verify each command's effect yourself.
- **Stalled investigation:** follow `AGENTS.md` - get a fresh-agent second opinion (read-only on the device) before repeating an experiment or declaring no solution, then verify its claims and record them in the docs.
- **Record results in docs, not here:** after any device action, update the findings Current state block, the runbook if procedure changed, and the ledger for persistent changes.

## Connect

1. `python3 docs/plans/ipad-port/scripts/ipad-hardware/host/check-pinned-wireless-ssh.py` - require `pinned-inputs=ok`, `mobile=ok`, `root=ok`. Pinned Wi-Fi SSH is the default control channel.
2. Address missing or stale: `python3 docs/plans/ipad-port/scripts/ipad-hardware/host/discover-pinned-ipad-wifi.py` (passive Bonjour, fails closed on ambiguity or host-key mismatch, prints no address).
3. USB only when the task needs usbmux: `python3 docs/plans/ipad-port/scripts/ipad-hardware/host/diagnose-usb-recognition.py`; require `USBMUX query=ok count=1` before `host/start-usb-ssh-tunnel.sh` on `127.0.0.1:2222`. Check for an existing listener first (`lsof -nP -iTCP:2222 -sTCP:LISTEN`) and never displace it.
4. Confirm the exact target with the pinned key plus any task-specific device check, then run only documented repo scripts.

## When a trial loses Mac USB

Owner policy: try a restore over pinned Wi-Fi SSH before asking for a restart.

1. `python3 docs/plans/ipad-port/scripts/ipad-hardware/host/recover-u2-over-wifi.py` - one shot. It refuses unless SSH works, the Mac sees no iPad, and the controller is unconfigured. It runs `backup-u2-wifi-restore-kit.py` first (failed journal and every U2 file, byte-exact, into a private kit), captures the failed-state reference set, then sends exactly one broker request (`restore-after-failure`, or `restore` on older brokers in `recoveryRequired`) with the passive Mac observer armed, and captures again.
2. Never confirm or clear the journal from that result; run the full external check first. Do not rerun the runner on the same boot after a failed attempt.
3. If USB does not return, read the recorded `syslog.txt` for `register function` lines. If functions are unregistered, run `host/recover-u2-until-registered-wifi.py` (bounded re-publication) until only user-space-owned functions remain, then `host/recover-u2-restart-function-owner-wifi.py com.apple.audiomxd` for Valeria/audio. This recovered USB without a reboot once; see the runbook.
4. If USB still does not return, record it and ask the owner for a restart/re-jailbreak; on the new boot, run the healthy reference capture and a fresh `backup-u2-wifi-restore-kit.py` before any new trial.

## Common mistakes

| Mistake | Correct reading |
|---|---|
| Acting on an older "stop point" paragraph | Only the findings Current state block is current |
| Controller API returned success, so USB is back | Require Mac USBMux/raw USB/NCM/pairing/power checks |
| Charging, so data is connected | Power and data are independent; check controller `OnBus` and Mac USBMux |
| Sandboxed check failed, so the iPad is broken | Rerun with normal permissions first |
| Retrying a failed same-boot recovery call | Never repeat a call the docs say failed on this boot |
| Writing status into this skill | Status goes in `target-device-findings.md` |

## Reference

- `references/cli.md` - Mac and iPad CLIs, their pinned usage, and known limits.
