# iPad port hardware docs

**Experiment closed as failed, 2026-11-02.** The reference device never
enumerated as a USB HID keyboard through the tested userspace approach. The
kernel route stopped at source eligibility, and subsequent device gates remain
unexecuted. These documents and tools are retained as research and recovery
records. Installed device tooling is still listed in the cleanup ledger;
closing the experiment did not uninstall it.

Start here before any work on an iPad or iPhone for the port.

1. [target-device-findings.md](target-device-findings.md): **Current state** (the single source of truth for what is true now), the reference device, what is proven, durable lessons, and private evidence locations.
2. [usb-recovery.md](usb-recovery.md): the operating runbook. Connect, run trials, recover lost USB, replace the broker.
3. [usb-auto-recovery.md](usb-auto-recovery.md): why USB drops after a description swap, how the broker heals it, the on-device learned device profile, and how to embed this in the TrollStore app or a jailbreak tweak.
4. [device-cleanup-ledger.md](device-cleanup-ledger.md): everything the port has left on the device and the Mac, with cleanup conditions.
5. [hardware-matrix.md](hardware-matrix.md): redacted gate decisions (U1 and U2 passed; userspace HID failed; kernel source gate failed; later gates not run).

Plans: `docs/plans/ipad-port/00-roadmap.md` (whole port) and `01-hardware-feasibility.md` (hardware gates). Tools: `docs/plans/ipad-port/scripts/README.md`. Procedure for agents: `.agents/skills/ipad-port-headless/SKILL.md` and `AGENTS.md`.

These docs were condensed on 2026-10-31. Dated investigation logs, superseded stop points and historical tool references are in git history only. If something here conflicts with an older note, these docs win.
