# Agent workflow

For iPad port hardware work, use the repository skill at `.agents/skills/ipad-port-headless/SKILL.md`. It contains the pinned connection CLIs, current device stop point, evidence paths, and cleanup constraints. Read the latest entries in `docs/ipad/target-device-findings.md` and `docs/ipad/usb-recovery.md` before acting on the device.

When an investigation stalls after checking the available evidence, ask a **fresh agent** for an independent second opinion before repeating an experiment or concluding that the issue has no solution. Give the agent the current objective, repo paths, observed results, and safety constraints, but no inherited analysis or preferred diagnosis. Ask it to look for missed evidence, test competing explanations, and identify the smallest discriminating next check.

For iPad hardware work, keep the second opinion read-only on the device unless the user has authorized a specific later action. Record its findings, corrections, and remaining uncertainty in the iPad findings and recovery documents. Do not treat a second opinion as proof without checking it against source, retained evidence, and a bounded observation.
