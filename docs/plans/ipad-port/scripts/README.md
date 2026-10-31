# iPad port scripts

All iPad hardware host tools, on-device probes, and Mac-only tests live in [ipad-hardware](ipad-hardware/). Run host tools from the repository root so their fixed `build/ipad-hardware/`, `ios/`, and documentation paths resolve as intended.

The former `scripts/ipad-hardware` compatibility symlink was removed on 2026-10-31; every script and document now uses `docs/plans/ipad-port/scripts/ipad-hardware/`. Historical receipts may still name the old path.

Read the current stop point in `docs/ipad/usb-recovery.md` and the repository iPad skill before running any tool against the target. An executable probe can be read-only even when its host wrapper writes private evidence on the Mac; verify each command's effect before using it on the iPad.
