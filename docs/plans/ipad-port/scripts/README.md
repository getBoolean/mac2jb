# iPad port scripts

All iPad hardware host tools, on-device probes, and Mac-only tests live in [ipad-hardware](ipad-hardware/). Run host tools from the repository root so their fixed `build/ipad-hardware/`, `ios/`, and documentation paths resolve as intended.

The old `scripts/ipad-hardware` path is a relative compatibility symlink to this directory. Existing command receipts and documentation may use that path; the source files are stored here. New references should use `docs/plans/ipad-port/scripts/ipad-hardware/`.

Read the current stop point in `docs/ipad/usb-recovery.md` and the repository iPad skill before running any tool against the target. An executable probe can be read-only even when its host wrapper writes private evidence on the Mac; verify each command's effect before using it on the iPad.
