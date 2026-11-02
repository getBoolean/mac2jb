#!/usr/bin/env python3
"""Mac-only fixture for the U2 USB/network target and pairing gate."""

from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BASELINE = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))
CHECKER = runpy.run_path(str(HOST / "check-u2-strict-external.py"))
USB = b"0123456789abcdef0123456789abcdef01234567"
OTHER = b"fedcba9876543210fedcba9876543210fedcba98"
ID = "/opt/homebrew/bin/idevice_id"
PAIR = "/opt/homebrew/bin/idevicepair"


def case(usb_ids, network_ids, expected, fail_pair=None):
    calls = []

    def checked(command, timeout=12):
        calls.append(command)
        if command == [ID, "-l"]:
            return usb_ids
        if command == [ID, "-n"]:
            return network_ids
        if command[0] == PAIR:
            if command == fail_pair:
                raise ValueError("pairing failed")
            return b"SUCCESS\n"
        raise AssertionError("unexpected command")

    trusted = BASELINE["trusted_usb"]
    trusted.__globals__["checked"] = checked
    try:
        count = trusted()
    except ValueError:
        if expected is not None:
            raise AssertionError("valid target rejected")
        assert all(command[0] != PAIR for command in calls) or fail_pair is not None
        return
    if expected is None or count != expected:
        raise AssertionError("unsafe target accepted")
    assert calls == [
        [ID, "-l"], [ID, "-n"],
        [PAIR, "-u", USB.decode("ascii"), "validate"],
        [PAIR, "-n", "-u", USB.decode("ascii"), "validate"],
    ]


def main():
    # The current checker must use this same target-pinned gate.
    trust = CHECKER["trust"]
    trust.__globals__["SNAPSHOT"] = {"trusted_usb": lambda: 2}
    trust()
    case(USB + b"\n", USB + b"\n" + OTHER + b"\n", 2)
    case(USB + b"\n", OTHER + b"\n", None)
    case(USB + b"\n", USB + b"\n" + USB + b"\n", None)
    case(USB + b"\n", USB + b"\ninvalid!\n", None)
    case(USB + b"\n" + OTHER + b"\n", USB + b"\n", None)
    case(USB + b"\n", USB + b"\n", None,
         fail_pair=[PAIR, "-u", USB.decode("ascii"), "validate"])
    case(USB + b"\n", USB + b"\n", None,
         fail_pair=[PAIR, "-n", "-u", USB.decode("ascii"), "validate"])
    print("PASS U2 target-pinned USB/network pairing guards")


if __name__ == "__main__":
    main()
