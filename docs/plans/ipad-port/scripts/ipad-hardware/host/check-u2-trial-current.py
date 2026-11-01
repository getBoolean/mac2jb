#!/usr/bin/env python3
"""Full read-only external USB check against the current-boot trial baseline.

Effect: runs the strict codex checker (check-u2-strict-external.py main) pinned to
build/ipad-hardware/u2-v9-trial-baseline/ (manifest SHA-256 below): live
description original or original plus AllowMultipleCreates, all five raw USB
configurations with semantically equal resolved strings, host interfaces,
device scalars, NCM driver binding and packet reply, USBMux/pairing, power and
the expected journal phase. Prints the checker's one-line verdict.
Usage: --expect-journal=absent|awaitingVerification
"""

from contextlib import redirect_stdout
import io
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-v9-trial-baseline"
MANIFEST_SHA256 = "556f0c9c3b48eb1e73a7caffcd4849d8bbbdcb0708a4511fad7ad5cc06a93e73"


def check(phase):
    checker = runpy.run_path(str(HOST / "check-u2-strict-external.py"))
    checker["main"].__globals__["BASE"] = BASE
    checker["main"].__globals__["MANIFEST_SHA256"] = MANIFEST_SHA256
    output = io.StringIO()
    with redirect_stdout(output):
        checker["main"](phase)
    return output.getvalue()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or not sys.argv[1].startswith("--expect-journal="):
            raise ValueError("usage: --expect-journal=absent|awaitingVerification")
        print(check(sys.argv[1].split("=", 1)[1]), end="")
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print("U2_V9_CURRENT rejected (%s)" % error)
        raise SystemExit(1)
