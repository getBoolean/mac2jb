#!/usr/bin/env python3
"""Compile and run the Mac-only USB function-registration healer policy tests."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[6]


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u2-healer-") as temporary:
        binary = Path(temporary) / "healer-tests"
        env = dict(os.environ, CLANG_MODULE_CACHE_PATH=temporary + "/clang",
                   SWIFT_MODULE_CACHE_PATH=temporary + "/swift")
        subprocess.run(["/usr/bin/xcrun", "swiftc",
                        str(ROOT / "ios/watchdog/USBFunctionRegistrationHealer.swift"),
                        str(ROOT / "ios/tests/USBFunctionRegistrationHealerTests.swift"),
                        "-o", str(binary)], check=True, env=env, timeout=120)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        print(result.stdout.strip() or result.stderr.strip())
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
