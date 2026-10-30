#!/var/jb/usr/bin/python3
"""Ask SpringBoard to launch the attested U1 toolbox by exact bundle ID.

What this code does: confirm one installed toolbox bundle and the exact
attested baseline executable SHA-256, then invoke the installed uiopen CLI
once with `dev.mac2jb.u1probe.toolbox`. The app receives no arguments; its
audited code must reject missing options before inventory or IOKit work.
It prints only uiopen's exit and fixed output categories, not raw logs.

This activates an app and may create transient app/launcher state. It does
not modify SSH/USB configuration or system files. The installed app and any
data container remain tracked in docs/ipad/device-cleanup-ledger.md.
"""

import glob
import hashlib
import os
import subprocess
import sys


APP_ID = "dev.mac2jb.u1probe.toolbox"
PATTERNS = ("/var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app",
            "/Applications/Mac2JBU1-Toolbox.app",
            "/var/jb/Applications/Mac2JBU1-Toolbox.app")


def main():
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64:
        raise SystemExit(64)
    matches = [p for pattern in PATTERNS for p in glob.glob(pattern)]
    if len(matches) != 1:
        raise SystemExit(65)
    executable = matches[0] + "/mac2jb-u1-baseline"
    if os.path.islink(executable):
        raise SystemExit(66)
    digest = hashlib.sha256()
    with open(executable, "rb") as file:
        while True:
            chunk = file.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != sys.argv[1]:
        raise SystemExit(67)
    try:
        result = subprocess.run(["/var/jb/usr/bin/uiopen", APP_ID],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10)
        output = (result.stdout + result.stderr)[:2048].lower()
        print("UIOPEN_LAUNCH status=" + str(result.returncode))
        print("UIOPEN_LAUNCH failure-word=" +
              ("yes" if any(term in output for term in
                            (b"fail", b"error", b"unable")) else "no"))
    except subprocess.TimeoutExpired:
        print("UIOPEN_LAUNCH status=timeout")


if __name__ == "__main__":
    main()
