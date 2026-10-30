#!/var/jb/usr/bin/python3
"""Check whether the attested toolbox baseline reaches its argument parser.

What this code does: locate one installed toolbox, verify one selected exact
attested executable SHA-256, then launch it with no arguments under a five
second deadline. The audited stdout-only program must reject missing
arguments before any IOKit work or file write. Only a status category is
printed; raw stdout, stderr, paths, and device values are discarded. It
neither creates a device file nor changes USB/SSH configuration.
"""

import glob
import hashlib
import os
import subprocess
import sys


PATTERNS = ("/var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app",
            "/Applications/Mac2JBU1-Toolbox.app",
            "/var/jb/Applications/Mac2JBU1-Toolbox.app")
VARIANTS = {
    "baseline": "mac2jb-u1-baseline",
    "setdescription": "Probes/mac2jb-u1-setdescription",
    "controller-client": "Probes/mac2jb-u1-controller-client",
    "interface-client": "Probes/mac2jb-u1-interface-client",
}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in VARIANTS or len(sys.argv[2]) != 64:
        raise SystemExit(64)
    paths = [p for pattern in PATTERNS for p in glob.glob(pattern)]
    if len(paths) != 1:
        raise SystemExit(65)
    executable = paths[0] + "/" + VARIANTS[sys.argv[1]]
    if os.path.islink(executable):
        raise SystemExit(66)
    digest = hashlib.sha256()
    with open(executable, "rb") as file:
        while True:
            chunk = file.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != sys.argv[2]:
        raise SystemExit(67)
    try:
        result = subprocess.run([executable], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5)
        status = str(result.returncode)
    except subprocess.TimeoutExpired:
        status = "timeout"
    print("TOOLBOX_STARTUP variant=" + sys.argv[1] + " status=" + status)


if __name__ == "__main__":
    main()
