#!/usr/bin/env python3
"""Stage and verify one signed U1 toolbox IPA over pinned root USB SSH.

What this code does: verify the exact local artifact and durable SSH files,
run the read-only absence/helper preflight, SCP the IPA to one fixed Media
path, then run a read-only on-device digest check. It never runs the IPA.
The stage path is recorded in the device cleanup ledger, including the
possibility of a partial file if transfer stops early.
"""

import hashlib
from pathlib import Path
import runpy
import subprocess


HERE = Path(__file__).resolve().parent
backup = runpy.run_path(str(HERE / "backup-clienttruth-over-root-ssh.py"))
ROOT = backup["ROOT"]
ARTIFACT = ROOT / "build/ipad-hardware/mac2jb-u1-stdout-toolbox.tipa"
PREFLIGHT = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-toolbox-install-preflight.py"
VERIFY = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-staged-toolbox-digest.py"
DEST = "/var/mobile/Media/.mac2jb-u1-stdout-toolbox.tipa"
SHA256 = "c97a5d9f60a67329b3b1946e478e95f1afc903d51a7cb7902d8dbdc9a4309f13"
EXPECTED = (b"TOOLBOX_PREFLIGHT trollstore=one\n"
            b"TOOLBOX_PREFLIGHT helper=executable\n"
            b"TOOLBOX_PREFLIGHT toolbox=absent\n"
            b"TOOLBOX_PREFLIGHT staged=absent\n")


def remote(source):
    command = ["/usr/bin/ssh", *backup["ssh_options"](), "-T", "-p", "2222",
               "root@127.0.0.1", "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=source.read_bytes(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15)
    backup["require"](result.returncode == 0 and len(result.stdout) < 1024,
                      "device query failed")
    return result.stdout


def main():
    backup["checked_local"](backup["IDENTITY"], backup["IDENTITY_SHA256"], 0o600)
    backup["checked_local"](backup["KNOWN_HOSTS"], backup["KNOWN_HOSTS_SHA256"], 0o600)
    data = ARTIFACT.read_bytes()
    backup["require"](hashlib.sha256(data).hexdigest() == SHA256,
                      "local toolbox digest mismatch")
    backup["require"](remote(PREFLIGHT) == EXPECTED,
                      "install preflight failed")
    command = ["/usr/bin/scp", *backup["ssh_options"](), "-P", "2222",
               str(ARTIFACT), "root@127.0.0.1:" + DEST]
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=30)
    backup["require"](result.returncode == 0, "toolbox transfer failed; inspect staged path")
    expected = ("TOOLBOX_STAGE size=" + str(len(data)) + " sha256=" + SHA256 + "\n").encode()
    backup["require"](remote(VERIFY) == expected,
                      "staged toolbox digest mismatch")
    print("TOOLBOX_STAGE verified " + DEST)


if __name__ == "__main__":
    main()
