#!/usr/bin/env python3
"""Clean exact archived v4/v5 trial stages after the verified v5 archive.

Inspect and verify modes are read-only. Clean mode rechecks four journal archives, absent
active journal and jobs, exact Mac backup, full external USB/NCM recovery,
trial binaries/plists, and the stale socket before removing those five exact
trial paths. The publication-disabled base package remains installed. The
device helper neither opens nor calls a USB controller.
"""

import hashlib
from pathlib import Path
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-clean-v4-v5-archived-trials.py"
SOURCE_SHA = "e3fe4be8283faaf90f07394c53a06997dc28de6454957b6e24e9b5c975ed430d"
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-v5-old-boot-journal-wifi.py"))
STAGE = "initial"


def remote(mode, payload):
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", mode]
    result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=25)
    if result.returncode or len(result.stdout) > 256:
        raise ValueError("remote cleanup state changed")
    return result.stdout


def preflight(require_trial_stage=True):
    ARCHIVE["verify_backup"]()
    if require_trial_stage:
        source = ARCHIVE["exact_source"](ARCHIVE["SOURCE"], ARCHIVE["SOURCE_SHA"], 32 * 1024)
        ARCHIVE["remote"]("--verify", source)
    ARCHIVE["external"](archived=True)


def main():
    global STAGE
    if len(sys.argv) != 2 or sys.argv[1] not in ("--inspect", "--clean", "--verify"):
        raise ValueError("fixed mode required")
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16 * 1024:
        raise ValueError("unsafe cleanup source")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA:
        raise ValueError("cleanup source changed")
    expected = b"U2_V4V5_CLEAN stages=absent socket=absent archives=exact jobs=absent base=retained\n"
    if sys.argv[1] == "--verify":
        STAGE = "verify"
        if remote("--verify", payload) != expected:
            raise ValueError("cleanup verification failed")
        preflight(require_trial_stage=False)
        print("U2_V4V5_CLEAN verified trial-stages=removed archives=retained base=retained external=equal usb-write=none")
        return
    STAGE = "preflight"
    preflight()
    inspect = remote("--inspect", payload)
    if inspect not in (
            b"U2_V4V5_CLEAN inspect=ready socket=stale archives=exact jobs=absent base=retained\n",
            b"U2_V4V5_CLEAN inspect=ready socket=absent archives=exact jobs=absent base=retained\n"):
        raise ValueError("trial stage changed")
    if sys.argv[1] == "--inspect":
        print("U2_V4V5_CLEAN inspect=ready archives=exact external=equal usb-write=none")
        return
    STAGE = "second-preflight"
    preflight()
    if remote("--inspect", payload) != inspect:
        raise ValueError("trial stage changed")
    STAGE = "cleanup"
    if remote("--clean", payload) != expected:
        raise ValueError("cleanup result changed")
    STAGE = "verify"
    if remote("--verify", payload) != expected:
        raise ValueError("cleanup verification failed")
    preflight(require_trial_stage=False)
    print("U2_V4V5_CLEAN verified trial-stages=removed archives=retained base=retained external=equal usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V4V5_CLEAN rejected stage=" + STAGE + "; inspect exact paths")
        raise SystemExit(1)
