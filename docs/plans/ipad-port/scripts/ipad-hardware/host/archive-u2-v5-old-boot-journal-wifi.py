#!/usr/bin/env python3
"""Guarded v5 failed-journal archival after full new-boot recovery proof.

`--inspect` reads only. `--archive` first rechecks the complete external
USB/NCM/pairing/power state and exact durable Mac backup, then runs the pinned
v5 device helper. That helper boots out only the exact stopped watchdog jobs,
links the old-boot journal to its fixed archive name, fsyncs and removes only
the active name. This host runner verifies the archive and full external state
again. Neither mode invokes a USB controller API or starts a new trial.
"""

import hashlib
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-archive-v5-old-boot-journal.py"
SOURCE_SHA = "b21b2fb68a4c6bb18c8b48d596075943c2b754e3bfbc8f9a94646dc23fba00e3"
CHECKER = HOST / "check-u2-post-v5-reboot.py"
CHECKER_SHA = "a2d65fdf4d8d419e05badcc03fa42f858e12417464380e5d2418e5063aca24ef"
BACKUP = ROOT / "build/ipad-hardware/u2-v5-oldboot-archive/restore-journal.oldboot-v5.json"
JOURNAL_SHA = "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"
RECOVERED = (b"U2_POST_V5_REBOOT boot=new live=original configs=5 resolved-strings=23 "
             b"renumbered=12 interfaces=equal scalars=equal network-binding=equal "
             b"network-packet=reply usbmux=one pairing=valid power=charging-or-full "
             b"journal=retained-exact\n")
ARCHIVED = RECOVERED.replace(b"journal=retained-exact", b"journal=archived-active-absent")
STAGE = "initial"


def exact_source(path, digest, limit):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= limit):
        raise ValueError("source metadata changed")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source digest changed")
    return data


def verify_backup():
    folder = BACKUP.parent
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            {p.name for p in folder.iterdir()} != {BACKUP.name}):
        raise ValueError("backup directory changed")
    info = BACKUP.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= 2_000_000 or
            hashlib.sha256(BACKUP.read_bytes()).hexdigest() != JOURNAL_SHA):
        raise ValueError("Mac backup changed")


def external(archived=False):
    args = ["/usr/bin/python3", str(CHECKER)]
    if archived:
        args.append("--archived")
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=60)
    if result.returncode or result.stdout != (ARCHIVED if archived else RECOVERED):
        raise ValueError("external recovery changed")


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
    expected = {
        "--inspect": b"U2_V5_OLD_JOURNAL inspect=ready jobs=known socket=owned journal=exact old-archives=retained\n",
        "--archive": b"U2_V5_OLD_JOURNAL archive=retained active=absent jobs=booted-out old-archives=retained\n",
        "--verify": b"U2_V5_OLD_JOURNAL archive=verified active=absent jobs=absent old-archives=retained\n",
    }[mode]
    if result.returncode or result.stdout != expected:
        raise ValueError("remote archive state changed")


def main():
    global STAGE
    if len(sys.argv) != 2 or sys.argv[1] not in ("--inspect", "--archive"):
        raise ValueError("fixed mode required")
    payload = exact_source(SOURCE, SOURCE_SHA, 32 * 1024)
    exact_source(CHECKER, CHECKER_SHA, 16 * 1024)
    STAGE = "backup"
    verify_backup()
    STAGE = "preflight"
    external()
    remote("--inspect", payload)
    if sys.argv[1] == "--inspect":
        print("U2_V5_OLD_JOURNAL inspect=ready mac-backup=exact external=postreboot-equal usb-write=none")
        return
    STAGE = "second-preflight"
    external()
    remote("--inspect", payload)
    STAGE = "archive"
    remote("--archive", payload)
    STAGE = "verify"
    remote("--verify", payload)
    external(archived=True)
    verify_backup()
    print("U2_V5_OLD_JOURNAL archived=verified mac-backup=durable external=equal usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V5_OLD_JOURNAL rejected stage=" + STAGE + "; inspect device and backup")
        raise SystemExit(1)
