#!/usr/bin/env python3
"""Back up and archive the failed v2 old-boot journal after full recovery.

This first requires the independent read-only postreboot USB/NCM/SSH/power
comparison and exact running v2 service status. It streams the exact journal
to a new exclusive owner-only Mac backup and fsyncs both files and directory.
Only then does the pinned device helper boot out the v2 and old disabled jobs,
hard-link the journal to its fixed old-boot archive name, fsync, unlink the
active name, and fsync. It makes no USB controller call and keeps both the
earlier failed-trial archive and the new v2 bytes on Mac and iPad. A failure
leaves evidence for inspection; it never silently retries a controller write.
"""

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-archive-v2-old-boot-journal.py"
SOURCE_SHA256 = "5d5a177e2990aa426a556dd0f102716329993522b11fe57fc856501b71f880ce"
COPY_HELPER_SHA256 = "9d80538c8c2cea0038cc52f46b8cbff6beb53b9132f75a04519b9354a73cb4df"
CHECKER = HOST / "check-u2-post-v2-reboot.py"
CHECKER_SHA256 = "34f27f07d69f7e0bf57e0204d2b80589c6e236080db9c5d6c68c7a7e0b0405d6"
EXPECTED_JOURNAL = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"
DEST = ROOT / "build/ipad-hardware/u2-v2-oldboot-archive"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
EXPECTED_CHECK = (b"U2_POST_V2_REBOOT boot=new live=original configs=5 "
                  b"resolved-strings=23 renumbered=14 interfaces=equal "
                  b"scalars=equal network-binding=equal network-packet=reply "
                  b"usbmux=one pairing=valid power=charging-or-full "
                  b"journal=retained-exact\n")
EXPECTED_STATUS = (b"U2_V2_POSTREBOOT job=running binary=regular plist=regular "
                   b"socket=socket phase=awaitingVerification "
                   b"original-job=")
STAGE = "initial"


def checked(path, digest, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError("unsafe source")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source changed")
    return data


def command(args, maximum=1024, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout)
    if result.returncode or len(result.stdout) > maximum:
        raise ValueError("read-only preflight unavailable")
    return result.stdout


def preflight():
    global STAGE
    parent_stage = STAGE
    checked(CHECKER, CHECKER_SHA256, 16 * 1024)
    STAGE = parent_stage + "-external"
    if command(["/usr/bin/python3", str(CHECKER)], timeout=50) != EXPECTED_CHECK:
        raise ValueError("postreboot external state changed")
    STAGE = parent_stage + "-service"
    status = command(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"),
            "--v2-postreboot"])
    if status not in (EXPECTED_STATUS + b"loaded-stopped\n",
                      EXPECTED_STATUS + b"running\n",
                      EXPECTED_STATUS + b"absent\n"):
        raise ValueError("v2 watchdog state changed")
    STAGE = parent_stage + "-journal"
    if command(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"),
            "--native-journal"]) != (
            "U2_NATIVE_JOURNAL phase=awaitingVerification sha256=" +
            EXPECTED_JOURNAL + "\n").encode("ascii"):
        raise ValueError("v2 journal changed")
    STAGE = parent_stage


def ssh(mode, payload, maximum):
    address = WIRELESS["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((HELPER["IDENTITY"], HELPER["IDENTITY_SHA256"]),
                         (HELPER["KNOWN_HOSTS"], HELPER["KNOWN_HOSTS_SHA256"])):
        HELPER["checked_local"](path, digest, 0o600)
    args = ["/usr/bin/ssh", *HELPER["ssh_options"](),
            "-o", "HostKeyAlias=" + WIRELESS["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22",
            "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", mode]
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=25)
    if result.returncode or not 0 < len(result.stdout) <= maximum:
        prefix = b"U2_V2_OLD_JOURNAL rejected reason="
        if result.stderr.startswith(prefix) and len(result.stderr) < 160:
            reason = result.stderr[len(prefix):].strip().decode("ascii", "ignore")
            known = {
                "journal is not from an old boot", "stock source changed",
                "journal phase changed", "journal digest changed",
                "journal checksum changed", "trial job state changed",
                "v2 socket changed", "v2 phase changed",
                "v2 binary metadata changed", "v2 binary digest changed",
                "v2 plist metadata changed", "v2 plist changed",
                "unsafe state directory", "unsafe journal metadata",
                "system-query",
            }
            if reason in known:
                print("U2_V2_OLD_JOURNAL remote-reason=" + reason.replace(" ", "-"))
        raise ValueError("v2 archive remote step failed")
    return result.stdout


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private backup write")
        os.fsync(fd)
    finally:
        os.close(fd)


def backup_metadata():
    return json.dumps({
        "version": 1, "journal_sha256": EXPECTED_JOURNAL,
        "helper_sha256": COPY_HELPER_SHA256,
        "checker_sha256": CHECKER_SHA256,
        "recovery": "postreboot-only",
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def archive_metadata():
    return json.dumps({
        "version": 1, "journal_sha256": EXPECTED_JOURNAL,
        "archive_helper_sha256": SOURCE_SHA256,
        "copy_helper_sha256": COPY_HELPER_SHA256,
        "checker_sha256": CHECKER_SHA256,
        "recovery": "postreboot-only",
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def verified_backup():
    info = DEST.lstat()
    names = set(x.name for x in DEST.iterdir())
    base_names = {"restore-journal.oldboot-v2.json", "backup.json"}
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            names not in (base_names, base_names | {"archive-helper.json"})):
        raise ValueError("unsafe existing backup")
    expected_files = [("restore-journal.oldboot-v2.json", EXPECTED_JOURNAL),
                      ("backup.json", hashlib.sha256(backup_metadata()).hexdigest())]
    if "archive-helper.json" in names:
        expected_files.append(("archive-helper.json", hashlib.sha256(archive_metadata()).hexdigest()))
    for name, expected in expected_files:
        path = DEST / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError("existing backup changed")


def main():
    global STAGE
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if len(sys.argv) != 2 or mode not in ("--resume-preflight", "--resume", "--copy-only"):
        raise ValueError("invalid mode")
    payload = checked(SOURCE, SOURCE_SHA256, 16 * 1024)
    verified_backup()
    if mode != "--copy-only":
        STAGE = "preflight"
        preflight()
    STAGE = "copy"
    journal = ssh("--copy", payload, 2_000_000)
    if hashlib.sha256(journal).hexdigest() != EXPECTED_JOURNAL:
        raise ValueError("v2 backup digest changed")
    if mode == "--copy-only":
        print("U2_V2_OLD_JOURNAL copy=exact backup=durable")
        return
    if mode == "--resume-preflight":
        print("U2_V2_OLD_JOURNAL preflight=ready external=postreboot-equal "
              "journal=exact service=known")
        return
    STAGE = "archive-metadata"
    if not (DEST / "archive-helper.json").exists():
        exclusive(DEST / "archive-helper.json", archive_metadata())
        fd = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    verified_backup()
    # The Mac backup is durable; recheck external state before any iPad change.
    STAGE = "second-preflight"
    preflight()
    STAGE = "archive"
    if ssh("--archive", payload, 256) != (
            b"U2_V2_OLD_JOURNAL archive=retained active=absent "
            b"trial=booted-out first-archive=retained\n"):
        raise ValueError("v2 device archive changed")
    STAGE = "verify"
    if ssh("--verify", payload, 256) != (
            b"U2_V2_OLD_JOURNAL archive=verified active=absent "
            b"trial=absent first-archive=retained\n"):
        raise ValueError("v2 device archive verification failed")
    if command(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"),
            "--native-journal"]) != b"U2_NATIVE_JOURNAL phase=absent sha256=none\n":
        raise ValueError("active journal still present")
    print("U2_V2_OLD_JOURNAL archived=verified mac-backup=durable "
          "trial=booted-out active=absent usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V2_OLD_JOURNAL rejected stage=" + STAGE +
              "; inspect backup and device state")
        raise SystemExit(1)
