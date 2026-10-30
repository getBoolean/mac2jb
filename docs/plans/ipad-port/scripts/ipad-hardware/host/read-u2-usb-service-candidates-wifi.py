#!/usr/bin/env python3
"""Run the exact read-only USB service classifier over pinned root Wi-Fi SSH."""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-usb-service-candidates.py"
SHA = "f04fee4151ebf25a5ef079edc91ac7f7292eac4a770e3fbb16ba8e8d274ff695"
LINE = re.compile(rb"U2_USB_(?:SERVICE|PROCESS) [A-Za-z0-9_.-]{1,110}\n")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
        raise ValueError("unsafe source")
    data = SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError("source changed")
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
               "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address,
               "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or len(result.stdout) > 8192:
        raise ValueError("device inventory failed")
    lines = result.stdout.splitlines(keepends=True)
    if not lines or not re.fullmatch(rb"U2_USB_SERVICES count=([0-9]|[1-7][0-9]|80)\n",
                                     lines[0]):
        raise ValueError("invalid service count")
    count = int(lines[0].split(b"=")[1])
    if len(lines) < count + 1 or not all(
            LINE.fullmatch(line) and line.startswith(b"U2_USB_SERVICE ")
            for line in lines[1:count + 1]):
        raise ValueError("invalid service labels")
    rest = lines[count + 1:]
    if not rest or not re.fullmatch(rb"U2_USB_PLISTS count=([0-9]|[1-7][0-9]|80)\n", rest[0]):
        raise ValueError("invalid plist count")
    plist_count = int(rest[0].split(b"=")[1])
    if len(rest) < plist_count + 1 or not all(
            re.fullmatch(rb"U2_USB_PLIST [A-Za-z0-9_.-]{1,110}\n", line)
            for line in rest[1:plist_count + 1]):
        raise ValueError("invalid plist names")
    rest = rest[plist_count + 1:]
    if rest:
        if not re.fullmatch(rb"U2_USB_PROCESSES count=([0-9]|[1-7][0-9]|80)\n", rest[0]):
            raise ValueError("invalid process count")
        process_count = int(rest[0].split(b"=")[1])
        if len(rest) != process_count + 1 or not all(
                LINE.fullmatch(line) and line.startswith(b"U2_USB_PROCESS ")
                for line in rest[1:]):
            raise ValueError("invalid process names")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        print("U2_USB_SERVICES rejected")
        raise SystemExit(1)
