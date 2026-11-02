#!/usr/bin/env python3
"""Advance a healed U2 journal and confirm it only after external checks pass.

Effect: sends `heal` to the broker (records awaitingVerification when the
controller is already configured; never publishes while configured), then
requires: Mac USBMux one device at configuration 5, `idevicepair validate`,
XDCI configured with BcdUSBVersion/MPS0 784/9, and a function census equal
(ID-independent) to the private healthy reference. Saves the evidence
privately and sends `confirm <sha256(evidence)>`. Refuses at any failure.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
REFERENCE = sorted((ROOT / "build/ipad-hardware/u2-function-census").glob("healthy-boot-*/xdci-function-census-1.txt"))[-1]
ASK = ('import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(120);'
       's.connect("/var/jb/var/lib/mac2jb-u2-native/broker.sock");'
       's.sendall(sys.argv[1].encode()+b"\\n");print(s.recv(512).decode().strip())')


def run(argv, timeout=90):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    return result.returncode, result.stdout


def normalized(text):
    return sorted(re.sub(r" i=\d+ parent=-?\d+", "", line) for line in text.splitlines())


def main():
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    def ask(command):
        code, out = run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(ASK) + " " +
                         shlex.quote(command)], 150)
        return out.decode().strip()
    print("heal:", ask("heal"))
    if ask("status") != "OK phase=awaitingVerification publication=enabled":
        raise ValueError("journal not awaitingVerification after heal")
    evidence = []
    code, usb = run([sys.executable, str(HOST / "diagnose-usb-recognition.py")])
    if b"USBMUX query=ok count=1\n" not in usb:
        raise ValueError("Mac USB not healthy")
    evidence.append(usb)
    ids = run(["/opt/homebrew/bin/idevice_id", "-l"])[1].split()
    if len(ids) != 1 or run(["/opt/homebrew/bin/idevicepair", "validate", "-u", ids[0].decode()])[0]:
        raise ValueError("pairing not valid")
    evidence.append(b"pairing=valid\n")
    profile = runpy.run_path(str(HOST / "u2_broker_profile.py"))["fetch"](ssh)
    code, child = run([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")])
    healthy = ("BcdUSBVersion=%d MPS0=%d" % (profile["healthyBcdUSB"], profile["healthyMPS0"])).encode()
    if (b"DeviceState=configured OnBus=yes SelectedConfiguration=" not in child or
            b"SelectedConfiguration=0" in child or healthy not in child):
        raise ValueError("controller not in healthy configured state")
    evidence.append(child)
    code, census = run([sys.executable, str(HOST / "read-u2-xdci-function-census-wifi.py")])
    if code or normalized(census.decode()) != normalized(REFERENCE.read_text()):
        raise ValueError("function census differs from the healthy reference")
    evidence.append(census)
    blob = b"".join(evidence)
    proof = hashlib.sha256(blob).hexdigest()
    out = ROOT / ("build/ipad-hardware/u2-trials/confirm-after-heal-%d" % time.time_ns())
    out.mkdir(mode=0o700)
    (out / "evidence.txt").write_bytes(blob)
    (out / "evidence.txt").chmod(0o600)
    reply = ask("confirm " + proof)
    print("confirm:", reply, "evidence=%s" % out.relative_to(ROOT))
    if reply != "OK verified-and-cleared":
        raise ValueError("broker did not confirm")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
        print("U2_CONFIRM_AFTER_HEAL rejected (%s); journal retained" % error)
        raise SystemExit(1)
