#!/usr/bin/env python3
"""One v9 `normal` no-op U2 trial: does the broker heal USB by itself?

Effect:
1. Read-only preflight: pinned SSH, healthy Mac USB (one USBMux device, raw
   iPad at configuration 5), configured XDCI, v8 broker idle with no journal.
2. Backup: a fresh Wi-Fi restore kit; then the seven read-only reference
   readers twice (precheck).
3. Streams the iPad syslog over the network into a private file, arms the
   passive Mac lifecycle monitor, and runs the v8 client `normal` mode
   once: the broker journals the live description, publishes it unchanged,
   and after the worker closes performs its readiness-gated restore.
4. Afterwards captures the reference readers again. If Mac USB did not
   return, runs host/recover-u2-over-wifi.py exactly once (owner policy).
It never confirms or clears the journal. `--preflight` stops after step 1.
"""

import json
from pathlib import Path
import runpy
import secrets
import shlex
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
TRIALS = BUILD / "u2-trials"
LEGACY = runpy.run_path(str(HOST / "run-u2-native-noop-trial-v4-wifi.py"))
RECOVER = runpy.run_path(str(HOST / "recover-u2-over-wifi.py"))
CLIENT = DEVICE / "u2-native-noop-trial-client-v9.py"
VENDOR, PRODUCT = 0x05AC, 0x12AB


def run(argv, timeout):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    return result.returncode, result.stdout


def usb_present():
    code, out = run([sys.executable, str(HOST / "diagnose-usb-recognition.py")], 30)
    return code == 0 and b"USBMUX query=ok count=1\n" in out and b"raw-ipad=yes current-configuration=5" in out


def preflight():
    code, out = run([sys.executable, str(HOST / "check-pinned-wireless-ssh.py")], 60)
    if code or out.count(b"=ok") != 3:
        raise ValueError("pinned Wi-Fi SSH unavailable")
    if not usb_present():
        raise ValueError("Mac USB not healthy")
    code, out = run([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")], 60)
    if code or b"DeviceState=configured OnBus=yes SelectedConfiguration=5" not in out:
        raise ValueError("controller not configured")
    ssh = LEGACY["ssh"]()
    client = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(CLIENT.read_bytes().decode("ascii"))
    code, out = run([*ssh, client + " status"], 20)
    if code or out != b"U2_NOOP_CLIENT service=ready\n":
        raise ValueError("v9 broker not idle with journal absent")
    return ssh, client


def main(mode):
    ssh, client = preflight()
    if mode == "--preflight":
        print("U2_V9_TRIAL preflight=ready usb=healthy controller=configured broker=idle")
        return
    code, out = run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")], 400)
    if code:
        raise ValueError("pre-trial backup failed")
    print(out.decode("ascii", "replace"), end="")
    TRIALS.mkdir(mode=0o700, exist_ok=True)
    trial = TRIALS / ("run-v9-%d-%s" % (time.time_ns(), secrets.token_hex(4)))
    trial.mkdir(mode=0o700)
    RECOVER["capture"](trial, "pre1")
    RECOVER["capture"](trial, "pre2")
    syslog = RECOVER["start_syslog"](trial / "syslog.txt")
    time.sleep(2)
    with tempfile.TemporaryDirectory(prefix="u2-v8-monitor-", dir=BUILD) as temporary:
        binary = LEGACY["monitor_binary"](temporary)
        process, ready = LEGACY["arm_monitor"](binary, VENDOR, PRODUCT)
        result = None
        try:
            try:
                result = subprocess.run([*ssh, client + " normal"], stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=45)
            except subprocess.TimeoutExpired:
                pass
        finally:
            try:
                tail, _ = process.communicate(timeout=LEGACY["WINDOW_SECONDS"] + 10)
            except subprocess.TimeoutExpired:
                process.kill()
                tail, _ = process.communicate(timeout=3)
    LEGACY["private_file"](trial / "lifecycle.ndjson", (ready + tail)[:16384])
    client_out = result.stdout if result is not None else b"U2_NOOP_CLIENT timeout\n"
    LEGACY["private_file"](trial / "client.txt", client_out[:4096])
    print(client_out.decode("ascii", "replace"), end="")
    arrived = b'"kind":"arrived"' in (ready + tail).replace(b" ", b"")
    # The v9 broker heals on its own after its readiness gate times out.
    deadline = time.monotonic() + 90
    back = usb_present()
    while not back and time.monotonic() < deadline:
        time.sleep(3)
        back = usb_present()
    RECOVER["stop_syslog"](syslog)
    RECOVER["capture"](trial, "post")
    print("U2_V9_TRIAL first-arrival=%s usb-now=%s evidence=%s" % (
        "yes" if arrived else "no", "present" if back else "absent", trial.relative_to(ROOT)))
    if back:
        print("U2_V9_TRIAL usb=returned journal=retained confirmation=not-sent")
        return
    print("U2_V9_TRIAL usb=lost after 90 s; sending one Wi-Fi heal")
    ask = ('import socket;s=socket.socket(socket.AF_UNIX);s.settimeout(150);'
           's.connect("/var/jb/var/lib/mac2jb-u2-native/broker.sock");')
    for command in ("heal-status", "heal"):
        code, out = run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(
            ask + 's.sendall(b"%s\\n");print(s.recv(512).decode().strip())' % command)], 200)
        print("U2_V9_TRIAL %s -> %s" % (command, out.decode().strip()))
    deadline = time.monotonic() + 60
    while not usb_present() and time.monotonic() < deadline:
        time.sleep(3)
    print("U2_V9_TRIAL after-wifi-heal usb=%s" % ("present" if usb_present() else "absent"))

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("--preflight", "--run-normal"):
            raise ValueError("usage: --preflight|--run-normal")
        main(sys.argv[1])
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print("U2_V9_TRIAL rejected (%s); journal and evidence retained" % error)
        raise SystemExit(1)
