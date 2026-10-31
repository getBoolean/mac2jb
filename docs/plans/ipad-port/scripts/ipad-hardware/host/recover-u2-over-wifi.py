#!/usr/bin/env python3
"""Standard response when a U2 trial loses Mac USB: back up, capture, then one Wi-Fi restore.

Effect, in order, stopping on the first failed precondition:
1. Read-only: pinned Wi-Fi SSH works, Mac USB/USBMux show the iPad absent,
   and the XDCI controller is not configured.
2. Backup: run backup-u2-wifi-restore-kit.py, which saves the failed journal
   and every U2 file byte-exact into a new private kit.
3. Read-only: capture the failed-state reference set into that kit, and
   stream the iPad syslog over the network into a private file until step 5.
4. Arm the passive Mac USB return observer, then send exactly one broker
   restore request over pinned root Wi-Fi SSH (device/u2-wifi-restore-request.py).
5. Read-only: capture the reference set again, back up the changed journal
   in a second kit, and print a verdict.
It never confirms or clears the journal and never retries. A later separate
full external check is still required before any confirmation.
"""

import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
KITS = ROOT / "build/ipad-hardware/u2-wifi-restore-kit"
READERS = ("xdci-function-census", "usb-function-providers", "provider-job-state",
           "accessory-ports", "typec-scalar-state", "lock-state", "xdci-child-census")
VENDOR, PRODUCT = "0x05ac", "0x12ab"


def run(argv, timeout):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    return result.returncode, result.stdout


def capture(directory, label):
    for name in READERS:
        code, out = run([sys.executable, str(HOST / ("read-u2-%s-wifi.py" % name))], 60)
        (directory / ("%s-%s.txt" % (name, label))).write_bytes(out)
        (directory / ("%s-%s.txt" % (name, label))).chmod(0o600)


def start_syslog(path):
    """Stream the iPad's live syslog over the network (works with USB down) into a private file."""
    ids = subprocess.run(["/opt/homebrew/bin/idevice_id", "-n"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, timeout=15).stdout.split()
    # The M2 iPad's ID has the T8112 chip prefix; other network entries are ignored.
    ids = sorted({value for value in ids if value.startswith(b"00008112-")})
    if len(ids) != 1:
        return None
    handle = open(path, "wb")
    path.chmod(0o600)
    # The network relay drops when the USB link changes; reconnect until stopped.
    loop = ('while :; do /opt/homebrew/bin/idevicesyslog -n -u "$1" --no-colors; '
            'echo "--- syslog stream reconnect ---"; sleep 1; done')
    return subprocess.Popen(["/bin/sh", "-c", loop, "sh", ids[0].decode()], stdout=handle,
                            stderr=subprocess.DEVNULL, start_new_session=True)


def stop_syslog(process):
    if process is not None:
        try:
            os.killpg(process.pid, 15)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def main():
    code, out = run([sys.executable, str(HOST / "check-pinned-wireless-ssh.py")], 60)
    if code or out.count(b"=ok") != 3:
        raise ValueError("pinned Wi-Fi SSH unavailable")
    code, out = run([sys.executable, str(HOST / "diagnose-usb-recognition.py")], 30)
    if code or b"USBMUX query=ok count=0\n" not in out or b"raw-ipad=no" not in out:
        raise ValueError("Mac USB still sees the iPad; nothing to restore")
    code, out = run([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")], 60)
    if code or b"DeviceState=configured" in out:
        raise ValueError("controller configured or unreadable; refusing")
    before = set(KITS.iterdir()) if KITS.exists() else set()
    code, out = run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")], 400)
    print(out.decode("ascii", "replace"), end="")
    created = [path for path in KITS.iterdir() if path not in before]
    if code or len(created) != 1:
        raise ValueError("backup failed; refusing to restore without it")
    kit = created[0]
    manifest = json.loads((kit / "manifest.json").read_bytes())
    journal = [entry for entry in manifest["device"]
               if entry["path"].endswith("/restore-journal.json") and "sha256" in entry]
    if len(journal) != 1:
        raise ValueError("no active journal backed up; refusing")
    digest = journal[0]["sha256"]
    evidence = kit / "wifi-restore"
    evidence.mkdir(mode=0o700)
    capture(evidence, "failed")
    syslog = start_syslog(evidence / "syslog.txt")
    observer = subprocess.Popen([sys.executable, str(HOST / "u2-usb-return-observer.py"),
                                 VENDOR, PRODUCT, "20"],
                                stdout=open(evidence / "observer.ndjson", "wb"),
                                stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    if observer.poll() is not None:
        raise ValueError("observer did not arm")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    source = (DEVICE / "u2-wifi-restore-request.py").read_bytes().decode("ascii")
    code, out = run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source) +
                     " " + digest], 60)
    (evidence / "request.txt").write_bytes(b"exit=%d\n" % code + out[:512])
    print(out.decode("ascii", "replace"), end="")
    observer.wait(timeout=40)
    time.sleep(10)
    stop_syslog(syslog)
    lifecycle = (evidence / "observer.ndjson").read_text()
    arrived = '"kind": "arrived"' in lifecycle
    time.sleep(3)
    capture(evidence, "after")
    # The request changes the journal (restoring -> awaitingVerification or
    # recoveryRequired), so back up its new bytes too.
    code_after, out_after = run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")], 400)
    (evidence / "post-request-backup.txt").write_bytes(b"exit=%d\n" % code_after + out_after[:512])
    print(out_after.decode("ascii", "replace"), end="")
    print("U2_WIFI_RECOVERY request-exit=%d mac-arrival=%s journal-backup-sha256=%s evidence=%s" % (
        code, "yes" if arrived else "no", digest[:12], evidence.relative_to(ROOT)))
    print("U2_WIFI_RECOVERY no confirmation sent; run the full external check before any confirm")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_WIFI_RECOVERY rejected: %s" % error)
        raise SystemExit(1)
