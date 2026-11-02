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
PROFILE = runpy.run_path(str(HOST / "u2_broker_profile.py"))


def run(argv, timeout):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    return result.returncode, result.stdout


def capture(directory, label):
    for name in READERS:
        code, out = run([sys.executable, str(HOST / ("read-u2-%s-wifi.py" % name))], 60)
        (directory / ("%s-%s.txt" % (name, label))).write_bytes(out)
        (directory / ("%s-%s.txt" % (name, label))).chmod(0o600)


# The marker every connect attempt writes. A gap between two of these is a gap
# in the device's log; a gap with no marker in it is a gap in the capture, and
# telling them apart is the whole reason the markers exist.
CONNECT_MARKER = "--- syslog capture connect"
DISCONNECT_MARKER = "--- syslog capture lost"
# How long the relay may deliver nothing before it is treated as dead. The
# observed failure is not an exit: the relay stops delivering and the process
# stays alive, so a loop that waits for its child to exit never reconnects and
# the log simply stops - which is how a whole bus cycle, every heal
# re-publication and the restore went unrecorded. Silence is therefore the
# trigger. 20 s is longer than any quiet period a device under trial has, and
# shorter than the 29-72 s the device spends off bus, so a stall is noticed
# while it still matters.
SYSLOG_STALL_SECONDS = 20
# Run as its own process so stopping the capture is one killpg, as before. Self
# contained: it is handed the command to supervise, so the loop can be driven
# offline against a stand-in that stalls the way the real relay does.
SUPERVISOR_SOURCE = r'''
import os, select, subprocess, sys, time

def mark(handle, marker, text):
    handle.write(("%s %s at=%s ---\n" % (marker, text,
                  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))).encode("ascii"))

def pump(handle, child, stall):
    """Copy the relay's output through until it stops; return why it stopped."""
    while True:
        ready = select.select([child.stdout], [], [], stall)[0]
        if not ready:
            child.kill()
            child.wait()
            return "stalled-after-%ds-of-silence" % int(stall)
        chunk = os.read(child.stdout.fileno(), 65536)
        if not chunk:
            code = child.wait()
            return "exited-code-%d" % code
        handle.write(chunk)

def main():
    path, stall = sys.argv[1], float(sys.argv[2])
    connect, lost = sys.argv[3], sys.argv[4]
    attempt = 0
    with open(path, "ab", buffering=0) as handle:
        while True:
            attempt += 1
            mark(handle, connect, "attempt=%d" % attempt)
            try:
                child = subprocess.Popen(sys.argv[5:], stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL)
            except OSError as error:
                mark(handle, lost, "attempt=%d reason=unstartable-%s" % (attempt, error.errno))
                time.sleep(1)
                continue
            try:
                reason = pump(handle, child, stall)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()
            mark(handle, lost, "attempt=%d reason=%s" % (attempt, reason))
            # A backoff, so a relay that cannot start at all cannot spin.
            time.sleep(1)

main()
'''


def start_supervisor(command, path, stall=SYSLOG_STALL_SECONDS):
    """Run `command` under the reconnecting supervisor, appending to `path`.

    Its own session, so stop_syslog's killpg takes the supervisor and whatever
    relay it currently has; the relay is deliberately not given a session of
    its own, so it cannot outlive that.
    """
    handle = open(path, "ab")
    try:
        os.chmod(path, 0o600)
        return subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-c", SUPERVISOR_SOURCE,
             str(path), str(stall), CONNECT_MARKER, DISCONNECT_MARKER, *command],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
    finally:
        handle.close()


def start_syslog(path):
    """Stream the iPad's live syslog over the network (works with USB down) into a private file."""
    ids = subprocess.run(["/opt/homebrew/bin/idevice_id", "-n"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, timeout=15).stdout.split()
    # The M2 iPad's ID has the T8112 chip prefix; other network entries are ignored.
    ids = sorted({value for value in ids if value.startswith(b"00008112-")})
    if len(ids) != 1:
        return None
    # The relay drops, and worse, goes silent without dropping, when the USB
    # link changes - which is exactly when this capture is the only record
    # there is. The supervisor reconnects on either and marks every attempt.
    return start_supervisor(["/opt/homebrew/bin/idevicesyslog", "-n", "-u",
                             ids[0].decode(), "--no-colors"], path)


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
    profile = PROFILE["fetch"]()
    observer = subprocess.Popen([sys.executable, str(HOST / "u2-usb-return-observer.py"),
                                 "0x%04x" % profile["usbVendorID"], "0x%04x" % profile["usbProductID"], "20"],
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
