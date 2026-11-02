#!/usr/bin/env python3
"""One auto-heal no-op U2 trial (normal | worker-kill | watchdog-kill) on any staged broker.

Usage: --broker vNN normal|worker-kill|watchdog-kill. USB vendor/product IDs come
from the broker's on-device learned profile; the client payload is the v11
client template with the broker's launchd label substituted.

Effect: read-only preflight (pinned SSH, healthy Mac USB, configured XDCI,
strict external check with no journal); a fresh Wi-Fi restore kit; network
syslog recording; the passive Mac lifecycle monitor; one v11 client run in
the given mode (the broker journals, publishes the original description and
recovers; the fault modes kill the worker or the broker). Then waits up to
120 s with no host action for USB to return, runs the strict external check
(check-u2-trial-current.py --expect-journal=awaitingVerification), and only if it
passes sends `confirm <sha256(check output)>` and re-checks with no journal.
If USB does not return it records the broker heal status and stops; it never
issues another controller request.
"""

import hashlib
import re
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
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))
RECOVER = runpy.run_path(str(HOST / "recover-u2-over-wifi.py"))
CLIENT_TEMPLATE = DEVICE / "u2-noop-trial-client.py"
PROFILE = runpy.run_path(str(HOST / "u2_broker_profile.py"))
CHECK = HOST / "check-u2-trial-current.py"
ASK = ('import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(150);'
       's.connect("/var/jb/var/lib/mac2jb-u2-native/broker.sock");'
       's.sendall(sys.argv[1].encode()+b"\\n");print(s.recv(512).decode().strip())')


def run(argv, timeout):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    return result.returncode, result.stdout


def usb_present():
    # Device-agnostic: one USBMux device (the raw-node check in the diagnostic is iPad-named).
    code, out = run([sys.executable, str(HOST / "diagnose-usb-recognition.py")], 30)
    return code == 0 and b"USBMUX query=ok count=1\n" in out


def strict(phase):
    code, out = run([sys.executable, str(CHECK), "--expect-journal=" + phase], 300)
    return code == 0 and out.startswith(b"U2_V7_CURRENT "), out


LABELS = {"v11": "dev.mac2jb.u2.nooptrialv11",
          "v12": "dev.mac2jb.u2.nooptrialv12",
          "v13": "dev.mac2jb.u2.additivev13",
          "v14": "dev.mac2jb.u2.additivev14",
          "v15": "dev.mac2jb.u2.additivev15",
          "v16": "dev.mac2jb.u2.additivev16",
          "v17": "dev.mac2jb.u2.additivev17"}


def main(broker, mode, publication="publish-noop"):
    ssh = SUPPORT["ssh"]()
    def ask(command):
        return run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(ASK) + " " +
                    shlex.quote(command)], 200)[1].decode().strip()
    template = CLIENT_TEMPLATE.read_bytes().decode("ascii")
    # The launchd label is not derivable from the broker name: the appending
    # broker uses its own. A wrong label would only surface as a watchdog-kill
    # that kills nothing, so resolve it explicitly and refuse an unknown broker.
    if template.count("system/dev.mac2jb.u2.nooptrialv11") != 1 or broker not in LABELS:
        raise ValueError("client template or broker label invalid")
    source = template.replace("system/dev.mac2jb.u2.nooptrialv11", "system/" + LABELS[broker])
    client = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source)
    profile = PROFILE["fetch"](ssh)
    vendor, product = profile["usbVendorID"], profile["usbProductID"]
    if not usb_present() or run([*ssh, client + " status"], 20)[1] != b"U2_NOOP_CLIENT service=ready\n":
        raise ValueError("preflight: USB or idle broker unavailable")
    ok, pre = strict("absent")
    if not ok:
        raise ValueError("preflight strict external check failed")
    if run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")], 400)[0]:
        raise ValueError("pre-trial backup failed")
    trial = BUILD / "u2-trials" / ("run-%s-%s-%s-%d-%s" % (
        broker, mode, publication.split()[0], time.time_ns(), secrets.token_hex(4)))
    trial.mkdir(mode=0o700)
    SUPPORT["private_file"](trial / "precheck.txt", pre)
    syslog = RECOVER["start_syslog"](trial / "syslog.txt")
    time.sleep(2)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="u2-autoheal-monitor-", dir=BUILD) as temporary:
        binary = SUPPORT["monitor_binary"](temporary)
        process, ready = SUPPORT["arm_monitor"](binary, vendor, product)
        try:
            result = subprocess.run([*ssh, client + " " + mode + " " + shlex.quote(publication)],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=60)
            client_out = result.stdout
        except subprocess.TimeoutExpired:
            client_out = b"U2_NOOP_CLIENT timeout\n"
        tail, _ = process.communicate(timeout=SUPPORT["WINDOW_SECONDS"] + 10)
    SUPPORT["private_file"](trial / "lifecycle.ndjson", (ready + tail)[:16384])
    SUPPORT["private_file"](trial / "client.txt", client_out[:4096])
    back = usb_present()
    while not back and time.monotonic() - started < 120:
        time.sleep(3)
        back = usb_present()
    elapsed = time.monotonic() - started
    heal = ask("heal-status")
    RECOVER["stop_syslog"](syslog)
    SUPPORT["private_file"](trial / "heal-status.txt", heal.encode() + b"\n")
    print("U2_AUTOHEAL_TRIAL mode=%s usb=%s after=%.0fs %s evidence=%s" % (
        mode, "returned" if back else "absent", elapsed, heal, trial.relative_to(ROOT)), flush=True)
    if not back:
        print("U2_AUTOHEAL_TRIAL FAIL automatic recovery; journal retained, no further controller request")
        raise SystemExit(2)
    time.sleep(5)
    ok, post = strict("awaitingVerification")
    SUPPORT["private_file"](trial / "postcheck.txt", post)
    if not ok:
        print("U2_AUTOHEAL_TRIAL FAIL strict external check: %s" % post.decode().strip())
        raise SystemExit(3)
    reply = ask("confirm " + hashlib.sha256(post).hexdigest())
    ok_after, after = strict("absent")
    SUPPORT["private_file"](trial / "after-confirm.txt", reply.encode() + b"\n" + after)
    print("U2_AUTOHEAL_TRIAL PASS mode=%s confirm=%s strict-after=%s" % (
        mode, reply, "pass" if ok_after else "fail"))
    if reply != "OK verified-and-cleared" or not ok_after:
        raise SystemExit(4)


if __name__ == "__main__":
    try:
        publication = "publish-noop"
        argv = sys.argv[1:]
        if len(argv) >= 2 and argv[-2] == "--publish":
            publication = argv[-1]
            argv = argv[:-2]
        sys.argv = [sys.argv[0], *argv]
        if (len(sys.argv) != 4 or sys.argv[1] != "--broker" or
                sys.argv[3] not in ("normal", "worker-kill", "watchdog-kill")):
            raise ValueError("usage: --broker vNN normal|worker-kill|watchdog-kill")
        main(sys.argv[2], sys.argv[3], publication)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_AUTOHEAL_TRIAL rejected (%s)" % error)
        raise SystemExit(1)
