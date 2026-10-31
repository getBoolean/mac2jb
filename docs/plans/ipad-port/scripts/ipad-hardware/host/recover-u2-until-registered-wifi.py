#!/usr/bin/env python3
"""Bounded re-publication until every USB function registers (Wi-Fi only).

Mechanism under test (2026-10-31 syslog): after each SetDescription the XDCI
controller stays off bus when any of the 16 functions fails to re-register
(`gated_registerFunction`); which ones fail varies per publication. Effect: up
to MAX attempts, each = back up the journal (kit), stream iPad syslog over the
network, send one broker `restore-after-failure`, wait, count registered
functions in that attempt's log, and check Mac USB. Stops at the first Mac
arrival. Never confirms or clears the journal. Refuses if Mac USB is present
or SSH/controller state is wrong.
"""

from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
RECOVER = runpy.run_path(str(HOST / "recover-u2-over-wifi.py"))
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))
FUNCTIONS = {"PTP", "USBAudioControl", "USBAudioStreaming", "IapOverUsbHid", "AppleUSBMux",
             "AppleUSBEthernet", "AppleUSBNCMControl", "AppleUSBNCMData", "AppleUSBNCMControlAux",
             "AppleUSBNCMDataAux", "Valeria", "USBAudio2Control", "USBAudio2StreamIN",
             "USBAudio2StreamOUT", "IDAMInterface", "AppleUSBNCMControlDirect"}
MAX = 4


def main():
    if SUPPORT["usb_present"]():
        raise ValueError("Mac USB present; nothing to restore")
    out = ROOT / ("build/ipad-hardware/u2-trials/register-loop-%d" % time.time_ns())
    out.mkdir(mode=0o700)
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    source = (DEVICE / "u2-wifi-restore-request.py").read_bytes().decode("ascii")
    for attempt in range(1, MAX + 1):
        code, text = RECOVER["run"]([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")], 400)
        kit = text.decode().strip().split("kit=")[-1]
        import json
        manifest = json.loads((ROOT / kit / "manifest.json").read_bytes())
        digest = [e["sha256"] for e in manifest["device"]
                  if e["path"].endswith("/restore-journal.json") and "sha256" in e][0]
        log = out / ("syslog-%d.txt" % attempt)
        syslog = RECOVER["start_syslog"](log)
        if syslog is None:
            raise ValueError("network syslog unavailable; refusing to publish blind")
        time.sleep(3)
        code, reply = RECOVER["run"]([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " +
                                      shlex.quote(source) + " " + digest], 60)
        time.sleep(12)
        RECOVER["stop_syslog"](syslog)
        registered = set(re.findall(r"register function ([A-Za-z0-9]+)",
                                    log.read_text("utf-8", "replace"))) & FUNCTIONS
        present = SUPPORT["usb_present"]()
        line = "U2_REGISTER_LOOP attempt=%d request=%s registered=%d/16 missing=%s usb=%s" % (
            attempt, reply.decode().strip().split()[-1] if reply else "none", len(registered),
            ",".join(sorted(FUNCTIONS - registered)) or "none", "present" if present else "absent")
        print(line, flush=True)
        (out / "attempts.txt").open("a").write(line + "\n")
        if present or code:
            break
    print("U2_REGISTER_LOOP evidence=%s journal=retained confirmation=not-sent" % out.relative_to(ROOT))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print("U2_REGISTER_LOOP rejected (%s)" % error)
        raise SystemExit(1)
