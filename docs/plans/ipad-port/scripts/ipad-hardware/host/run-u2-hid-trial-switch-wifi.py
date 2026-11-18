#!/usr/bin/env python3
"""One HID keyboard trial with the Switch 2 (not the Mac) as the USB host.

Usage: same arguments as run-u2-hid-trial-wifi.py, and it requires
       --interfaces=AppleUSBMux,Keyboard --sole-configuration=yes
       (--configuration=selected reads the host-selected configuration on the iPad)
       plus --cable-side=A|B|unrecorded --power=external|none (owner-observed facts).

Effect: the device half of run-u2-hid-trial-wifi.py, reusing its tested pieces
(pinned Wi-Fi SSH, broker commands, lease renewal, canary launch, device
syslog, restore kit). With the iPad cabled to the Switch 2 there is no Mac
USB, so the Mac-side observers (report reader, descriptor capture, lifecycle
monitor, USB-return wait, strict check) are not run. Evidence is device-side:
the canary's enumeration result and per-report write returns (an interrupt-IN
write completes only when the host polls it), device syslog and heal status.
Whether text appeared on the Switch is the owner's observation.

Steps: preflight exactly as the Mac runner (binary digests, SSH, broker idle,
function absent, staged canary, fresh restore kit); prepare; canary takes the
lease; renewal starts; publish-sole-configuration; cycle-bus once the canary
reports its interface configured; collect the canary (which closes its input,
so it exits right after typing); stop renewal. The canary's exit returns the
lease and the broker restores the stock description by itself. The journal is
NEVER confirmed here: it stays awaitingVerification until the cable is back on
the Mac and host/confirm-u2-after-heal-wifi.py verifies the restore.
"""

from pathlib import Path
import re
import runpy
import sys

HOST = Path(__file__).resolve().parent
RUNNER = runpy.run_path(str(HOST / "run-u2-hid-trial-wifi.py"))
PREFIX = "U2_HID_SWITCH"


def selected_configuration():
    """The configuration the current host selected, read on the iPad (read-only).

    The broker only publishes against the host-selected configuration, and the
    Switch 2 selects 1 where the Mac selects 5, so this is read, not assumed.
    """
    import subprocess
    out = subprocess.run([sys.executable, str(HOST / "read-u2-controller-state-keys-wifi.py")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120).stdout
    found = re.search(rb"^CONTROLLER_STATE SelectedConfiguration=(\d+)$", out, re.MULTILINE)
    if not found or int(found.group(1)) < 1:
        raise ValueError("no host-selected configuration on the iPad (is the cable on the host?)")
    return int(found.group(1))


def parse(argv):
    extra = {}
    rest = []
    for item in argv:
        name, _, value = item.partition("=")
        if name in ("--cable-side", "--power"):
            extra[name[2:]] = value
        elif item == "--configuration=selected":
            rest.append("--configuration=%d" % selected_configuration())
        else:
            rest.append(item)
    options = RUNNER["parse"](rest)
    if not options["sole_configuration"] or options["interfaces"] is None:
        raise ValueError("the Switch trial requires --interfaces and --sole-configuration=yes")
    if extra.get("cable-side") not in ("A", "B", "unrecorded") or extra.get("power") not in ("external", "none"):
        raise ValueError("--cable-side=A|B|unrecorded and --power=external|none are owner-observed and required")
    options.update(extra)
    return options


def main(options, env):
    digests = env["local_digests"]()
    if digests.get("canary") != options["canary_sha256"]:
        raise ValueError("canary binary absent or not at the expected digest")
    if digests.get("broker") != options["broker_sha256"]:
        raise ValueError("broker binary absent or not at the expected digest")
    if not env["ssh_reachable"]():
        raise ValueError("pinned Wi-Fi SSH unreachable; it is the only control channel")
    status = env["ask"]("status")
    if status != RUNNER["IDLE_STATUS"]:
        raise ValueError("broker not idle (%s)" % status)
    if env["function_outcome"](options["function"]) != "absent-service":
        raise ValueError("device already publishing the function")
    if env["staged_canary_digest"]() != options["canary_sha256"]:
        raise ValueError("staged canary on the device differs from the Mac-built binary")
    if env["restore_kit"]():
        raise ValueError("no fresh restore kit; a trial may not start without one")
    env["evidence"]("host.txt", ("host=switch2 cable-side=%s power=%s\n"
                                 % (options["cable-side"], options["power"])).encode("ascii"))

    syslog = env["syslog"]()
    renewal = None
    published = cycled = "not-sent"
    canary = (None, b"")
    try:
        prepared = env["ask"]("prepare")
        if prepared != "OK prepared":
            raise ValueError("broker refused to journal the original (%s)" % prepared)
        handle = env["start_canary"]()
        try:
            if not env["await_lease"](handle):
                raise ValueError("the canary never reported the broker lease held")
            renewal = env["start_renewal"]()
            published = env["ask"]("publish-sole-configuration %d %s"
                                   % (options["configuration"], options["interfaces"]))
            if published != "OK published-sole-configuration":
                raise ValueError("broker refused the publication (%s)" % published)
            if env["await_configured"](handle):
                cycled = env["ask"]("cycle-bus")
        finally:
            # Closing the canary's input releases it; it still types first if
            # the host polls, then exits and hands the lease back.
            canary = env["collect_canary"](handle)
            if renewal is not None:
                log = env["stop_renewal"](renewal)
                env["evidence"]("lease-renewal.txt", log.encode("ascii", "replace")[:8192])
        env["evidence"]("canary.txt", canary[1][:262144])
        heal = env["ask"]("heal-status")
        env["evidence"]("heal-status.txt", heal.encode("ascii") + b"\n")
        text = canary[1].decode("ascii", "replace")
        enumerated = re.search(r"enumeration host=([a-z-]+)", text)
        written = re.search(r"reports written=(\d+) stop=([A-Za-z]+)", text)
        delivered = len(re.findall(r"write result=0 io=0x00000000 transferred=8", text))
        print("%s host=switch2 cable-side=%s power=%s published=%s cycle=%s canary-exit=%s "
              "host-enumerated=%s reports-written=%s stop=%s writes-collected=%d heal=%s "
              "journal=retained-until-mac-confirm"
              % (PREFIX, options["cable-side"], options["power"], published, cycled.split(" ")[0],
                 canary[0], enumerated.group(1) if enumerated else "unknown",
                 written.group(1) if written else "0", written.group(2) if written else "none",
                 delivered, heal), flush=True)
        return {"enumerated": bool(enumerated and enumerated.group(1) == "enumerated"),
                "written": int(written.group(1)) if written else 0}
    finally:
        env["stop_syslog"](syslog)


if __name__ == "__main__":
    try:
        if any(item in ("--help", "-h") for item in sys.argv[1:]):
            print(__doc__, end="")
            raise SystemExit(0)
        parsed = parse(sys.argv[1:])
        environment = RUNNER["live_environment"](parsed)
        print("%s evidence=%s" % (PREFIX, environment["trial"].relative_to(RUNNER["ROOT"])),
              flush=True)
        result = main(parsed, environment)
        raise SystemExit(0 if result["enumerated"] and result["written"] == 12 else 2)
    except (OSError, ValueError, KeyError) as error:
        print("%s rejected (%s); journal left alone" % (PREFIX, error))
        raise SystemExit(1)
