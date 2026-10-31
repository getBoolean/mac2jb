#!/usr/bin/env python3
"""One HID keyboard trial, wrapped in the same safety shape as the no-op trial runner.

Usage: --broker vNN --function NAME --controller REGISTRY_ID
       --canary-path /var/jb/... --canary-sha256 HEX --broker-sha256 HEX
       --configuration N --stock-interfaces N [--mode MODE]

`--mode` picks which of the canary's staged gates to attempt, defaulting to the
full run so an existing invocation is unchanged. `open-only` stops after the
single attempt to open the appended interface's user client and configures
nothing; `configure-only` walks the configuration sequence, records every raw
return and writes no reports. The gates write no reports by design, so an
absent observed sequence is their expected outcome and not one of the
report-gap labels - but it is not a HID result either, so a gate never
confirms the journal: the original stays journalled and healable and the gate's
answer is the canary's own exit code and raw returns in the evidence directory.
The report reader is armed before the publication in every mode, because an
interface that appears unseized is real keyboard input to this Mac whatever the
canary was asked to do, and it is collected on every path.

The expected binary digests are arguments rather than pins, because the canary
is still changing; the trial refuses unless the Mac-built binaries and the copy
staged on the device all match the digests given here. The host-selected
configuration number and its pre-publication interface count come from the
trial baseline, so nothing device-specific is compiled in.

Refuses to start, with its own message for each, unless: both binaries exist at
the expected digests; pinned Wi-Fi SSH reaches the device, since that is the
control channel that survives USB going down; the broker is idle; the broker
has no journal; the device is not already publishing the function; and a fresh
restore kit was taken.

Then, with network syslog recording and the passive Mac lifecycle monitor
armed: `prepare`, then the canary, which connects to the broker and sends
`watch`; only once it reports that lease held does the host send
`publish-hid NAME`, because the broker refuses to publish with no worker
registered, and that registration is also what makes the worker's death
restore the original. The canary holds that one connection open across the
publication and waits, bounded, for the appended interface to appear.

The report capture is armed before `publish-hid`, not after: the device
publishes itself as a real USB keyboard, so a trial that let the system bind it
first would type its string into whatever window has focus on this Mac. Armed
first, the reader is already waiting when the interface appears and seizes it
before the canary types, which is a guarantee rather than a race. Its deadline
therefore covers the publication and the canary's interface wait as well as the
typing. A reader armed this early that still binds nothing means the interface
never appeared at all, and is labelled as that rather than as an empty capture.

The enumeration capture is then started while the lease is still held and the
function is live, since releasing the lease tears the interface down again, and
after the reports are collected, because the comparator reads the observed
sequence when it starts.

It then waits up to 120 s with no host action for USB to return, runs the
strict external check, and sends `confirm <sha256(check output)>` only when
that check's own output is the proof - never on a successful canary write, a
passing descriptor comparison or anything else. On any failure the journal is
left alone and the broker's heal-status is reported.

An observed-report file is accepted only where this same trial wrote it, in its
own fresh evidence directory; an operator-supplied path is refused, so an
unprovenanced file cannot manufacture a pass. `hid-proof=pass` needs the
descriptors to have matched and the observed reports to have matched the
press/release sequence the canary types; a comparison with no sequence at all
is `hid-proof=inconclusive reason=reports-unobserved`, never a pass.

Reading input reports on this Mac needs the Input Monitoring privacy grant, so
a permission refusal is its own labelled outcome, as are an empty capture and a
reader that bound no device or several. None of them is a HID result and none
of them clears the journal: the trial refuses before `confirm`, leaving the
original journalled and healable, and reports the broker's heal-status.

The command surface is injected (`live_environment`), so the refusals, the
publication ordering and the proof-gated confirm are testable with no device
and no network.
"""

import hashlib
import json
from pathlib import Path
import re
import runpy
import secrets
import select
import shlex
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BUILD = ROOT / "build/ipad-hardware"
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))
RECOVER = runpy.run_path(str(HOST / "recover-u2-over-wifi.py"))
PROFILE = runpy.run_path(str(HOST / "u2_broker_profile.py"))
IDLE_STATUS = "OK phase=absent publication=enabled"
USB_RETURN_SECONDS = 120
LEASE_WAIT_SECONDS = 20
CANARY_SECONDS = 90
CAPTURE_SECONDS = 180
# Larger than the typing alone, because the reader is armed before the
# publication: its deadline has to cover the broker's publish reply, the
# canary's own bounded wait for the appended interface to appear, and only then
# the twelve reports. It still returns the moment the expected count arrives,
# so a healthy run does not spend this; it is a bound, not a pause.
REPORT_SECONDS = 90
REPORTS_FILE = "reports.txt"
FULL_MODE = "full"
# The canary's staged gates, in the order they are meant to be attempted. The
# first asks whether the appended name materializes as an interface whose user
# client opens; the second asks which configuration operations this build
# authorizes; the full run also types. Defaulted to the full run, so an
# invocation from before the gates existed is unchanged.
MODES = (FULL_MODE, "open-only", "configure-only")
# The canary says this as soon as the broker has made it the worker.
LEASE_MARKER = b"U3_HID_CANARY lease=held"
PREFIX = "U2_HID_TRIAL"
ASK = ('import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(150);'
       's.connect("/var/jb/var/lib/mac2jb-u2-native/broker.sock");'
       's.sendall(sys.argv[1].encode()+b"\\n");print(s.recv(512).decode().strip())')
DIGEST = ('import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())')
BROKER = re.compile(r"v[0-9]{1,3}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")
DEVICE_PATH = re.compile(r"/var/jb/[A-Za-z0-9._/-]{1,128}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def hid_proof(outcome):
    """The HID verdict, kept apart from the restore verdict. Only `pass` passes.

    An absent report sequence is `inconclusive`, never a pass: it says the
    descriptors matched and nothing at all about reports reaching a host.
    """
    if outcome == "pass":
        return "pass"
    return "inconclusive" if outcome == "reports-unobserved" else "fail"


RECORDED = "reports-recorded"
# Why no observed sequence reached the comparator, one label per cause.
#
# None of these is a result about the device. A permission refusal is a fault
# on this Mac. Because the reader is armed before the publication, a reader
# that bound nothing means the appended interface never appeared at all, which
# is `reports-device-unbound` and never the empty-capture label; the empty
# capture is the narrower statement that the reader held the device and nothing
# arrived. Collapsing any of them would let one read as "the device sent
# nothing".
REPORT_GAPS = {"no-reports": "reports-empty",
               "permission-denied": "reports-permission-denied",
               "no-matching-device": "reports-device-unbound",
               "several-matching-devices": "reports-device-ambiguous",
               "profile-unavailable": "reports-precondition-missing",
               "seize-refused": "reports-capture-rejected"}


def reports_gap(outcome):
    """The label for a capture that produced no sequence, or None if it did."""
    if outcome == RECORDED:
        return None
    return REPORT_GAPS.get(outcome, "reports-capture-rejected")


def mode_writes_reports(mode):
    """Whether this canary mode types at all.

    Only the full run does. For the gates, an absent observed sequence is the
    expected outcome rather than a capture gap, so it is reported as that
    mode's own result - and it is still not a HID result, so it still cannot
    confirm the journal.
    """
    return mode == FULL_MODE


def mode_hid_proof(mode, outcome):
    """The HID verdict for this mode; a mode that types nothing has none.

    The descriptor comparison can still pass in a gate, and reading that as a
    keyboard proof would be exactly the conflation the gates exist to prevent.
    """
    return hid_proof(outcome) if mode_writes_reports(mode) else "not-attempted"


def canary_arguments(options):
    """The canary's own arguments.

    The mode is passed only when it is not the full run, so the command line of
    an invocation from before the gates existed is byte-for-byte unchanged.
    """
    text = ("--function " + shlex.quote(options["function"]) +
            " --controller " + str(options["controller"]))
    if options["mode"] != FULL_MODE:
        text += " --mode " + shlex.quote(options["mode"])
    return text


def checked_reports_path(value, trial):
    """Accept an observed-report file only if this trial produced it itself.

    The capture step below is the only thing that writes one, so any other path
    arrived from outside - and an unprovenanced file would turn a red trial
    green. The trial directory is fresh and randomly named, so requiring the
    file to live in it refuses anything this run did not write.
    """
    if value is None:
        return None
    candidate = Path(value).resolve()
    if candidate.parent != Path(trial).resolve() or not candidate.is_file():
        raise ValueError("an observed-report file must be one this trial wrote in its "
                         "own evidence directory; no other file may produce a HID pass")
    return str(candidate)


def captured_reports_path(outcome, trial, name):
    """The capture step's own file, through the same provenance check as any other.

    A path only exists where the reader says it recorded a sequence, so a
    refusal, an empty capture or a reader that bound nothing hands the
    comparator nothing to compare.
    """
    if outcome != RECORDED:
        return None
    return checked_reports_path(str(Path(trial) / name), trial)


def main(options, env):
    """One trial. Every refusal carries its own message and leaves the journal alone."""
    digests = env["local_digests"]()
    if digests.get("canary") != options["canary_sha256"]:
        raise ValueError("canary binary absent or not at the expected digest")
    if digests.get("broker") != options["broker_sha256"]:
        raise ValueError("broker binary absent or not at the expected digest")
    if not env["ssh_reachable"]():
        raise ValueError("pinned Wi-Fi SSH unreachable; the control channel that "
                         "survives USB going down must be up before publishing")
    status = env["ask"]("status")
    if status != IDLE_STATUS:
        if "phase=absent" not in status:
            raise ValueError("broker journal present (%s); it must be cleared first" % status)
        raise ValueError("broker not idle (%s)" % status)
    outcome = env["function_outcome"](options["function"])
    if outcome != "absent-service":
        raise ValueError("device already publishing the function (%s)" % outcome)
    if env["staged_canary_digest"]() != options["canary_sha256"]:
        raise ValueError("staged canary on the device differs from the Mac-built binary")
    if env["restore_kit"]():
        raise ValueError("no fresh restore kit; a trial may not start without one")

    syslog = env["syslog"]()
    try:
        prepared = env["ask"]("prepare")
        if prepared != "OK prepared":
            raise ValueError("broker refused to journal the original (%s)" % prepared)

        def body():
            # The broker refuses to publish unless a worker is registered, and
            # only a held `watch` connection registers one. The canary is that
            # worker: it takes the lease first and keeps the connection open
            # across the publication, so its death restores the original.
            canary = env["start_canary"]()
            try:
                if not env["await_lease"](canary):
                    raise ValueError("the canary never reported the broker lease held "
                                     "within %ds; nothing was published"
                                     % LEASE_WAIT_SECONDS)
                # Armed before the publication, and this ordering is the whole
                # safety argument: the device publishes itself as a real USB
                # keyboard, so from the moment the interface appears until
                # something seizes it, every report it sends is real keyboard
                # input to whatever window has focus on this Mac. Starting the
                # reader afterwards would leave a race between the system
                # binding the new keyboard and the seize taking it away; armed
                # first, the reader is already waiting when the interface
                # appears and seizes it before the canary - which types only
                # after its own bounded wait for that same interface finds it -
                # can write anything. There is no interface to match yet, so
                # waiting is all the reader does until the publication lands.
                reader = env["start_reports"]("published")
                try:
                    published = env["ask"]("publish-hid " + options["function"])
                    if published != "OK published-additive":
                        raise ValueError("broker refused the additive publication (%s)"
                                         % published)
                finally:
                    # Collected on every path, including a refused publication:
                    # a reader left running holds a device seized. Bounded by
                    # its own deadline, so this cannot wait indefinitely.
                    reports = env["collect_reports"](reader)
            except BaseException:
                env["collect_canary"](canary)
                raise
            # The descriptor capture also has to run while the lease is held
            # and the function is live - the canary's release tears the
            # appended interface down again - and it has to start after the
            # reports are collected, because the comparator reads the observed
            # sequence when it starts. The reader returns as soon as the
            # expected report count arrives, so both still fall inside the
            # lease the canary has not yet given back.
            capture = env["start_capture"]("published", reports[2])
            return (published, env["collect_canary"](canary),
                    env["collect_capture"](capture), reports)

        (published, canary, capture, reports), lifecycle = env["observe"](body)
        env["evidence"]("lifecycle.ndjson", lifecycle[:16384])
        env["evidence"]("canary.txt", canary[1][:8192])
        env["evidence"]("report-capture.txt", reports[1].encode("ascii")[:8192])
        env["evidence"]("enumeration.txt", capture[1].encode("ascii"))
        back = env["usb_present"]()
        waited = 0
        while not back and waited < USB_RETURN_SECONDS:
            env["sleep"](3)
            waited += 3
            back = env["usb_present"]()
        # Asked before any verdict: on every failure path this is what gets reported.
        heal = env["ask"]("heal-status")
        env["evidence"]("heal-status.txt", heal.encode("ascii") + b"\n")
        typing = mode_writes_reports(options["mode"])
        proof = mode_hid_proof(options["mode"], capture[0])
        # A mode that writes no reports cannot have a capture gap: there was
        # never a sequence to miss. Its result is its own, reported below.
        gap = reports_gap(reports[0]) if typing else None
        print("%s mode=%s published=%s canary-exit=%d reports=%s enumeration=%s "
              "hid-proof=%s usb=%s heal=%s"
              % (PREFIX, options["mode"], published, canary[0], reports[0], capture[0],
                 proof, "returned" if back else "absent", heal), flush=True)
        if not back:
            raise ValueError("USB did not return in %ds; journal retained, heal %s"
                             % (USB_RETURN_SECONDS, heal))
        env["sleep"](5)
        ok, post = env["strict"]("awaitingVerification")
        env["evidence"]("postcheck.txt", post)
        if not ok:
            raise ValueError("strict external check failed; journal retained, heal %s" % heal)
        if not typing:
            # This gate writes no reports, so the absent sequence is expected
            # and none of the report-gap labels applies. The gate's answer is
            # the canary's own exit code and its printed raw returns, which are
            # in the evidence directory; nothing here is a HID result, so the
            # confirm is never sent and the original stays journalled and
            # healable.
            print("%s mode=%s gate=canary-exit-%d reports=not-expected "
                  "journal=retained heal=%s"
                  % (PREFIX, options["mode"], canary[0], heal), flush=True)
            raise ValueError("canary mode %s writes no reports; its result is "
                             "canary-exit=%d in the evidence directory; journal "
                             "retained, heal %s" % (options["mode"], canary[0], heal))
        if gap:
            # No observed sequence, so there is no HID result to report and no
            # completed trial to clear a journal for. Said with its own label
            # and refused here, before the confirm: the original stays
            # journalled and healable, which is the conservative direction.
            raise ValueError("report capture produced no observed sequence (%s); "
                             "journal retained, heal %s" % (gap, heal))
        # The check's own output is the proof. Nothing else may clear a journal.
        reply = env["ask"]("confirm " + hashlib.sha256(post).hexdigest())
        ok_after, after = env["strict"]("absent")
        env["evidence"]("after-confirm.txt", reply.encode("ascii") + b"\n" + after)
        if reply != "OK verified-and-cleared" or not ok_after:
            raise ValueError("broker did not clear the journal (%s)" % reply)
        print("%s confirm=%s strict-after=pass enumeration=%s hid-proof=%s"
              % (PREFIX, reply, capture[0], proof))
        if proof != "pass":
            # The restore is proven; the keyboard is not. Said in its own line
            # so no reader can take a cleared journal for a HID proof.
            print("%s hid-proof=%s reason=%s note=%s" % (
                PREFIX, proof, capture[0],
                "no-report-sequence-was-recorded-on-this-Mac"
                if capture[0] == "reports-unobserved" else "see-the-enumeration-evidence"))
        return {"confirmed": True, "enumeration": capture[0], "hid_proof": proof,
                "reports": reports[0], "canary_exit": canary[0]}
    finally:
        env["stop_syslog"](syslog)


def live_environment(options):
    """The real command surface: pinned SSH, the broker socket and the host tools."""
    ssh = SUPPORT["ssh"]()
    trial = BUILD / "u2-trials" / ("hid-%s-%d-%s" % (options["broker"], time.time_ns(),
                                                     secrets.token_hex(4)))
    trial.mkdir(mode=0o700, parents=True)

    def remote(command, timeout):
        result = subprocess.run([*ssh, command], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout)
        return result.returncode, result.stdout

    def python(source, argument, timeout):
        return remote("/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source) +
                      " " + shlex.quote(argument), timeout)

    def local_digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

    def ask(command):
        return python(ASK, command, 200)[1].decode("ascii", "replace").strip()

    def added_function(name):
        result = subprocess.run(
            [sys.executable, str(HOST / "read-u2-added-function-wifi.py"), name],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        match = re.search(r"outcome=([a-z-]+)", result.stdout.decode("ascii", "replace"))
        if result.returncode or not match:
            raise ValueError("the device's function state could not be read")
        return match.group(1)

    def observe(callable_body):
        profile = PROFILE["fetch"](ssh)
        with tempfile.TemporaryDirectory(prefix="u2-hid-monitor-", dir=BUILD) as temporary:
            binary = SUPPORT["monitor_binary"](temporary)
            process, ready = SUPPORT["arm_monitor"](binary, profile["usbVendorID"],
                                                    profile["usbProductID"])
            try:
                result = callable_body()
            finally:
                tail = process.communicate(timeout=SUPPORT["WINDOW_SECONDS"] + 10)[0]
        return result, ready + tail

    # The capture step is the only producer of an observed sequence; an
    # operator-supplied path cannot live in this run's fresh directory, so this
    # refuses `--reports` rather than letting it reach the comparator.
    if checked_reports_path(options["reports"], trial) is not None:
        raise ValueError("the observed-report file is this trial's own capture; "
                         "--reports may not be supplied")

    def start_canary():
        """The lease holder, left running: it is the broker's worker."""
        process = subprocess.Popen(
            [*ssh, shlex.quote(options["canary_path"]) + " " +
             canary_arguments(options)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return {"process": process, "output": b""}

    def await_lease(handle):
        """Bounded wait for the canary's own report that the lease is held."""
        process = handle["process"]
        deadline = time.monotonic() + LEASE_WAIT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                return False
            text = process.stdout.readline()
            if not text:
                return False
            handle["output"] += text
            if text.startswith(LEASE_MARKER):
                return True

    def collect_canary(handle):
        process = handle["process"]
        try:
            rest = process.communicate(timeout=CANARY_SECONDS)[0]
        except subprocess.TimeoutExpired:
            process.kill()
            rest = process.communicate(timeout=10)[0]
        return process.returncode, handle["output"] + (rest or b"")

    def start_reports(stage):
        """The seizing report reader: it takes the keyboard away from this Mac.

        Until it has the device, the canary's keystrokes are real input to
        whatever window has focus here, so this is started first and its
        refusals are never worked around.
        """
        return subprocess.Popen(
            [sys.executable, str(HOST / "capture-u2-hid-reports.py"),
             "--out-dir=%s" % trial, "--name=%s-%s" % (stage, REPORTS_FILE),
             "--deadline=%d" % REPORT_SECONDS],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def collect_reports(process):
        try:
            out = process.communicate(timeout=REPORT_SECONDS + 90)[0]
        except subprocess.TimeoutExpired:
            process.kill()
            out = process.communicate(timeout=10)[0]
        text = (out or b"").decode("ascii", "replace")
        match = re.search(r"outcome=([a-z-]+)", text)
        outcome = match.group(1) if match else "rejected"
        # Provenance unchanged: the file goes through the same check as any
        # other, so only one this run wrote in its own directory can be used.
        return outcome, text, captured_reports_path(outcome, trial,
                                                    "published-" + REPORTS_FILE)

    def start_capture(stage, observed):
        argv = [sys.executable, str(HOST / "capture-u2-hid-enumeration.py"),
                "--configuration=%d" % options["configuration"],
                "--stock-interfaces=%d" % options["stock_interfaces"],
                "--out=%s" % (trial / ("enumeration-%s.txt" % stage))]
        if observed:
            argv.append("--reports=%s" % observed)
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def collect_capture(process):
        try:
            out = process.communicate(timeout=CAPTURE_SECONDS)[0]
        except subprocess.TimeoutExpired:
            process.kill()
            out = process.communicate(timeout=10)[0]
        text = (out or b"").decode("ascii", "replace")
        match = re.search(r"outcome=([a-z-]+)", text)
        return (match.group(1) if match else "rejected"), text

    def strict(phase):
        result = subprocess.run([sys.executable, str(HOST / "check-u2-trial-current.py"),
                                 "--expect-journal=" + phase], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=300)
        return (result.returncode == 0 and
                result.stdout.startswith(b"U2_V7_CURRENT ")), result.stdout

    return {
        "local_digests": lambda: {
            "canary": local_digest(BUILD / "u3-hid-canary-v1"),
            "broker": local_digest(BUILD / ("u3-native-additive-function-" + options["broker"])),
        },
        "staged_canary_digest": lambda: python(DIGEST, options["canary_path"], 60)[1]
            .decode("ascii", "replace").strip(),
        "ssh_reachable": lambda: remote("echo reachable", 30)[1] == b"reachable\n",
        "ask": ask,
        "function_outcome": added_function,
        "restore_kit": lambda: subprocess.run(
            [sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=400).returncode,
        "observe": observe,
        "start_canary": start_canary,
        "await_lease": await_lease,
        "collect_canary": collect_canary,
        "start_reports": start_reports,
        "collect_reports": collect_reports,
        "start_capture": start_capture,
        "collect_capture": collect_capture,
        "usb_present": SUPPORT["usb_present"],
        "strict": strict,
        "syslog": lambda: RECOVER["start_syslog"](trial / "syslog.txt"),
        "stop_syslog": RECOVER["stop_syslog"],
        "evidence": lambda name, data: SUPPORT["private_file"](trial / name, data),
        "sleep": time.sleep,
        "trial": trial,
    }


def parse(argv):
    options = {"reports": None, "mode": FULL_MODE}
    for item in argv:
        name, _, value = item.partition("=")
        if not name.startswith("--") or not value:
            raise ValueError("usage: see the module docstring")
        options[name[2:].replace("-", "_")] = value
    required = ("broker", "function", "controller", "canary_path", "canary_sha256",
                "broker_sha256", "configuration", "stock_interfaces")
    if any(name not in options for name in required):
        raise ValueError("usage: see the module docstring")
    for name in ("controller", "configuration", "stock_interfaces"):
        options[name] = int(options[name], 0)
    if options["mode"] not in MODES:
        raise ValueError("unknown canary mode %r; one of %s" %
                         (options["mode"], ", ".join(MODES)))
    if (not BROKER.fullmatch(options["broker"]) or not NAME.fullmatch(options["function"]) or
            not DEVICE_PATH.fullmatch(options["canary_path"]) or options["controller"] <= 0 or
            not HEX64.fullmatch(options["canary_sha256"]) or
            not HEX64.fullmatch(options["broker_sha256"])):
        raise ValueError("invalid argument")
    return options


if __name__ == "__main__":
    try:
        if any(item in ("--help", "-h") for item in sys.argv[1:]):
            print(__doc__, end="")
            raise SystemExit(0)
        parsed = parse(sys.argv[1:])
        environment = live_environment(parsed)
        print("%s evidence=%s" % (PREFIX, environment["trial"].relative_to(ROOT)), flush=True)
        summary = main(parsed, environment)
        print("%s %s" % (PREFIX, json.dumps(summary, sort_keys=True)))
        raise SystemExit(0 if summary["hid_proof"] == "pass" else 2)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("%s rejected (%s); journal left alone" % (PREFIX, error))
        raise SystemExit(1)
