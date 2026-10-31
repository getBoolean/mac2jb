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

Publishing the description cycles the bus, so the host reads the configuration
descriptor at that moment - before the appended interface has any class,
descriptors or endpoints. The canary configures and commits it afterwards,
which changes the device's own state and nothing the host has read, so the
interface stays absent from the host's view and it never asks for a report
descriptor. So once the canary reports its configuration sequence succeeded,
and while it is still inside its own bounded wait for the host, the runner asks
the broker for `cycle-bus`: the device re-presents itself and the host
enumerates again, this time reading a configuration descriptor that includes
the keyboard. Only the broker has controller authority, so only it can cycle
the bus; the canary holds the interface user client and nothing else. If the
configuration line never arrives, nothing is cycled - re-presenting an
unconfigured interface would only repeat what the host already read - and the
existing refusals report the run.

The report capture is armed before `publish-hid`, not after: the device
publishes itself as a real USB keyboard, so a trial that let the system bind it
first would type its string into whatever window has focus on this Mac. Armed
first, the reader is already waiting when the interface appears and seizes it
before the canary types, which is a guarantee rather than a race. Its deadline
therefore covers the publication and the canary's interface wait as well as the
typing. A reader armed this early that still binds nothing means the interface
never appeared at all, and is labelled as that rather than as an empty capture.

Cycling the bus takes the device off bus for a measured 29 to 72 seconds, so
the runner then waits, with no host action, for USB to come back - before
anything tries to measure it, not after. A capture that reads while the device
is away, or after the canary has handed the lease back and the healer has
re-published the journalled original, is measuring a different description; the
reports are collected and the enumeration capture is started only once the
device is back, and the capture is collected before the canary is, because the
canary's exit tears the appended interface down.

Measuring a live publication is not something this runner can take on trust,
so it does not: it asks the broker for its status immediately before the
capture and hands that answer, the time it was given and the lease that bounds
it to the capture as a witness. The capture stamps its own read time and
refuses to emit a pass or any descriptor verdict unless the read falls inside
that window - `publication-liveness-unestablished`. The runner asks again after
the read, and a publication that had gone by then is
`publication-not-live-after-read`. Both are void observations rather than
negative results: `hid-proof=void`, never `fail`, because an observation that
was not positioned says nothing about the device.

It then runs the strict external check, and sends `confirm <sha256(check output)>` only when
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
import threading
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BUILD = ROOT / "build/ipad-hardware"
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))
RECOVER = runpy.run_path(str(HOST / "recover-u2-over-wifi.py"))
PROFILE = runpy.run_path(str(HOST / "u2_broker_profile.py"))
IDLE_STATUS = "OK phase=absent publication=enabled"
# The fragment of the broker's status line that says the additive publication
# is live. Nothing else is accepted as a witness that a read was positioned.
LIVE_STATUS_FRAGMENT = "phase=published"
# The broker's lease ceiling. It is the only thing that keeps a publication
# from being healed back to the journalled original, so it - not a deadline
# picked by this file - is what bounds everything that has to happen while the
# publication is live.
BROKER_LEASE_CEILING_SECONDS = 30
# The broker's total life cap for one publication: renewal moves the deadline
# forward in quanta of the ceiling above, but never past this. It is what makes
# the 29-72 s bus return observable at all, and it still bounds an unrestored
# publication behind a hung worker at three minutes rather than indefinitely.
BROKER_LEASE_CAP_SECONDS = 180
# Three attempts inside one quantum, so a single lost or heal-blocked reply
# cannot end the publication. The broker is single-threaded and cannot answer a
# renewal while it is healing, so a slow or failed tick is expected and is not
# treated as the lease being gone; only an explicit refusal is.
RENEW_INTERVAL_SECONDS = 10
# Bounded by the device's own measurement rather than by the lease: the device
# takes 29-72 s to come back on bus after a description change, which the lease
# cannot cover. 120 s is the slowest measured return with margin.
USB_RETURN_SECONDS = 120
LEASE_WAIT_SECONDS = 20
CANARY_SECONDS = 90
# A process bound on a read-only registry read, not a liveness bound: whether
# the read was positioned is settled by the witness the capture is given and
# its own stamped read time, never by how long this runner was prepared to
# wait.
CAPTURE_SECONDS = 180
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
# The canary prints its configuration ledger on this line once the sequence has
# run, and then enters its own bounded wait for the host. The ledger's
# "nothing aborted the sequence" value is what says the interface is configured;
# an aborted sequence prints the same line with the operation that refused.
CONFIGURED_MARKER = b"U3_HID_CANARY operations "
CONFIGURED_NOTHING_ABORTED = b"aborted-by=255"
# Bounded wait for that line: the configuration sequence runs after the
# publication, so this covers the canary's own wait for the appended interface
# to appear as well as the selectors themselves. It stays inside the broker's
# lease, which is the real bound.
CONFIGURE_WAIT_SECONDS = 30
# Said in the trial's report where the cycle was not sent at all, as distinct
# from a cycle that was sent and returned something.
CYCLE_NOT_SENT = "not-sent"
PREFIX = "U2_HID_TRIAL"
ASK = ('import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(150);'
       's.connect("/var/jb/var/lib/mac2jb-u2-native/broker.sock");'
       's.sendall(sys.argv[1].encode()+b"\\n");print(s.recv(512).decode().strip())')
DIGEST = ('import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())')
BROKER = re.compile(r"v[0-9]{1,3}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")
DEVICE_PATH = re.compile(r"/var/jb/[A-Za-z0-9._/-]{1,128}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def lease_budget_seconds():
    """How long the publication can be relied on to stay live, in seconds.

    Everything that has to happen while the publication is live is bounded by
    this and not by a deadline of its own: a wait that can outlive the lease
    measures a device the healer has already restored, which is how a 90 s
    report deadline came to produce confident descriptor failures about a stock
    description.

    --- LEASE RENEWAL SEAM ---
    Wired: this trial drives the broker's `renew-lease` on RENEW_INTERVAL_SECONDS
    for as long as it needs the publication, so the horizon is the renewed
    lease's total cap rather than one quantum. Without this the window was empty
    by construction - the lease ended at 30 s and the bus came back at 29-72 s -
    which is why every earlier trial measured a stock device and reported a
    confident falsehood about it.
    """
    return BROKER_LEASE_CAP_SECONDS


# The reader's deadline. Bounded by the lease rather than by a fixed 90 s,
# because the reader must have returned while the publication is still live:
# past the lease it is no longer waiting on the published keyboard at all. It
# still returns the moment the expected report count arrives, so a healthy run
# does not spend this; it is a bound, not a pause.
REPORT_DEADLINE_SECONDS = BROKER_LEASE_CEILING_SECONDS
# A read this trial cannot place inside a live publication, said by the capture
# itself, and a publication that had gone by the time the read finished, which
# only this runner can see. Two different failures to be positioned, so two
# labels; neither is a result about the device.
PUBLICATION_UNESTABLISHED = "publication-liveness-unestablished"
NOT_LIVE_AFTER_READ = "publication-not-live-after-read"
VOID_OBSERVATIONS = (PUBLICATION_UNESTABLISHED, NOT_LIVE_AFTER_READ)


def hid_proof(outcome):
    """The HID verdict, kept apart from the restore verdict. Only `pass` passes.

    An absent report sequence is `inconclusive`, never a pass: it says the
    descriptors matched and nothing at all about reports reaching a host.

    A void observation is `void`, which is neither: a capture that cannot be
    placed inside a live publication has not failed to find a keyboard, it has
    failed to look at one, and `fail` would report the rig's own blindness as
    the device's answer.
    """
    if outcome == "pass":
        return "pass"
    if outcome in VOID_OBSERVATIONS:
        return "void"
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
            # Stopped exactly once, on every path, and never before the read it
            # exists to cover: a renewer still running after the trial would
            # hold a publication alive with nothing watching it, and one
            # stopped too early hands the window back mid-capture.
            renewal = {"state": None, "log": ""}

            def finish_renewal():
                if renewal["state"] is not None:
                    state, renewal["state"] = renewal["state"], None
                    renewal["log"] = env["stop_renewal"](state)
                    # Written here rather than with the other evidence, because
                    # the failure paths never reach that point: the first run
                    # of this rig aborted on a refused bus cycle and left no
                    # record of what the broker had said to any renewal, which
                    # was the one thing needed to explain the abort.
                    env["evidence"]("lease-renewal.txt",
                                    renewal["log"].encode("ascii", "replace")[:8192])

            canary = env["start_canary"]()
            try:
                if not env["await_lease"](canary):
                    raise ValueError("the canary never reported the broker lease held "
                                     "within %ds; nothing was published"
                                     % LEASE_WAIT_SECONDS)
                # Started before the publication and kept running through the
                # bus cycle, the reattach and the capture. The canary holds the
                # lease; this keeps it from expiring underneath it while the
                # device is off bus, which is the whole reason earlier trials
                # could not observe anything.
                renewal["state"] = env["start_renewal"]()
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
                    # The publication's own bus cycle happened before the
                    # appended interface had a class, descriptors or
                    # endpoints, so the configuration descriptor the host read
                    # does not contain it and no commit afterwards can change
                    # what the host already read. Asked for here, after the
                    # canary reports the sequence succeeded and while it is
                    # still waiting for the host: the device re-presents
                    # itself and the host enumerates again, this time reading
                    # the interface. Sent to the broker because controller
                    # authority is the broker's alone.
                    cycled = CYCLE_NOT_SENT
                    if env["await_configured"](canary):
                        cycled = env["ask"]("cycle-bus")
                        if not cycled.startswith("OK bus-cycled "):
                            raise ValueError("broker refused the bus cycle (%s); the "
                                             "host cannot re-read the configuration "
                                             "descriptor without it" % cycled)
                    # Waited for before anything measures, not after: the cycle
                    # takes the device off bus for a measured 29-72 s, and a
                    # capture that reads while it is away reads nothing that
                    # belongs to this publication. Bounded by that measurement
                    # rather than by the lease, which cannot stretch that far -
                    # the gap between the two is what the renewal seam closes.
                    back = env["await_usb"]()
                finally:
                    # Collected on every path, including a refused publication:
                    # a reader left running holds a device seized. Bounded by
                    # the lease, so it cannot still be waiting on a keyboard
                    # the healer has already taken away.
                    reports = env["collect_reports"](reader)
            except BaseException:
                finish_renewal()
                env["collect_canary"](canary)
                raise
            # The witness the capture's verdict depends on: the broker's own
            # word that the publication is live, the moment it was given, and
            # the lease that bounds how long that word can be relied on. Asked
            # here, immediately before the read, because a witness taken any
            # earlier covers less of it.
            witness = {"state": env["ask"]("status"), "observed_at": env["now"](),
                       "max_age": lease_budget_seconds()}
            # Started after the reports are collected, because the comparator
            # reads the observed sequence when it starts, and collected before
            # the canary is: the canary's exit hands the lease back and tears
            # the appended interface down, so a capture still reading then is
            # reading the restored original.
            capture = env["collect_capture"](
                env["start_capture"]("published", reports[2], witness))
            # Asked again after the read: a publication that was live when the
            # witness was taken and gone by now may not have covered the read,
            # and this is the only place that can see it.
            after = env["ask"]("status")
            # Only now: everything that had to happen inside the publication
            # has happened, and the broker restores on its own within a quantum.
            finish_renewal()
            return (published, cycled, env["collect_canary"](canary), capture, reports,
                    back, witness, after, renewal["log"])

        ((published, cycled, canary, capture, reports, back, witness, after,
          renewal_log), lifecycle) = env["observe"](body)
        # lease-renewal.txt is already written by finish_renewal, so that the
        # failure paths record it too; renewal_log is kept for the summary line.
        env["evidence"]("lifecycle.ndjson", lifecycle[:16384])
        env["evidence"]("canary.txt", canary[1][:8192])
        env["evidence"]("report-capture.txt", reports[1].encode("ascii")[:8192])
        env["evidence"]("enumeration.txt", capture[1].encode("ascii"))
        live_after = LIVE_STATUS_FRAGMENT in after
        env["evidence"]("publication-liveness.txt",
                        ("witness-state=%s\nwitness-observed-at-epoch=%d\n"
                         "lease-seconds=%d\nstate-after-read=%s\nlive-after-read=%s\n"
                         % (witness["state"], int(witness["observed_at"]),
                            witness["max_age"], after, "yes" if live_after else "no")
                         ).encode("ascii", "replace"))
        # Asked before any verdict: on every failure path this is what gets reported.
        heal = env["ask"]("heal-status")
        env["evidence"]("heal-status.txt", heal.encode("ascii") + b"\n")
        typing = mode_writes_reports(options["mode"])
        # The capture refuses its own verdict when it cannot place its read
        # inside the publication; this is the other half of the same rule and
        # keeps its own label. A capture that already voided itself keeps the
        # label it gave, because that cause is the more specific one.
        enumeration = capture[0]
        if enumeration not in VOID_OBSERVATIONS and not live_after:
            enumeration = NOT_LIVE_AFTER_READ
        proof = mode_hid_proof(options["mode"], enumeration)
        # A mode that writes no reports cannot have a capture gap: there was
        # never a sequence to miss. Its result is its own, reported below.
        gap = reports_gap(reports[0]) if typing else None
        # The renewal tally is on the summary line because a publication that
        # was not kept alive explains every downstream result, and reading it
        # out of the evidence directory afterwards is a step too late.
        print("%s mode=%s published=%s cycle=%s canary-exit=%d reports=%s "
              "enumeration=%s hid-proof=%s usb=%s publication-after-read=%s "
              "lease=%s heal=%s"
              % (PREFIX, options["mode"], published, cycled, canary[0], reports[0],
                 enumeration, proof, "returned" if back else "absent",
                 "live" if live_after else "gone",
                 renewal_log.strip().splitlines()[-1] if renewal_log.strip() else "none",
                 heal), flush=True)
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
        ok_after, after_strict = env["strict"]("absent")
        env["evidence"]("after-confirm.txt", reply.encode("ascii") + b"\n" + after_strict)
        if reply != "OK verified-and-cleared" or not ok_after:
            raise ValueError("broker did not clear the journal (%s)" % reply)
        print("%s confirm=%s strict-after=pass enumeration=%s hid-proof=%s"
              % (PREFIX, reply, enumeration, proof))
        if proof != "pass":
            # The restore is proven; the keyboard is not. Said in its own line
            # so no reader can take a cleared journal for a HID proof - and a
            # void observation says so in those words, because "we were not
            # looking at it" is not a statement about the device.
            note = "see-the-enumeration-evidence"
            if enumeration == "reports-unobserved":
                note = "no-report-sequence-was-recorded-on-this-Mac"
            elif enumeration in VOID_OBSERVATIONS:
                note = "the-observation-was-not-positioned-nothing-was-measured"
            print("%s hid-proof=%s reason=%s note=%s" % (PREFIX, proof, enumeration, note))
        return {"confirmed": True, "enumeration": enumeration, "hid_proof": proof,
                "reports": reports[0], "canary_exit": canary[0], "cycle": cycled}
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
            # The long window, because this trial changes the description: the
            # device is measured at 29-72 s to come back on bus, so a window
            # that ends sooner records the absence and never the reattach.
            window = SUPPORT["TRIAL_WINDOW_SECONDS"]
            process, ready = SUPPORT["arm_monitor"](binary, profile["usbVendorID"],
                                                    profile["usbProductID"], window)
            try:
                result = callable_body()
            finally:
                # The monitor buffers its events and emits them when the window
                # ends, so it is waited out rather than cut short: ending it
                # early would discard the reattach it was armed to record.
                tail = process.communicate(timeout=window + 10)[0]
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

    def await_line(handle, marker, seconds, required=None):
        """Bounded read of the canary's streamed output for one of its lines.

        Every line read is kept, so the canary's own evidence is complete
        whether or not the line arrives. A closed stream and an expired
        deadline both mean it did not.
        """
        process = handle["process"]
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                return False
            text = process.stdout.readline()
            if not text:
                return False
            handle["output"] += text
            if text.startswith(marker) and (required is None or required in text):
                return True

    def start_renewal():
        """Drive `renew-lease` in the background for the life of the window.

        The publication only lasts one 30 s quantum unless something keeps
        asking, and the device needs 29-72 s to come back on bus, so without
        this the observation window is empty by construction and every
        measurement lands on a device the healer has already restored.

        A tick that fails is not the lease being gone: the broker is
        single-threaded and cannot answer while it is healing, so a reply can
        be late or lost. Only an explicit refusal stops the renewer, and it
        records that moment, because after it the broker will restore on its
        own within one quantum and nothing read later is positioned.
        """
        state = {"stop": threading.Event(), "replies": [], "refused_at": None}

        def loop():
            while not state["stop"].wait(RENEW_INTERVAL_SECONDS):
                stamp = time.time()
                try:
                    reply = ask("renew-lease")
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    state["replies"].append((stamp, "unreachable %s" % type(error).__name__))
                    continue
                state["replies"].append((stamp, reply))
                if not reply.startswith("OK lease-renewed"):
                    state["refused_at"] = stamp
                    return

        state["thread"] = threading.Thread(target=loop, daemon=True)
        state["thread"].start()
        return state

    def stop_renewal(state):
        """Stop renewing and hand back what the broker said, for the evidence.

        Called on every path, including failures: a renewer left running would
        hold a publication alive past the trial that was watching it.
        """
        state["stop"].set()
        state["thread"].join(timeout=RENEW_INTERVAL_SECONDS + 30)
        lines = ["renew-at-epoch=%d reply=%s" % (int(stamp), reply)
                 for stamp, reply in state["replies"]]
        lines.append("renewals=%d refused-at-epoch=%s"
                     % (len(state["replies"]),
                        "none" if state["refused_at"] is None
                        else int(state["refused_at"])))
        return "\n".join(lines) + "\n"

    def await_lease(handle):
        """Bounded wait for the canary's own report that the lease is held."""
        return await_line(handle, LEASE_MARKER, LEASE_WAIT_SECONDS)

    def await_configured(handle):
        """Bounded wait for the canary's report that the interface is configured.

        The same streamed output the lease is read from. An aborted sequence
        prints the same line naming the operation that refused, so the ledger's
        "nothing aborted the sequence" value is required: a refused
        configuration is not something to cycle the bus for.
        """
        return await_line(handle, CONFIGURED_MARKER, CONFIGURE_WAIT_SECONDS,
                          CONFIGURED_NOTHING_ABORTED)

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
             "--deadline=%d" % REPORT_DEADLINE_SECONDS],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def collect_reports(process):
        try:
            # A short grace over the reader's own deadline, so collecting it
            # cannot become a second, longer wait than the lease allows.
            out = process.communicate(timeout=REPORT_DEADLINE_SECONDS + 15)[0]
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

    def start_capture(stage, observed, live):
        argv = [sys.executable, str(HOST / "capture-u2-hid-enumeration.py"),
                "--configuration=%d" % options["configuration"],
                "--stock-interfaces=%d" % options["stock_interfaces"],
                # The witness, without which the capture emits no verdict at
                # all: what the broker said, when, and the lease it is good for.
                "--publication-state=%s" % live["state"],
                "--publication-observed-at=%.3f" % live["observed_at"],
                "--publication-max-age=%d" % live["max_age"],
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

    def await_usb():
        """Bounded wait for the device to come back on bus, with no host action.

        Measuring before this has returned true measures a device that is not
        there. Bounded by the measured 29-72 s reattach rather than by the
        lease, which cannot cover it.
        """
        waited = 0
        while True:
            if SUPPORT["usb_present"]():
                return True
            if waited >= USB_RETURN_SECONDS:
                return False
            time.sleep(3)
            waited += 3

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
        "start_renewal": start_renewal,
        "stop_renewal": stop_renewal,
        "await_configured": await_configured,
        "collect_canary": collect_canary,
        "start_reports": start_reports,
        "collect_reports": collect_reports,
        "start_capture": start_capture,
        "collect_capture": collect_capture,
        "await_usb": await_usb,
        "now": time.time,
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
