#!/usr/bin/env python3
"""Inspect, explain or probe a driverless audio USB function nub over pinned root Wi-Fi SSH.

Effect: `--explain-census` classifies why the live function census differs from
the private healthy reference, separating a missing kernel child driver from a
missing USB function nub; it runs only read-only probes. `--inspect` streams the
hash-pinned read-only payload that lists every function nub and its driver.
`--probe FUNCTION` additionally lets the payload call `IOServiceRequestProbe` on
exactly one driverless audio nub, and only when: the payload digest matches, Mac
USB is healthy before and after, the controller is configured and on bus, the
live census is missing nothing but audio child drivers, and that one nub is the
only driverless audio nub. It never publishes a description, never sends the
broker a command and never reads or writes a journal.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u3-rematch-driverless-function.py"
PAYLOAD_SHA256 = "d4e8cb59b07ed8341f530c2751d237af14fb3812c9cfab7b31fe6137269f9b4d"
CENSUS = ROOT / "build/ipad-hardware/u2-function-census"
TRIALS = ROOT / "build/ipad-hardware/u2-trials"
NUB_CLASS = "IOUSBDeviceInterface"
# Kernel audio drivers and the audio user client, the nodes this tool is about.
AUDIO_CHILDREN = frozenset({"AppleUSBDeviceAudioController", "AppleUSBMike",
                            "IOAudio2DeviceUserClient"})
# Nodes whose presence tracks a host connection or an on-demand daemon rather
# than the USB description: ptpd's and audiomxd's clients, the accessory port
# and its client, configd's network-stack clients. Retained censuses show these
# coming and going on a device whose description is byte-identical.
VOLATILE_CHILDREN = AUDIO_CHILDREN | frozenset({
    "IOUSBDeviceInterfaceUserClient", "IOAccessoryPortUSB",
    "IOAccessoryPortUserClient", "IONetworkStackUserClient"})
NODE = re.compile(
    r"U2_XDCI_NODE i=\d{1,3} parent=(?:-1|\d{1,3}) depth=(\d) "
    r"class=([A-Za-z][A-Za-z0-9_]{0,99})(?: busy=(?:\d{1,2}|unknown))?"
    r"(?: function=([A-Za-z0-9_+-]{1,64}))?(?: creator=([A-Za-z0-9._-]{1,48}))?\Z")
INSPECT = re.compile(
    r"U3_REMATCH inspect functions=(\d{1,3}) audio=(\d{1,2}) driverless-audio=(\d{1,2}) "
    r"served-audio=(\d{1,2}) other-driverless=(\d{1,2}) state=([a-z]{1,16})/(yes|no)/(\d{1,3})\Z")
NUB = re.compile(
    r"U3_REMATCH_NUB function=([A-Za-z0-9_]{1,64}|absent|invalid) served=(yes|no) "
    r"audio=(yes|no) expected=([A-Za-z][A-Za-z0-9_]{0,99}|none) children=(\d) "
    r"classes=(?:none|[A-Za-z][A-Za-z0-9_+]{0,199})\Z")
PROBE = re.compile(
    r"U3_REMATCH probe function=([A-Za-z0-9_]{1,64}) expected=([A-Za-z][A-Za-z0-9_]{0,99}|none) "
    r"options=0 result=0x[0-9a-f]{8} ret=([a-z-]{1,24}) children-before=0 "
    r"children-after=(\d) classes=(?:none|[A-Za-z][A-Za-z0-9_+]{0,199}) "
    r"rematched=(yes|no) state=([a-z]{1,16})/(yes|no)/(\d{1,3})\Z")


def signature(line):
    """An identity-free node signature: depth, class, function and creator only."""
    match = NODE.fullmatch(line.strip())
    if not match:
        raise ValueError("invalid census node line")
    return (int(match[1]), match[2], match[3] or "", match[4] or "")


def census_nodes(text):
    nodes = {}
    for line in text.splitlines():
        if not line.startswith("U2_XDCI_NODE "):
            continue
        key = signature(line)
        nodes[key] = nodes.get(key, 0) + 1
    if not nodes:
        raise ValueError("census holds no nodes")
    return nodes


def function_names(nodes):
    names = []
    for (_depth, cls, function, _creator), count in nodes.items():
        if cls == NUB_CLASS:
            names.extend([function] * count)
    return sorted(names)


def audio_children(nodes):
    return sum(count for (_depth, cls, _function, _creator), count in nodes.items()
               if cls in AUDIO_CHILDREN)


def difference(reference, current):
    missing, extra = {}, {}
    for key in set(reference) | set(current):
        delta = current.get(key, 0) - reference.get(key, 0)
        if delta < 0:
            missing[key] = -delta
        elif delta > 0:
            extra[key] = delta
    return missing, extra


def classify_delta(reference_text, current_text):
    """Say what a census difference is, in the terms the confirm gate needs.

    `nub-missing` means a USB function did not come back: the description on the
    bus is wrong and the device still needs restoring. `audio-children-missing`
    and `volatile-clients-missing` mean every function nub is present with its
    own name and only a kernel driver or an on-demand client is absent - nothing
    a host can see in the descriptor.
    """
    reference, current = census_nodes(reference_text), census_nodes(current_text)
    missing, extra = difference(reference, current)
    reference_functions, current_functions = function_names(reference), function_names(current)
    nubs_missing = sorted(set(reference_functions) - set(current_functions))
    missing_classes = {cls for _depth, cls, _function, _creator in missing}
    if not missing and not extra:
        verdict = "equal"
    elif extra or len(current_functions) != len(reference_functions) or nubs_missing:
        verdict = "nub-missing" if (nubs_missing or NUB_CLASS in missing_classes) else "unexpected"
    elif missing_classes <= AUDIO_CHILDREN:
        verdict = "audio-children-missing"
    elif missing_classes <= VOLATILE_CHILDREN:
        verdict = "volatile-clients-missing"
    else:
        verdict = "unexpected"
    return {"verdict": verdict, "missing": missing, "extra": extra,
            "nubs": (len(current_functions), len(reference_functions)),
            "nubs_missing": tuple(nubs_missing),
            "audio_children": (audio_children(current), audio_children(reference))}


def render_delta(tag, delta):
    def counted(table):
        return ",".join("%s:%d" % (cls, count) for (_d, cls, _f, _c), count
                        in sorted(table.items(), key=lambda item: item[0][1])) or "none"
    return ("%s verdict=%s nubs=%d/%d audio-children=%d/%d missing=%s extra=%s nubs-missing=%s" %
            (tag, delta["verdict"], delta["nubs"][0], delta["nubs"][1],
             delta["audio_children"][0], delta["audio_children"][1],
             counted(delta["missing"]), counted(delta["extra"]),
             ",".join(delta["nubs_missing"]) or "none"))


def driverless_audio(output):
    """The audio functions the payload reported as having no driver."""
    head = INSPECT.fullmatch(output.splitlines()[0])
    if not head:
        raise ValueError("invalid inspect header")
    names = []
    for line in output.splitlines()[1:-1]:
        nub = NUB.fullmatch(line)
        if not nub:
            raise ValueError("invalid nub line")
        if nub[3] == "yes" and nub[2] == "no":
            names.append(nub[1])
    if len(names) != int(head[3]):
        raise ValueError("inspect counts disagree")
    return tuple(names), head


def reference_census():
    return sorted(CENSUS.glob("healthy-boot-*/xdci-function-census-1.txt"))[-1]


def run(argv, timeout=90):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout)
    return result.returncode, result.stdout


def live_census():
    code, census = run([sys.executable, str(HOST / "read-u2-xdci-function-census-wifi.py")])
    if code:
        raise ValueError("live function census unavailable")
    return census.decode("ascii")


def configured():
    code, child = run([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")])
    if (code or b"DeviceState=configured OnBus=yes SelectedConfiguration=" not in child or
            b"SelectedConfiguration=0" in child):
        raise ValueError("controller not configured")
    return child


def device(support, step, name=""):
    info = PAYLOAD.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 20480:
        raise ValueError("unsafe payload")
    source = PAYLOAD.read_bytes()
    if hashlib.sha256(source).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("payload changed")
    command = ("/var/jb/usr/bin/python3 -I -S -B -c " +
               shlex.quote(source.decode("ascii")) + " " + step +
               ((" " + shlex.quote(name)) if name else ""))
    code, out = run([*support["ssh"](), command], 60)
    text = out.decode("ascii", "replace")
    if code or len(text) > 4096 or not text.endswith("U3_REMATCH done\n"):
        last = text.strip().splitlines()[-1] if text.strip() else "no output"
        raise ValueError("device payload refused (%s)" % last)
    return text


def evidence(blob):
    out = TRIALS / ("rematch-%d" % time.time_ns())
    out.mkdir(mode=0o700, parents=True)
    runpy.run_path(str(HOST / "u2_trial_support.py"))["private_file"](
        str(out / "evidence.txt"), blob)
    return out.relative_to(ROOT)


def main(mode, name):
    support = runpy.run_path(str(HOST / "u2_trial_support.py"))
    reference = reference_census()
    if mode == "--explain-census":
        current = live_census()
        delta = classify_delta(reference.read_text(), current)
        print(render_delta("U3_REMATCH_CENSUS", delta))
        return
    if not support["usb_present"]():
        raise ValueError("Mac USB not healthy")
    configured()
    before = live_census()
    delta = classify_delta(reference.read_text(), before)
    report = device(support, "--inspect")
    print(report, end="")
    print(render_delta("U3_REMATCH_CENSUS", delta))
    if mode == "--inspect":
        return
    names, _head = driverless_audio(report)
    if names != (name,):
        raise ValueError("requested function is not the only driverless audio nub")
    if delta["verdict"] not in ("audio-children-missing", "volatile-clients-missing"):
        raise ValueError("census difference is not audio-only (%s)" % delta["verdict"])
    probe = device(support, "--probe", name)
    print(probe, end="")
    if not PROBE.fullmatch(probe.splitlines()[0]):
        raise ValueError("invalid probe line")
    after = live_census()
    moved = classify_delta(before, after)
    print(render_delta("U3_REMATCH_DELTA", moved))
    if not support["usb_present"]():
        raise ValueError("Mac USB not healthy afterwards")
    blob = (report + probe + before + after).encode("ascii")
    print("U3_REMATCH evidence=%s" % evidence(blob))


if __name__ == "__main__":
    try:
        argv = sys.argv[1:]
        if (len(argv) not in (1, 2) or argv[0] not in ("--explain-census", "--inspect", "--probe") or
                (argv[0] == "--probe") != (len(argv) == 2)):
            raise ValueError("usage: --explain-census | --inspect | --probe FUNCTION")
        main(argv[0], argv[1] if len(argv) == 2 else "")
    except (OSError, ValueError, IndexError, KeyError, UnicodeError,
            subprocess.SubprocessError) as error:
        print("U3_REMATCH rejected (%s)" % error)
        raise SystemExit(1)
