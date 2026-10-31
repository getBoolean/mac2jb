#!/usr/bin/env python3
"""Record from this Mac the HID input reports the appended function actually sent.

This is the other half of the HID proof: the enumeration comparator checks the
descriptors the device publishes, and this records the reports a host received,
in the hex-line format that comparator reads through `--reports`.

Effect on the device: none. Effect on this Mac: the matched keyboard is seized
for the length of the capture. That is deliberate and is the reason the tool
exists in this shape - the device presents itself as a real USB keyboard, so a
reader that merely observed would also type the trial's string into whatever
window has focus. The compiled reader opens the device with
kIOHIDOptionsTypeSeizeDevice and treats a failed seize as a refusal; it never
falls back to passive observation. See the reader's own file comment.

The device's USB vendor and product IDs come from the broker's learned
on-device profile, never from a constant here; `--vendor`/`--product` exist so
this tool can be exercised with identifiers that bind nothing. With no device
and no control channel there is no profile, and that is reported as a missing
precondition rather than waited on.

Each outcome the reader distinguishes is surfaced verbatim and gets its own
exit code, because a tooling fault read as a hardware result would turn "we
could not look" into "the device sent nothing".

Usage: --out-dir DIR [--name NAME] [--deadline N] [--max-reports N]
       [--vendor 0xNNNN --product 0xNNNN]
Exit: 0 reports recorded, 2 none arrived before the deadline, 3 permission
denied, 4 no matching device, 5 several matching devices, 6 no learned profile,
7 the seize itself was refused, 1 refused.
"""

import hashlib
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[6]
HOST = Path(__file__).resolve().parent
SOURCE = HOST / "u2-hid-report-reader.swift"
# The ignored build tree this project's other host artifacts already live in.
BUILD = ROOT / "build/ipad-hardware"
ENUM = runpy.run_path(str(HOST / "capture-u2-hid-enumeration.py"))
PROFILE = runpy.run_path(str(HOST / "u2_broker_profile.py"))
PREFIX = "U2_HID_REPORTS"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
OUTCOME = re.compile(r"outcome=([a-z-]+)")
# The reader's exit codes, as its own source defines them. Kept as a table so a
# disagreement between the code and the label it printed is a refusal here.
READER_OUTCOMES = {0: "reports-recorded", 66: "no-reports", 67: "permission-denied",
                   68: "no-matching-device", 69: "several-matching-devices",
                   70: "seize-refused"}
# The outcomes that mean the device was seized, and so the only ones that may
# leave a reports file behind.
SEIZED = ("reports-recorded", "no-reports")
# One exit code per outcome, success alone at zero.
EXIT_CODES = {"reports-recorded": 0, "no-reports": 2, "permission-denied": 3,
              "no-matching-device": 4, "several-matching-devices": 5,
              "profile-unavailable": 6, "seize-refused": 7}
# As many reports as the canary's string produces, so the reader returns as
# soon as the sequence is complete instead of holding the live window open to
# its deadline. The count comes from the comparator's own table, which is
# checked against the canary's.
DEFAULT_MAXIMUM = len(ENUM["expected_reports"]())
DEFAULT_DEADLINE = 20


def identifiers(options, fetch=None):
    """The device's USB IDs from the learned profile, or None if there is none."""
    if options.get("vendor") is not None and options.get("product") is not None:
        return options["vendor"], options["product"]
    try:
        profile = (fetch or PROFILE["fetch"])()
        return profile["usbVendorID"], profile["usbProductID"]
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return None


def reader_binary():
    """Compile once to a stable path under the ignored build tree.

    macOS attaches an Input Monitoring grant to a binary, so the path has to
    outlive the run that compiled it: a temporary directory is reaped, and a
    grant whose target can vanish is worse than no grant. The source digest is
    in the file name instead, so a changed source is visibly a different
    artifact - and, because an unsigned binary's identity is its bytes, one
    that needs the grant again. The reader says so itself when it is refused.
    """
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = BUILD.lstat()
    # Shared with the other host tools' artifacts, so the mode is not pinned;
    # what matters is that it is a real directory this user owns and that no
    # other user can write a binary into it.
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError("unsafe report reader build directory")
    binary = BUILD / ("u2-hid-report-reader-" + digest[:16])
    if not binary.is_file():
        with tempfile.TemporaryDirectory(prefix="u2-hid-reader-", dir=BUILD) as cache:
            result = subprocess.run(
                ["/usr/bin/xcrun", "swiftc", str(SOURCE), "-o", str(binary)],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=600,
                env=dict(os.environ, CLANG_MODULE_CACHE_PATH=str(Path(cache) / "clang"),
                         SWIFT_MODULE_CACHE_PATH=str(Path(cache) / "swift")))
        if result.returncode != 0 or not binary.is_file():
            raise ValueError("report reader compile failed")
    reader = binary.lstat()
    if (not stat.S_ISREG(reader.st_mode) or reader.st_uid != os.getuid() or
            stat.S_IMODE(reader.st_mode) & 0o022):
        raise ValueError("unsafe report reader binary")
    return binary


def parse(argv):
    options = {"name": "reports.txt", "deadline": DEFAULT_DEADLINE,
               "max-reports": DEFAULT_MAXIMUM, "vendor": None, "product": None}
    for item in argv:
        name, _, value = item.partition("=")
        if not name.startswith("--") or not value:
            raise ValueError("usage: see the module docstring")
        options[name[2:]] = value
    if "out-dir" not in options:
        raise ValueError("--out-dir is required")
    for name in ("deadline", "max-reports"):
        options[name] = int(options[name])
    for name in ("vendor", "product"):
        if options[name] is not None and not isinstance(options[name], int):
            options[name] = int(options[name], 0)
    options["name"] = str(options["name"])
    if not NAME.fullmatch(options["name"]):
        raise ValueError("the reports file name must be one plain component")
    if not 1 <= options["deadline"] <= 600 or not 1 <= options["max-reports"] <= 4096:
        raise ValueError("the deadline and the report maximum are both bounded")
    return options


def main(argv):
    options = parse(argv)
    directory = Path(options["out-dir"]).resolve()
    if not directory.is_dir():
        raise ValueError("the caller's evidence directory must exist already")
    target = directory / options["name"]
    if target.exists():
        raise ValueError("the reports file already exists; evidence is never overwritten")
    pair = identifiers(options)
    if pair is None:
        # No device or no control channel: a precondition, said and not waited on.
        print("%s outcome=profile-unavailable reports=0 seized=no "
              "note=no-learned-device-profile-so-nothing-to-match" % PREFIX)
        return EXIT_CODES["profile-unavailable"]
    binary = reader_binary()
    result = subprocess.run(
        [str(binary), "0x%04x" % pair[0], "0x%04x" % pair[1],
         str(options["deadline"]), str(options["max-reports"]), str(target)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=options["deadline"] + 60)
    text = result.stdout.decode("ascii", "replace")
    ENUM["assert_identifier_free"](text)
    print(text, end="" if text.endswith("\n") else "\n")
    label = READER_OUTCOMES.get(result.returncode)
    stated = OUTCOME.search(text)
    if label is None or not stated or stated.group(1) != label:
        raise ValueError("the report reader's exit code and its own label disagree")
    # Only a seized device can have written anything: an empty file is the
    # honest record of a silent function, and nothing at all is the honest
    # record of a device that was never bound.
    if (label in SEIZED) != target.is_file():
        raise ValueError("the reports file and the reader's outcome disagree")
    print("%s file=%s reader=%s" % (PREFIX, target if label in SEIZED else "none", binary))
    return EXIT_CODES[label]


if __name__ == "__main__":
    try:
        if any(item in ("--help", "-h") for item in sys.argv[1:]):
            print(__doc__, end="")
            raise SystemExit(0)
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("%s rejected (%s)" % (PREFIX, error))
        raise SystemExit(1)
