#!/var/jb/usr/bin/python3
"""Classify only the native U2 journal phase and file hash, without writes.

This fixed root-only probe opens the dedicated state directory and journal
through no-follow directory descriptors, checks owner/mode/link/size, verifies
the journal's JSON envelope checksum, and prints only a lifecycle phase and
SHA-256 of the complete file. It does not print the recipe, controller ID,
serial, boot token, or original description. It never calls a USB API or
changes any iPad file. An absent journal is reported without creating one.
"""

import base64
import hashlib
import json
import os
import re
import stat


STATE = "/var/jb/var/lib/mac2jb-u2-native"
NAME = "restore-journal.json"
PHASES = {"prepared", "published", "restoring", "awaitingVerification",
          "recoveryRequired", "restored"}
# The same function-name shape the broker and both shims enforce.
FUNCTION_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")


def exact_read(fd, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise ValueError("short journal")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main():
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("unsafe state directory")
        try:
            fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            print("U2_NATIVE_JOURNAL phase=absent sha256=none")
            return
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                    not 0 < info.st_size <= 2_000_000):
                raise ValueError("unsafe journal")
            data = exact_read(fd, info.st_size)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    envelope = json.loads(data)
    if set(envelope) != {"payload", "sha256"}:
        raise ValueError("unknown envelope")
    payload = base64.b64decode(envelope["payload"], validate=True)
    if hashlib.sha256(payload).hexdigest() != envelope["sha256"]:
        raise ValueError("journal checksum")
    record = json.loads(payload)
    required = {"recipe", "phase", "leaseDeadlineUptime"}
    # Written only while a restore still owes the removal of one appended
    # function; absent before and after. Checked, never printed.
    optional = {"externalVerificationSHA256", "appendedFunctionName",
                "appendedFunctionConfiguration"}
    proof = record.get("externalVerificationSHA256")
    function = record.get("appendedFunctionName")
    configuration = record.get("appendedFunctionConfiguration")
    if (not required <= set(record) or
            not (set(record) - required) <= optional or
            (proof is not None and
             (not isinstance(proof, str) or len(proof) != 64 or
              any(ch not in "0123456789abcdef" for ch in proof))) or
            (function is None) != (configuration is None) or
            (function is not None and
             (not isinstance(function, str) or not FUNCTION_NAME.match(function) or
              not isinstance(configuration, int) or
              isinstance(configuration, bool) or
              not 1 <= configuration <= 255)) or
            record["phase"] not in PHASES):
        raise ValueError("unknown record")
    print("U2_NATIVE_JOURNAL phase=" + record["phase"] +
          " sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        print("U2_NATIVE_JOURNAL rejected")
        raise SystemExit(1)
