#!/var/jb/usr/bin/python3
"""Classify four installed U1 code hashes in Dopamine's trust-cache listing.

What this code does: as root, validate four exact 20-byte CodeDirectory hashes,
run only `jbctl trustcache info` with a six-second and one-MiB output bound,
then report whether each hash appears in the listing. Raw cache contents and
hashes stay on the iPad. This is a read-only query: it never invokes a cache
add, clear, load, signing, SSH, USB, or file-write operation. Normal process
and system accounting logs may occur. A missing listing entry is not proof
that all kernel trust paths reject the binary.
"""

import os
import re
import select
import signal
import stat
import subprocess
import sys
import time


NAMES = ("baseline", "setdescription", "controller-client", "interface-client")
HASH = re.compile(r"[0-9a-f]{40}\Z")
ROW = re.compile(rb"(?m)^\| [0-9]+:[ \t]+([0-9a-f]{40})[ \t]*$")
MAX_OUTPUT = 1024 * 1024
TIMEOUT = 6.0
TOOLS = ("/var/jb/basebin/jbctl", "/var/jb/usr/bin/jbctl")


def choose_tool():
    for path in TOOLS:
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and
                os.access(path, os.X_OK)):
            return path
    return None


def query(path):
    child = subprocess.Popen((path, "trustcache", "info"),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + TIMEOUT
    complete = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select((child.stdout,), (), (), remaining)
            if not readable:
                break
            chunk = os.read(child.stdout.fileno(), min(65536, MAX_OUTPUT + 1 - len(output)))
            if not chunk:
                complete = True
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                break
        if complete:
            remaining = max(0, deadline - time.monotonic())
            try:
                status = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                status = None
        else:
            status = None
        return status, bytes(output), complete and len(output) <= MAX_OUTPUT
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        child.stdout.close()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 5 or not all(
            HASH.fullmatch(value) for value in sys.argv[1:]):
        raise SystemExit(64)
    path = choose_tool()
    if path is None:
        print("TRUST_QUERY tool=unavailable")
        raise SystemExit(65)
    status, output, complete = query(path)
    if status != 0 or not complete:
        print("TRUST_QUERY result=incomplete-or-failed")
        raise SystemExit(66)
    listed = set(ROW.findall(output.lower()))
    if not listed:
        print("TRUST_QUERY result=unrecognized-or-empty-listing")
        raise SystemExit(67)
    for name, digest in zip(NAMES, sys.argv[1:]):
        print("TRUST_QUERY " + name + "=" +
              ("listed" if digest.encode("ascii") in listed else "not-listed-in-query"))


if __name__ == "__main__":
    main()
