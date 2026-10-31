#!/var/jb/usr/bin/python3
"""Replace one allowlisted U2 broker with another, keeping any active journal.

Effect: `--inspect OLD NEW` is read-only. `--replace OLD NEW` requires the exact
OLD binary and plist with OLD loaded, absent NEW paths, and either no journal
(broker idle, phase absent) or a journal in recoveryRequired/awaitingVerification;
reads the exact NEW binary from stdin; boots OLD out; removes only the stale
socket and OLD's plist; exclusively creates NEW's binary (0755) and plist
(0644, JetsamMemoryLimit 96); bootstraps NEW and requires the same journal
phase. The journal is never modified. No USB controller call.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time

STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
JOURNAL = STATE + "/restore-journal.json"
LAUNCHCTL = "/var/jb/bin/launchctl"
DAEMONS = "/var/jb/Library/LaunchDaemons/"
JETSAM = {"JetsamMemoryLimit": 96, "JetsamPriority": -49}
BROKERS = {
    "v12": ("dev.mac2jb.u2.nooptrialv12", "9629611372c6f570db18064a2cfcd077601f59a1b5a2a4644dbc3bdbefe37a3e"),
    "v11": ("dev.mac2jb.u2.nooptrialv11", "8fdb044ff8840084e27e896432de060deecd6cdc9d27913b9ae3f379077b3736"),
    # The broker that also carries the appending command. The two entries above
    # have no such command compiled in, so a rollback to either removes the
    # capability rather than leaving it unused.
    "v13": ("dev.mac2jb.u2.additivev13", "71cf7b63072919370e2e6b41aa6b249a761cc10ff684aa79fa3a49f6348dcc97"),
}


def binary_path(digest):
    return "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-" + digest[:8]


def description(label, digest):
    return {"Label": label, "ProgramArguments": [binary_path(digest), "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2, "UserName": "root",
            "JetsamProperties": JETSAM}


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def loaded(label):
    return subprocess.run([LAUNCHCTL, "print", "system/" + label], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=6).returncode == 0


def status():
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(5)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128)


def status_when_ready(deadline_seconds):
    """Wait for the newly started broker to answer, then return its reply.

    The broker recovers any journal before it binds its socket, so the socket
    does not exist the moment launchd starts it. A single fixed sleep followed by
    one connect reports a completed swap as a failure when the broker is merely
    slow, which invites an operator to re-run a swap that already happened.
    """
    deadline = time.monotonic() + deadline_seconds
    while True:
        try:
            return status()
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout, OSError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        if os.write(fd, data) != len(data):
            raise ValueError("short write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(mode, old, new):
    if os.geteuid() != 0 or mode not in ("--inspect", "--replace") or old not in BROKERS or new not in BROKERS or old == new:
        raise ValueError("fixed root mode and allowlisted brokers required")
    old_label, old_sha = BROKERS[old]
    new_label, new_sha = BROKERS[new]
    old_plist, new_plist = DAEMONS + old_label + ".plist", DAEMONS + new_label + ".plist"
    if (sha(binary_path(old_sha)) != old_sha or not loaded(old_label) or
            plistlib.loads(open(old_plist, "rb").read()) != description(old_label, old_sha)):
        raise ValueError("old broker stage changed")
    if os.path.lexists(binary_path(new_sha)) or os.path.lexists(new_plist) or loaded(new_label):
        raise ValueError("new broker already present")
    journal_sha = None
    if os.path.lexists(JOURNAL):
        info = os.lstat(JOURNAL)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("journal unsafe")
        journal_sha = sha(JOURNAL)
    before = status()
    allowed = ((b"OK phase=recoveryRequired publication=enabled\n",
                b"OK phase=awaitingVerification publication=enabled\n") if journal_sha
               else (b"OK phase=absent publication=enabled\n",))
    if before not in allowed:
        raise ValueError("broker phase not eligible")
    binary = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if hashlib.sha256(binary).hexdigest() != new_sha:
        raise ValueError("new binary changed")
    if mode == "--inspect":
        print("U2_REPLACE inspect=ready %s->%s %s" % (old, new, before.decode().strip().replace("OK ", "")))
        return
    if subprocess.run([LAUNCHCTL, "bootout", "system/" + old_label], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=10).returncode != 0 or loaded(old_label):
        raise ValueError("old bootout failed")
    if journal_sha and sha(JOURNAL) != journal_sha:
        raise ValueError("journal changed during bootout")
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.path.lexists(SOCKET):
            try:
                status()
                raise ValueError("socket still live")
            except ConnectionRefusedError:
                os.unlink("broker.sock", dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)
    os.unlink(old_plist)
    create(binary_path(new_sha), binary, 0o755)
    create(new_plist, plistlib.dumps(description(new_label, new_sha), fmt=plistlib.FMT_XML), 0o644)
    if subprocess.run([LAUNCHCTL, "bootstrap", "system", new_plist], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=10).returncode != 0:
        raise ValueError("new bootstrap failed")
    after = status_when_ready(60)
    if after != before or (journal_sha and sha(JOURNAL) != journal_sha):
        raise ValueError("new broker state differs after start")
    print("U2_REPLACE replaced %s->%s %s journal=%s" % (old, new, after.decode().strip().replace("OK ", ""),
                                                       "unchanged" if journal_sha else "absent"))


if __name__ == "__main__":
    try:
        main(*(sys.argv[1:4] if len(sys.argv) == 4 else ("", "", "")))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("U2_REPLACE rejected (%s)" % error)
        raise SystemExit(1)
