#!/usr/bin/env python3
"""Classify the pinned iPad SSH transport without opening a remote session.

What this code does:
1. Accepts no arguments. It securely reads and hash-pins the existing SSH
   identity and known-host record, then stages private mode-0400 copies.
2. Starts one SSH connection to the fixed USB-forwarded endpoint with the
   pinned identity, public key as the only preferred method, password methods
   disabled, ``SessionType=none``, and ``-N``. It also disables commands,
   shells, PTYs, forwarding, agents, X11, alternate known-host sources, and
   host-key updates.
3. Requires OpenSSH to create a private local control socket, which happens
   only after user authentication. The receipt deliberately does not claim
   which method succeeded because SSH may try protocol method ``none`` before
   the preferred method. Bounded diagnostics remain in memory and are used
   only for fixed failure categories. It never prints keys, fingerprints,
   addresses, paths, banners, or raw diagnostics. The local connection is
   terminated as soon as authentication is proven.
4. Bounds the process group, stderr, wall time, and signal cleanup. It creates
   no iPad file and invokes no remote command, shell, subsystem, USB operation,
   daemon-control action, or SSH configuration change. Authentication and
   transport can still create ordinary sshd/accounting logs and transient
   socket/process state.

Trust boundary: honest local account, honest authenticated ``mobile`` account,
and no concurrent same-UID pathname replacement.

Exact invocation: ``/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C TMPDIR=/tmp /usr/bin/python3 -I -S -B
docs/plans/ipad-port/scripts/ipad-hardware/diagnose-ipad-ssh-transport.py``
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time


IDENTITY_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-probe-ed25519")
KNOWN_HOSTS_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-known-hosts")
SSH = Path("/usr/bin/ssh")

EXPECTED_IDENTITY_SHA = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
EXPECTED_KNOWN_HOSTS_SHA = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
SSH_HOST = "127.0.0.1"
SSH_PORT = 2222
SSH_USER = "mobile"
DEADLINE_SECONDS = 10.0
TERMINATE_GRACE = 1.0
MAX_CREDENTIAL_SIZE = 64 * 1024
MAX_DIAGNOSTICS = 64 * 1024
CLEAN_ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}

ACTIVE_PROCESS: subprocess.Popen[bytes] | None = None
RECEIVED_SIGNAL = 0


class Rejection(Exception):
    pass


class Interrupted(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejection(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, maximum: int, allowed_modes: set[int]) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and status.st_nlink == 1
            and status.st_uid == os.getuid()
            and 0 < status.st_size <= maximum
            and stat.S_IMODE(status.st_mode) in allowed_modes,
            f"unsafe pinned input: {path.name}",
        )
        data = bytearray()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= maximum, f"oversized pinned input: {path.name}")
        require(len(data) == status.st_size, f"changed pinned input: {path.name}")
        return bytes(data)
    finally:
        os.close(descriptor)


def write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "short private staging write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def signal_handler(signum: int, _frame: object) -> None:
    global RECEIVED_SIGNAL
    RECEIVED_SIGNAL = signum


def check_signal() -> None:
    if RECEIVED_SIGNAL:
        raise Interrupted()


def terminate_process_group(process: subprocess.Popen[bytes] | None) -> None:
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=TERMINATE_GRACE)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def ssh_command(identity: Path, known_hosts: Path, control_socket: Path) -> list[str]:
    return [
        str(SSH),
        "-F",
        "/dev/null",
        "-N",
        "-T",
        "-vv",
        "-M",
        "-S",
        str(control_socket),
        "-p",
        str(SSH_PORT),
        "-i",
        str(identity),
        "-o",
        "SessionType=none",
        "-o",
        "ControlMaster=yes",
        "-o",
        "ControlPersist=no",
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "KnownHostsCommand=none",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ConnectionAttempts=1",
        f"{SSH_USER}@{SSH_HOST}",
    ]


def fixed_category(diagnostics: bytes) -> str:
    categories = (
        (b"Host key verification failed", "host-key-rejected"),
        (b"Permission denied", "public-key-rejected"),
        (b"Connection refused", "connection-refused"),
        (b"Connection reset", "connection-reset"),
        (b"Connection closed", "connection-closed"),
        (b"Operation timed out", "connection-timeout"),
        (b"Connection timed out", "connection-timeout"),
        (b"No route to host", "no-route"),
        (b"kex_exchange_identification", "key-exchange-rejected"),
    )
    for marker, category in categories:
        if marker in diagnostics:
            return category
    return "unclassified-failure"


def control_socket_proves_authentication(path: Path) -> bool:
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    require(
        stat.S_ISSOCK(status.st_mode)
        and status.st_nlink == 1
        and status.st_uid == os.getuid(),
        "unsafe SSH control socket",
    )
    return True


def classify(identity: Path, known_hosts: Path, control_socket: Path) -> str:
    global ACTIVE_PROCESS
    process = subprocess.Popen(
        ssh_command(identity, known_hosts, control_socket),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=CLEAN_ENVIRONMENT,
        start_new_session=True,
    )
    ACTIVE_PROCESS = process
    assert process.stderr is not None
    os.set_blocking(process.stderr.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    diagnostics = bytearray()
    stderr_open = True
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        while stderr_open or process.poll() is None:
            check_signal()
            require(time.monotonic() < deadline, "SSH diagnostic timed out")
            if control_socket_proves_authentication(control_socket):
                return "authenticated-no-session-method-unverified"
            for key, _mask in selector.select(0.05):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(process.stderr)
                    stderr_open = False
                else:
                    diagnostics.extend(chunk)
                    require(
                        len(diagnostics) <= MAX_DIAGNOSTICS,
                        "SSH diagnostic exceeded output cap",
                    )
            if control_socket_proves_authentication(control_socket):
                return "authenticated-no-session-method-unverified"
        return fixed_category(diagnostics)
    finally:
        selector.close()
        ACTIVE_PROCESS = None
        terminate_process_group(process)


def main() -> int:
    require(len(sys.argv) == 1, "this diagnostic accepts no arguments")
    require(SSH.is_file() and not SSH.is_symlink(), "fixed SSH client unavailable")
    identity = read_regular(IDENTITY_FILE, MAX_CREDENTIAL_SIZE, {0o400, 0o600})
    known_hosts = read_regular(
        KNOWN_HOSTS_FILE,
        MAX_CREDENTIAL_SIZE,
        {0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
    )
    require(sha256(identity) == EXPECTED_IDENTITY_SHA, "identity digest mismatch")
    require(sha256(known_hosts) == EXPECTED_KNOWN_HOSTS_SHA, "known-host digest mismatch")

    for handled in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled, signal_handler)

    with tempfile.TemporaryDirectory(prefix="m2j-ssh-", dir="/tmp") as directory:
        stage = Path(directory)
        stage_status = stage.stat()
        require(
            stat.S_ISDIR(stage_status.st_mode)
            and stage_status.st_uid == os.getuid()
            and stat.S_IMODE(stage_status.st_mode) == 0o700,
            "unsafe private staging directory",
        )
        staged_identity = stage / "identity"
        staged_known_hosts = stage / "known-hosts"
        control_socket = stage / "control.sock"
        write_private(staged_identity, identity)
        write_private(staged_known_hosts, known_hosts)
        require(
            sha256(read_regular(staged_identity, MAX_CREDENTIAL_SIZE, {0o400}))
            == EXPECTED_IDENTITY_SHA,
            "staged identity digest",
        )
        require(
            sha256(read_regular(staged_known_hosts, MAX_CREDENTIAL_SIZE, {0o400}))
            == EXPECTED_KNOWN_HOSTS_SHA,
            "staged known-host digest",
        )
        check_signal()
        category = classify(staged_identity, staged_known_hosts, control_socket)
        check_signal()
    check_signal()
    print(f"SSH_TRANSPORT {category}")
    return 0 if category == "authenticated-no-session-method-unverified" else 65


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Interrupted:
        terminate_process_group(ACTIVE_PROCESS)
        raise SystemExit(128 + RECEIVED_SIGNAL)
    except (OSError, Rejection):
        terminate_process_group(ACTIVE_PROCESS)
        print("SSH_TRANSPORT local-rejected", file=sys.stderr)
        raise SystemExit(65)
