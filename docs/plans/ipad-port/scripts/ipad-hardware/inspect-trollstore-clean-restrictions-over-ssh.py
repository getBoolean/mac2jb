#!/usr/bin/env python3
"""Capture whether TrollStore 2.1.1 cleanRestrictions() is a no-op now.

What this code does:
1. Before network access, it opens the exact device payload, SSH identity, and
   known-host record with ``O_NOFOLLOW|O_NONBLOCK``; requires regular,
   single-link, current-owner, bounded inputs with safe modes; pins every byte
   by SHA-256; and stages private mode-0400 copies.
2. It streams the payload into one fresh key-only ``mobile`` SSH shell. The
   child has a complete process group, a thirty-second wall deadline, no
   transport stderr, and a 2 MiB parent-enforced stdout cap. HUP/INT/TERM,
   timeout, output overflow, SSH failure, or a descendant retaining the pipe
   kills and reaps the complete local group.
3. It accepts only the payload's exact ``ABSENT`` result or one bounded,
   checksum-validated regular ustar member for TrollStore's fixed
   ClientTruth.plist. Unused metadata fields carry no authority. The plist is
   parsed only in memory with duplicate-key rejection. No raw profile value,
   path-derived identifier, archive, or plist is written to disk or printed.
4. It returns success only when the captured plist is absent or the exact
   nested ``removedSystemAppBundleIDs.values`` state is absent/empty. Any
   non-empty, malformed, unreadable, ambiguous, or hostile captured state is
   rejected. This is point-in-time evidence only: it never authorizes a later
   installation, because a concurrent writer could change the plist after the
   capture.

This inspector is observational/read-only. It never invokes TrollStore,
cleanRestrictions, profiled, registration, USB, SSH configuration, or a remote
write command. Reads can affect access metadata; SSH/tar/timeout and the OS may
create ordinary logs and transient processes. Its trust boundary is the
project's documented honest local account and honest authenticated ``mobile``
account with no concurrent same-UID pathname replacement; either account can
already control its own SSH process or credentials outside this inspector.

Exact invocation: ``python3 scripts/ipad-hardware/inspect-trollstore-clean-restrictions-over-ssh.py``
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import plistlib
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time


SOURCE_FILE = Path(__file__).resolve()
SCRIPT_DIRECTORY = SOURCE_FILE.parent
PAYLOAD = SCRIPT_DIRECTORY / "device/u1-readonly-trollstore-clean-restrictions-input.sh"
IDENTITY_FILE = Path("/tmp/mac2jb-ipad-probe-ed25519")
KNOWN_HOSTS_FILE = Path("/tmp/mac2jb-ipad-known-hosts")
SSH = Path("/usr/bin/ssh")

EXPECTED_PAYLOAD_SHA = "4efb71dad88cc4257ba75282a0824dc1123797e14d47c768a71dfd49029fd95e"
EXPECTED_IDENTITY_SHA = "c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f"
EXPECTED_KNOWN_HOSTS_SHA = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
EXPECTED_MEMBER = "private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"

SSH_HOST = "127.0.0.1"
SSH_PORT = 2222
SSH_USER = "mobile"
SSH_TIMEOUT = 30.0
TERMINATE_GRACE = 1.0
MAX_PAYLOAD_SIZE = 64 * 1024
MAX_CREDENTIAL_SIZE = 64 * 1024
MAX_TRANSPORT_OUTPUT = 2 * 1024 * 1024
MAX_PLIST_SIZE = 1024 * 1024
CLEAN_ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}

ACTIVE_PROCESS: subprocess.Popen[bytes] | None = None
RECEIVED_SIGNAL = 0
MISSING = object()


class Rejection(Exception):
    pass


class NonNoopRestrictions(Exception):
    def __init__(self, count: int) -> None:
        super().__init__(f"cleanRestrictions input contains {count} entries")
        self.count = count


class Interrupted(Exception):
    pass


class DuplicateRejectingDict(dict[object, object]):
    def __setitem__(self, key: object, value: object) -> None:
        if key in self:
            raise Rejection("duplicate plist key")
        super().__setitem__(key, value)


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


def ssh_command(identity: Path, known_hosts: Path) -> list[str]:
    remote_command = (
        "exec 2>&-; set +euxv; env_path=; "
        "for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do "
        "if [ -f \"$candidate\" ] && [ ! -L \"$candidate\" ] && "
        "[ -r \"$candidate\" ] && [ -x \"$candidate\" ] && [ ! -w \"$candidate\" ]; "
        "then env_path=$candidate; break; fi; done; shell_path=; "
        "for candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash "
        "/var/jb/bin/bash /var/jb/usr/bin/bash; do "
        "if [ -f \"$candidate\" ] && [ ! -L \"$candidate\" ] && "
        "[ -r \"$candidate\" ] && [ -x \"$candidate\" ] && [ ! -w \"$candidate\" ]; "
        "then shell_path=$candidate; break; fi; done; "
        "[ -n \"$env_path\" ] || exit 127; [ -n \"$shell_path\" ] || exit 126; "
        "exec \"$env_path\" -i "
        "PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' "
        "LC_ALL=C \"$shell_path\" -s"
    )
    return [
        str(SSH),
        "-F",
        "/dev/null",
        "-T",
        "-p",
        str(SSH_PORT),
        "-i",
        str(identity),
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
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "LogLevel=ERROR",
        f"{SSH_USER}@{SSH_HOST}",
        remote_command,
    ]


def capture(payload: Path, identity: Path, known_hosts: Path) -> bytes:
    global ACTIVE_PROCESS
    with payload.open("rb", buffering=0) as payload_stream:
        process = subprocess.Popen(
            ssh_command(identity, known_hosts),
            stdin=payload_stream,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=CLEAN_ENVIRONMENT,
            start_new_session=True,
        )
        ACTIVE_PROCESS = process
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        stdout_open = True
        deadline = time.monotonic() + SSH_TIMEOUT
        try:
            while stdout_open or process.poll() is None:
                check_signal()
                require(time.monotonic() < deadline, "SSH capture timed out")
                for key, _mask in selector.select(0.05):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(process.stdout)
                        stdout_open = False
                    else:
                        output.extend(chunk)
                        require(
                            len(output) <= MAX_TRANSPORT_OUTPUT,
                            "SSH capture exceeded output cap",
                        )
            status = process.wait()
            failure_categories = {
                66: "device-input-inaccessible",
                67: "device-input-unsafe",
                68: "device-tar-unavailable",
                69: "device-timeout-unavailable",
                124: "device-archive-timeout",
                255: "ssh-transport-failed",
            }
            require(
                status == 0,
                f"capture-category={failure_categories.get(status, 'remote-rejected')}",
            )
            return bytes(output)
        finally:
            try:
                selector.close()
            finally:
                ACTIVE_PROCESS = None
                terminate_process_group(process)


def octal_value(field: bytes) -> int:
    stripped = field.strip(b"\0 ")
    require(
        bool(stripped) and all(48 <= byte <= 55 for byte in stripped),
        "invalid ustar octal field",
    )
    return int(stripped, 8)


def text_field(field: bytes) -> str:
    nul = field.find(0)
    if nul >= 0:
        require(not any(field[nul:]), "nonzero ustar text padding")
        field = field[:nul]
    try:
        return field.decode("utf-8")
    except UnicodeError as error:
        raise Rejection("invalid ustar text") from error


def parse_archive(data: bytes) -> bytes:
    zero = bytes(512)
    position = 0
    content: bytes | None = None
    while True:
        require(position + 1024 <= len(data), "archive lacks terminal zero blocks")
        header = data[position : position + 512]
        if header == zero:
            require(data[position + 512 : position + 1024] == zero, "one zero block")
            require(not any(data[position + 1024 :]), "archive trailing content")
            break
        require(content is None, "archive contains multiple members")
        require(
            header[257:263] == b"ustar\0"
            and header[263:265] == b"00"
            and not any(header[500:512]),
            "archive is not supported ustar",
        )
        require(header[156:157] in (b"\0", b"0"), "archive member is not regular")
        require(not text_field(header[157:257]), "archive member has link target")
        stored_checksum = octal_value(header[148:156])
        computed_checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
        require(stored_checksum == computed_checksum, "archive checksum")
        name = text_field(header[0:100])
        prefix = text_field(header[345:500])
        if prefix:
            name = f"{prefix}/{name}"
        require(name == EXPECTED_MEMBER, "unexpected archive member")
        size = octal_value(header[124:136])
        require(0 < size <= MAX_PLIST_SIZE, "unsafe plist size")
        data_start = position + 512
        data_end = data_start + size
        padded_end = data_start + ((size + 511) // 512 * 512)
        require(padded_end <= len(data), "truncated archive member")
        require(not any(data[data_end:padded_end]), "nonzero archive padding")
        content = data[data_start:data_end]
        position = padded_end
    require(content is not None, "archive has no plist")
    return content


def nested_noop_reason(document: object) -> str:
    require(isinstance(document, dict), "plist root is not dictionary")
    app_removal = document.get("com.apple.lsd.appremoval", MISSING)
    if app_removal is MISSING:
        return "restriction field absent"
    require(isinstance(app_removal, dict), "app-removal field type")
    client_restrictions = app_removal.get("clientRestrictions", MISSING)
    if client_restrictions is MISSING:
        return "restriction field absent"
    require(isinstance(client_restrictions, dict), "client-restrictions field type")
    union = client_restrictions.get("union", MISSING)
    if union is MISSING:
        return "restriction field absent"
    require(isinstance(union, dict), "union field type")
    removed = union.get("removedSystemAppBundleIDs", MISSING)
    if removed is MISSING:
        return "restriction field absent"
    require(isinstance(removed, dict), "removed-app field type")
    values = removed.get("values", MISSING)
    if values is MISSING:
        return "restriction field absent"
    require(isinstance(values, list), "removed-app values type")
    if values:
        raise NonNoopRestrictions(len(values))
    return "removed-app values empty"


def prevalidate_binary_plist(content: bytes) -> None:
    """Reject malformed, cyclic, hidden, or resource-amplifying bplist graphs."""
    if not content.startswith(b"bplist00"):
        return
    require(len(content) >= 40, "truncated binary plist")
    offset_size, reference_size, object_count, top_object, offset_table = struct.unpack(
        ">6xBBQQQ", content[-32:]
    )
    require(
        offset_size in (1, 2, 4, 8) and reference_size in (1, 2, 4, 8),
        "invalid binary plist integer width",
    )
    require(
        0 < object_count <= 65536 and top_object < object_count,
        "invalid binary plist object count",
    )
    table_size = object_count * offset_size
    require(
        offset_table >= 8 and offset_table + table_size == len(content) - 32,
        "invalid binary plist offset table",
    )
    offsets = [
        int.from_bytes(content[position : position + offset_size], "big")
        for position in range(offset_table, offset_table + table_size, offset_size)
    ]
    require(
        len(set(offsets)) == object_count
        and all(8 <= value < offset_table for value in offsets),
        "invalid binary plist object offsets",
    )
    references: dict[int, list[int]] = {index: [] for index in range(object_count)}
    extents: list[tuple[int, int]] = []
    reference_count = 0

    def sized_count(offset: int, token_low: int) -> tuple[int, int]:
        cursor = offset + 1
        if token_low < 15:
            return token_low, cursor
        require(cursor < offset_table, "truncated binary plist count")
        marker = content[cursor]
        marker_high, marker_low = marker & 0xF0, marker & 0x0F
        require(
            marker_high == 0x10 and marker_low <= 3,
            "invalid binary plist count marker",
        )
        width = 1 << marker_low
        end = cursor + 1 + width
        require(end <= offset_table, "truncated binary plist count")
        return int.from_bytes(content[cursor + 1 : end], "big"), end

    for object_index, offset in enumerate(offsets):
        token = content[offset]
        token_high, token_low = token & 0xF0, token & 0x0F
        cursor = offset + 1
        if token in (0x00, 0x08, 0x09, 0x0F):
            end = cursor
        elif token_high == 0x10:
            require(token_low <= 3, "oversized binary plist integer")
            end = cursor + (1 << token_low)
        elif token == 0x22:
            end = cursor + 4
        elif token in (0x23, 0x33):
            end = cursor + 8
        elif token_high in (0x40, 0x50, 0x60, 0xA0, 0xD0):
            count, cursor = sized_count(offset, token_low)
            require(count <= 1048576, "oversized binary plist object")
            if token_high in (0x40, 0x50):
                end = cursor + count
            elif token_high == 0x60:
                end = cursor + (count * 2)
            else:
                multiplier = 2 if token_high == 0xD0 else 1
                end = cursor + (count * reference_size * multiplier)
                require(end <= offset_table, "truncated binary plist references")
                object_references = [
                    int.from_bytes(content[position : position + reference_size], "big")
                    for position in range(cursor, end, reference_size)
                ]
                require(
                    all(reference < object_count for reference in object_references),
                    "invalid binary plist reference",
                )
                references[object_index] = object_references
                reference_count += len(object_references)
                require(
                    reference_count <= 131072,
                    "oversized binary plist reference graph",
                )
        elif token_high == 0x80:
            end = cursor + token_low + 1
        else:
            raise Rejection("unsupported binary plist object")
        require(end <= offset_table, "binary plist object exceeds object table")
        extents.append((offset, end))

    ordered_extents = sorted(extents)
    require(
        ordered_extents[0][0] == 8 and ordered_extents[-1][1] == offset_table,
        "binary plist object table has hidden bytes",
    )
    for (_start, end), (next_start, _next_end) in zip(
        ordered_extents, ordered_extents[1:]
    ):
        require(end == next_start, "binary plist objects overlap or have gaps")

    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(reference: int, depth: int) -> None:
        require(depth <= 128 and reference not in visiting, "invalid binary plist graph")
        if reference in visited:
            return
        visiting.add(reference)
        for child in references[reference]:
            visit(child, depth + 1)
        visiting.remove(reference)
        visited.add(reference)

    visit(top_object, 0)
    require(len(visited) == object_count, "binary plist contains unreachable objects")


def inspect_capture(data: bytes) -> str:
    if data == b"ABSENT\n":
        return "ClientTruth absent"
    require(data.startswith(b"ARCHIVE\n"), "unexpected payload grammar")
    plist_data = parse_archive(data.removeprefix(b"ARCHIVE\n"))
    require(
        plist_data.startswith(b"bplist00")
        or plist_data.lstrip().startswith(b"<?xml"),
        "plist encoding is unsupported",
    )
    prevalidate_binary_plist(plist_data)
    try:
        document = plistlib.loads(plist_data, dict_type=DuplicateRejectingDict)
    except Rejection:
        raise
    except (OverflowError, plistlib.InvalidFileException, TypeError, ValueError) as error:
        raise Rejection("invalid ClientTruth plist") from error
    return nested_noop_reason(document)


def main() -> int:
    require(len(sys.argv) == 1, "this inspector accepts no arguments")
    require(SSH.is_file() and not SSH.is_symlink(), "fixed SSH client unavailable")
    payload = read_regular(PAYLOAD, MAX_PAYLOAD_SIZE, {0o400, 0o440, 0o444, 0o500, 0o550, 0o555, 0o600, 0o640, 0o644, 0o700, 0o750, 0o755})
    identity = read_regular(IDENTITY_FILE, MAX_CREDENTIAL_SIZE, {0o400, 0o600})
    known_hosts = read_regular(
        KNOWN_HOSTS_FILE,
        MAX_CREDENTIAL_SIZE,
        {0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
    )
    require(sha256(payload) == EXPECTED_PAYLOAD_SHA, "payload digest mismatch")
    require(sha256(identity) == EXPECTED_IDENTITY_SHA, "identity digest mismatch")
    require(sha256(known_hosts) == EXPECTED_KNOWN_HOSTS_SHA, "known-host digest mismatch")

    for handled in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled, signal_handler)

    with tempfile.TemporaryDirectory(prefix="mac2jb-clean-restrictions-") as directory:
        stage = Path(directory)
        staged_payload = stage / "payload.sh"
        staged_identity = stage / "identity"
        staged_known_hosts = stage / "known-hosts"
        write_private(staged_payload, payload)
        write_private(staged_identity, identity)
        write_private(staged_known_hosts, known_hosts)
        require(
            sha256(read_regular(staged_payload, MAX_PAYLOAD_SIZE, {0o400}))
            == EXPECTED_PAYLOAD_SHA,
            "staged payload digest",
        )
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
        captured = capture(staged_payload, staged_identity, staged_known_hosts)
        check_signal()
        reason = inspect_capture(captured)
        check_signal()
    check_signal()
    print(f"PASS cleanRestrictions snapshot is no-op: {reason}; not install authorization")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NonNoopRestrictions as error:
        terminate_process_group(ACTIVE_PROCESS)
        print(
            f"BLOCKED cleanRestrictions input contains {error.count} entries; values withheld",
            file=sys.stderr,
        )
        raise SystemExit(78)
    except Interrupted:
        terminate_process_group(ACTIVE_PROCESS)
        raise SystemExit(128 + RECEIVED_SIGNAL)
    except (OSError, Rejection) as error:
        terminate_process_group(ACTIVE_PROCESS)
        print(f"REJECTED: {error}", file=sys.stderr)
        raise SystemExit(65)
