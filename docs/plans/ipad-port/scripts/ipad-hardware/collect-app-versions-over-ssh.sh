#!/bin/sh
# Read-only SSH collector for Dopamine and TrollStore app versions.
# Do not run until this exact runner and its pinned device payload pass
# adversarial review with an explicit no-persistent-iPad-write finding.
#
# What this code does:
# 1. Pins the SSH key, known-host record, and repository-hosted device payload.
# 2. Streams that payload to one hardened, clean, key-only `mobile` shell. The
#    payload creates a device-timeout-bounded ustar byte stream on stdout from
#    fixed Info.plist roots using root-relative member names; it creates no
#    remote archive or file.
# 3. Bounds the complete SSH process group to 60 seconds and the private local
#    archive to 8 MiB. HUP/INT/TERM and timeout paths kill and reap the client.
# 4. Parses the archive locally without extraction. Every member must be a
#    bounded regular Info.plist at one of three exact path shapes. Python's
#    plist parser accepts only exact bundle IDs and string-typed, sanitized
#    version/build values; duplicate matches fail closed.
# 5. Emits only two fixed sanitized lines, then deletes the archive and all
#    staged credentials/payload copies on every handled exit.
#
# Device effects are limited to reads plus ordinary SSH/tar processes, logs,
# and possible access metadata. Local private temporary files are intentional.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly ssh_host='127.0.0.1'
readonly ssh_port='2222'
readonly ssh_user='mobile'
readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'
readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'
readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'
readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'
readonly expected_payload_sha='55b83cf33bf9d96dd17c3a342bffb7756542d83528789af0de18b148e6bb429e'

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: collect-app-versions-over-ssh.sh' >&2
  exit 64
fi

script_dir=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" 2>/dev/null && pwd -P)
if [ -z "$script_dir" ]; then exit 64; fi
payload="$script_dir/device/u1-readonly-app-plist-archive.sh"

for source_file in "$payload" "$identity_file" "$known_hosts_file"; do
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    command printf '%s\n' 'A required pinned input is unavailable. Nothing was sent.' >&2
    exit 66
  fi
done

current_uid=$(/usr/bin/id -u) || exit 70
identity_uid=$(/usr/bin/stat -f '%u' "$identity_file" 2>/dev/null) || exit 66
known_hosts_uid=$(/usr/bin/stat -f '%u' "$known_hosts_file" 2>/dev/null) || exit 66
identity_mode=$(/usr/bin/stat -f '%Lp' "$identity_file" 2>/dev/null) || exit 66
known_hosts_mode=$(/usr/bin/stat -f '%Lp' "$known_hosts_file" 2>/dev/null) || exit 66
if [ "$identity_uid" != "$current_uid" ] || [ "$known_hosts_uid" != "$current_uid" ]; then exit 66; fi
case "$identity_mode" in 400|600) ;; *) exit 66 ;; esac
case "$known_hosts_mode" in 400|440|444|600|640|644) ;; *) exit 66 ;; esac

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-app-plists.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-app-plists.*) ;; *) exit 70 ;; esac
staged_payload="$temp_dir/payload.sh"
staged_identity="$temp_dir/identity"
staged_known_hosts="$temp_dir/known-hosts"
archive_file="$temp_dir/app-plists.tar"
result_file="$temp_dir/result"
diagnostic_file="$temp_dir/diagnostic"

cleanup() {
  /bin/rm -f "$staged_payload" "$staged_identity" "$staged_known_hosts" \
    "$archive_file" "$result_file" "$diagnostic_file" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

sha256_file() {
  /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/python3 -I -S -c 'import hashlib
import os
import stat
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
status = os.fstat(descriptor)
if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
    raise SystemExit(65)
digest = hashlib.sha256()
total = 0
while True:
    chunk = os.read(descriptor, 65536)
    if not chunk:
        break
    total += len(chunk)
    if total > 2 * 1024 * 1024:
        raise SystemExit(65)
    digest.update(chunk)
os.close(descriptor)
print(digest.hexdigest())' "$1" 2>/dev/null
}

/bin/cp "$payload" "$staged_payload" || exit 70
/bin/cp "$identity_file" "$staged_identity" || exit 70
/bin/cp "$known_hosts_file" "$staged_known_hosts" || exit 70
/bin/chmod 400 "$staged_payload" "$staged_identity" "$staged_known_hosts" || exit 70

payload_sha=$(sha256_file "$staged_payload") || exit 65
identity_sha=$(sha256_file "$staged_identity") || exit 65
known_hosts_sha=$(sha256_file "$staged_known_hosts") || exit 65
if [ "$payload_sha" != "$expected_payload_sha" ] ||
  [ "$identity_sha" != "$expected_identity_sha" ] ||
  [ "$known_hosts_sha" != "$expected_known_hosts_sha" ]; then
  command printf '%s\n' 'A staged digest differs from its reviewed value. Nothing was sent.' >&2
  exit 65
fi

process_runner_code='import os
import signal
import subprocess
import sys

handled = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
received = 0


class Interrupted(Exception):
    pass


def handler(signum, _frame):
    global received
    received = signum
    signal.pthread_sigmask(signal.SIG_BLOCK, handled)
    raise Interrupted()


def kill_and_reap(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait()
    except ChildProcessError:
        pass


previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled)
for item in handled:
    signal.signal(item, handler)


def restore_child_mask():
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


try:
    process = subprocess.Popen(
        sys.argv[2:],
        stdin=None,
        stdout=None,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=restore_child_mask,
    )
except BaseException:
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    raise
try:
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    try:
        status = process.wait(timeout=float(sys.argv[1]))
    except subprocess.TimeoutExpired:
        kill_and_reap(process)
        raise SystemExit(125)
except Interrupted:
    kill_and_reap(process)
    raise SystemExit(128 + received)
except BaseException:
    kill_and_reap(process)
    raise
if status < 0:
    kill_and_reap(process)
    raise SystemExit(125)
raise SystemExit(status)'

remote_command="exec 2>&-; set +euxv; env_path=; for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ -f \"\$candidate\" ] && [ ! -L \"\$candidate\" ] && [ -r \"\$candidate\" ] && [ -x \"\$candidate\" ] && [ ! -w \"\$candidate\" ]; then env_path=\$candidate; break; fi; done; shell_path=; for shell_candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash /var/jb/bin/bash /var/jb/usr/bin/bash; do if [ -f \"\$shell_candidate\" ] && [ ! -L \"\$shell_candidate\" ] && [ -r \"\$shell_candidate\" ] && [ -x \"\$shell_candidate\" ] && [ ! -w \"\$shell_candidate\" ]; then shell_path=\$shell_candidate; break; fi; done; if [ -z \"\$env_path\" ]; then exit 127; fi; if [ -z \"\$shell_path\" ]; then exit 126; fi; \"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C \"\$shell_path\" -s"

(
  ulimit -f 16384 2>/dev/null || exit 70
  exec /usr/bin/env -i PATH="$PATH" LC_ALL=C \
    /usr/bin/python3 -I -S -c "$process_runner_code" 60 /usr/bin/ssh \
    -F /dev/null -T -p "$ssh_port" -i "$staged_identity" \
    -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$staged_known_hosts" \
    -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o UpdateHostKeys=no \
    -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no \
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes \
    -o RequestTTY=no -o ControlMaster=no -o ControlPath=none \
    -o ConnectTimeout=10 -o ConnectionAttempts=1 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
    -o NumberOfPasswordPrompts=0 -o LogLevel=ERROR \
    "$ssh_user@$ssh_host" "$remote_command"
) < "$staged_payload" > "$archive_file" 2>/dev/null
ssh_status=$?
if [ "$ssh_status" -ne 0 ]; then
  command printf 'SSH or the remote archive payload failed with status %s; archive discarded.\n' "$ssh_status" >&2
  exit 69
fi

/usr/bin/env -i PATH="$PATH" LC_ALL=C \
  /usr/bin/python3 -I -S -c "$process_runner_code" 10 /usr/bin/python3 -I -S -c 'import atexit
import os
from pathlib import PurePosixPath
import plistlib
import re
import stat
import struct
import sys

source, output, diagnostic = sys.argv[1:]
stage = "archive-file"
accepted = False


def record_rejection_stage():
    if accepted:
        return
    try:
        descriptor = os.open(
            diagnostic,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.write(descriptor, (stage + "\n").encode("ascii"))
        os.close(descriptor)
    except OSError:
        pass


atexit.register(record_rejection_stage)
descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
status = os.fstat(descriptor)
if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
    raise SystemExit(65)
if not 1024 <= status.st_size <= 8 * 1024 * 1024 or status.st_size % 512 != 0:
    raise SystemExit(65)
archive_bytes = bytearray()
while True:
    chunk = os.read(descriptor, 65536)
    if not chunk:
        break
    archive_bytes.extend(chunk)
os.close(descriptor)
if len(archive_bytes) != status.st_size:
    raise SystemExit(65)

safe_value = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_() -]{0,63}")
stealth_prefix = "com.opa334.TrollStore.TS_"
found = {"dopamine": [], "trollstore": []}
names = set()
total_size = 0
missing_value = object()


def allowed_name(name):
    path = PurePosixPath(name)
    parts = path.parts
    if name != path.as_posix() or path.is_absolute() or any(part in ("", ".", "..") for part in parts):
        return False
    def target_app(component):
        return component.endswith(".app") and (
            component.startswith("Dopamine") or component.startswith("TrollStore")
        )
    if len(parts) == 7 and parts[:4] == ("var", "containers", "Bundle", "Application"):
        return bool(parts[4]) and target_app(parts[5]) and parts[6] == "Info.plist"
    if len(parts) == 3 and parts[0] == "Applications":
        return target_app(parts[1]) and parts[2] == "Info.plist"
    if len(parts) == 5 and parts[:3] == ("var", "jb", "Applications"):
        return target_app(parts[3]) and parts[4] == "Info.plist"
    return False


def octal_value(field):
    stripped = field.strip(b"\0 ")
    if not stripped or any(byte < 48 or byte > 55 for byte in stripped):
        raise ValueError("invalid ustar octal field")
    return int(stripped, 8)


def text_field(field):
    nul = field.find(0)
    if nul >= 0:
        if any(field[nul:]):
            raise ValueError("nonzero ustar field padding")
        field = field[:nul]
    return bytes(field).decode("utf-8")


entries = []
position = 0
zero_block = bytes(512)
stage = "ustar-structure"
while True:
    if position + 1024 > len(archive_bytes):
        raise SystemExit(65)
    header = bytes(archive_bytes[position:position + 512])
    if header == zero_block:
        if bytes(archive_bytes[position + 512:position + 1024]) != zero_block:
            raise SystemExit(65)
        if any(archive_bytes[position + 1024:]):
            raise SystemExit(65)
        break
    if len(entries) >= 64:
        raise SystemExit(65)
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        raise SystemExit(65)
    if header[156:157] not in (b"0", b"\0") or any(header[500:512]):
        raise SystemExit(65)
    if text_field(header[157:257]):
        raise SystemExit(65)
    stored_checksum = octal_value(header[148:156])
    computed_checksum = sum(header[:148]) + (8 * 32) + sum(header[156:])
    if stored_checksum != computed_checksum:
        raise SystemExit(65)
    member_size = octal_value(header[124:136])
    if not 0 < member_size <= 1024 * 1024:
        raise SystemExit(65)
    name = text_field(header[0:100])
    prefix = text_field(header[345:500])
    if prefix:
        name = prefix + "/" + name
    if not name or not allowed_name(name) or name in names:
        raise SystemExit(65)
    names.add(name)
    data_start = position + 512
    data_end = data_start + member_size
    padded_end = data_start + ((member_size + 511) // 512 * 512)
    if padded_end > len(archive_bytes) or any(archive_bytes[data_end:padded_end]):
        raise SystemExit(65)
    content = bytes(archive_bytes[data_start:data_end])
    entries.append((name, content))
    total_size += member_size
    if total_size > 8 * 1024 * 1024:
        raise SystemExit(65)
    position = padded_end


class RejectingDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise ValueError("duplicate plist key")
        super().__setitem__(key, value)


def prevalidate_binary_plist(content):
    if not content.startswith(b"bplist00"):
        return
    if len(content) < 40:
        raise ValueError("truncated binary plist")
    offset_size, reference_size, object_count, top_object, offset_table = struct.unpack(
        ">6xBBQQQ", content[-32:]
    )
    if offset_size not in (1, 2, 4, 8) or reference_size not in (1, 2, 4, 8):
        raise ValueError("invalid binary plist integer width")
    if not 0 < object_count <= 65536 or top_object >= object_count:
        raise ValueError("invalid binary plist object count")
    table_size = object_count * offset_size
    if offset_table < 8 or offset_table + table_size != len(content) - 32:
        raise ValueError("invalid binary plist offset table")
    offsets = [
        int.from_bytes(content[position:position + offset_size], "big")
        for position in range(offset_table, offset_table + table_size, offset_size)
    ]
    if len(set(offsets)) != object_count or any(value < 8 or value >= offset_table for value in offsets):
        raise ValueError("invalid binary plist object offsets")
    references = {index: [] for index in range(object_count)}
    extents = []
    reference_count = 0

    def sized_count(offset, token_low):
        cursor = offset + 1
        if token_low < 15:
            return token_low, cursor
        if cursor >= offset_table:
            raise ValueError("truncated binary plist count")
        marker = content[cursor]
        marker_high, marker_low = marker & 0xF0, marker & 0x0F
        if marker_high != 0x10 or marker_low > 3:
            raise ValueError("invalid binary plist count marker")
        width = 1 << marker_low
        end = cursor + 1 + width
        if end > offset_table:
            raise ValueError("truncated binary plist count")
        return int.from_bytes(content[cursor + 1:end], "big"), end

    for object_index, offset in enumerate(offsets):
        token = content[offset]
        token_high, token_low = token & 0xF0, token & 0x0F
        cursor = offset + 1
        if token in (0x00, 0x08, 0x09, 0x0F):
            end = cursor
        elif token_high == 0x10:
            if token_low > 3:
                raise ValueError("oversized binary plist integer")
            end = cursor + (1 << token_low)
        elif token == 0x22:
            end = cursor + 4
        elif token in (0x23, 0x33):
            end = cursor + 8
        elif token_high in (0x40, 0x50, 0x60, 0xA0, 0xD0):
            count, cursor = sized_count(offset, token_low)
            if count > 1048576:
                raise ValueError("oversized binary plist object")
            if token_high in (0x40, 0x50):
                end = cursor + count
            elif token_high == 0x60:
                end = cursor + (count * 2)
            else:
                multiplier = 2 if token_high == 0xD0 else 1
                reference_bytes = count * reference_size * multiplier
                end = cursor + reference_bytes
                if end > offset_table:
                    raise ValueError("truncated binary plist references")
                object_references = [
                    int.from_bytes(content[position:position + reference_size], "big")
                    for position in range(cursor, end, reference_size)
                ]
                if any(reference >= object_count for reference in object_references):
                    raise ValueError("invalid binary plist reference")
                references[object_index] = object_references
                reference_count += len(object_references)
                if reference_count > 131072:
                    raise ValueError("oversized binary plist reference graph")
        elif token_high == 0x80:
            end = cursor + token_low + 1
        else:
            raise ValueError("unsupported binary plist object")
        if end > offset_table:
            raise ValueError("binary plist object exceeds object table")
        extents.append((offset, end))

    ordered_extents = sorted(extents)
    if ordered_extents[0][0] != 8 or ordered_extents[-1][1] != offset_table:
        raise ValueError("binary plist object table has hidden bytes")
    for (_start, end), (next_start, _next_end) in zip(ordered_extents, ordered_extents[1:]):
        if end != next_start:
            raise ValueError("binary plist objects overlap or have gaps")

    visiting = set()
    visited = set()

    def visit(reference, depth):
        if depth > 128 or reference in visiting:
            raise ValueError("invalid binary plist graph")
        if reference in visited:
            return
        visiting.add(reference)
        for child in references[reference]:
            visit(child, depth + 1)
        visiting.remove(reference)
        visited.add(reference)

    visit(top_object, 0)
    if len(visited) != object_count:
        raise ValueError("binary plist contains unreachable objects")


for _name, content in entries:
    stage = "binary-plist-structure"
    prevalidate_binary_plist(content)
    stage = "plist-decode"
    document = plistlib.loads(content, dict_type=RejectingDict)
    if not isinstance(document, dict):
        raise SystemExit(65)
    stage = "app-bundle-type"
    bundle = document.get("CFBundleIdentifier")
    if bundle is not None and not isinstance(bundle, str):
        raise SystemExit(65)
    if bundle == "com.opa334.Dopamine":
        label, family = "dopamine", "standard"
    elif bundle == "com.opa334.TrollStore":
        label, family = "trollstore", "standard"
    elif isinstance(bundle, str) and bundle.startswith(stealth_prefix) and len(bundle) > len(stealth_prefix):
        label, family = "trollstore", "stealth"
    else:
        continue
    version = document.get("CFBundleShortVersionString", missing_value)
    build = document.get("CFBundleVersion")
    if version is missing_value:
        if label == "trollstore":
            version = "not-present"
        else:
            stage = label + "-version-missing"
            raise SystemExit(65)
    if version is None:
        stage = label + "-version-null"
        raise SystemExit(65)
    if isinstance(version, bool):
        stage = label + "-version-boolean"
        raise SystemExit(65)
    if isinstance(version, int):
        stage = label + "-version-integer"
        raise SystemExit(65)
    if isinstance(version, float):
        stage = label + "-version-real"
        raise SystemExit(65)
    stage = label + "-version-other-type"
    if not isinstance(version, str):
        raise SystemExit(65)
    stage = "app-build-type"
    if not isinstance(build, str):
        raise SystemExit(65)
    stage = "app-version-grammar"
    if not safe_value.fullmatch(version):
        raise SystemExit(65)
    stage = "app-build-grammar"
    if not safe_value.fullmatch(build):
        raise SystemExit(65)
    found[label].append((version, build, family))

stage = "app-ambiguity"
for values in found.values():
    if len(values) > 1:
        raise SystemExit(66)


def render(label):
    values = found[label]
    if not values:
        return f"{label}-app: not-observed"
    version, build, family = values[0]
    return f"{label}-app: version={version} build={build} bundle-family={family}"

stage = "result-write"
lines = [render("dopamine"), render("trollstore")]
result = ("\n".join(lines) + "\n").encode("ascii")
target = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.write(target, result)
os.close(target)
accepted = True
' "$archive_file" "$result_file" "$diagnostic_file" 2>/dev/null || {
  rejection_stage=
  if [ -f "$diagnostic_file" ] && [ ! -L "$diagnostic_file" ]; then
    rejection_stage=$(/bin/cat "$diagnostic_file" 2>/dev/null)
  fi
  case "$rejection_stage" in
    archive-file|ustar-structure|binary-plist-structure|plist-decode|app-bundle-type|dopamine-version-missing|dopamine-version-null|dopamine-version-boolean|dopamine-version-integer|dopamine-version-real|dopamine-version-other-type|trollstore-version-missing|trollstore-version-null|trollstore-version-boolean|trollstore-version-integer|trollstore-version-real|trollstore-version-other-type|app-build-type|app-version-grammar|app-build-grammar|app-ambiguity|result-write)
      command printf 'The private app archive was rejected at local validation stage: %s; output discarded.\n' "$rejection_stage" >&2
      ;;
    *)
      command printf '%s\n' 'The private app archive was malformed, ambiguous, or unsafe; output discarded.' >&2
      ;;
  esac
  exit 65
}

line_count=$(/usr/bin/wc -l < "$result_file" | /usr/bin/tr -d ' ')
if [ "$line_count" != 2 ]; then exit 65; fi
/bin/cat "$result_file"
