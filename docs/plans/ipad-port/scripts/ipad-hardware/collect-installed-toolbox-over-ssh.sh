#!/bin/sh
# Read-only post-install collector for the MAC2JB U1 TrollStore toolbox.
# The owner dropped mandatory adversarial reviews on 2026-10-30; keep the
# exact input and read-only checks below before collecting device evidence.
#
# What this code does:
# 1. Refuses to contact the iPad if the fixed local evidence directory or its
#    fixed crash-recovery staging directory already exists. It then pins private
#    copies of the SSH credentials, device payload, and validator by SHA-256.
# 2. Streams the payload to one clean key-only `mobile` SSH shell. The payload
#    finds exactly one fixed-name toolbox app and emits a device-timeout-bounded
#    ustar stream to stdout without creating a remote file or launching code.
# 3. Bounds the SSH process group to sixty seconds, caps the archive at 16 MiB,
#    then bounds the isolated validator process group to twenty seconds. Handled
#    signals are forwarded; timeout and signal paths kill and reap the full
#    active local process group.
# 4. The validator accepts only the reviewed app layout, ownership and modes;
#    exact TrollStore-adjusted metadata; installed code pages, entitlements,
#    and code identity against the signed package. It publishes
#    the normalized app and manifest with a Darwin no-replace rename after
#    syncing files and directories. The random container component is omitted.
#
# Device effects are limited to reads, transient processes, possible access
# metadata, and ordinary SSH/tar logs. Local evidence files are intentional.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly ssh_host='127.0.0.1'
readonly ssh_port='2222'
readonly ssh_user='mobile'
readonly identity_file='/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-probe-ed25519'
readonly known_hosts_file='/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-known-hosts'
readonly expected_identity_sha='50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd'
readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'
readonly expected_payload_sha='97f8132e2ebcb2bd100040bc32cc91acf52b7496d301cfdb5f678b3c8216f7e8'
readonly expected_validator_sha='4b82e513f5573c01867ef2747fac540583a1ca48ccb15880583595b06fd882f0'

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: collect-installed-toolbox-over-ssh.sh' >&2
  exit 64
fi

script_dir=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" 2>/dev/null && pwd -P) || exit 64
repo_root=$(CDPATH= cd -P "$script_dir/../../../../.." 2>/dev/null && pwd -P) || exit 64
payload="$script_dir/device/u1-readonly-installed-toolbox-archive.sh"
validator="$script_dir/validate-installed-toolbox-trollstore.py"
evidence_parent="$repo_root/build/ipad-hardware"
evidence_directory="$evidence_parent/installed-toolbox-attestation"
staging_directory="$evidence_parent/.installed-toolbox-attestation.staging"

if [ -e "$evidence_directory" ] || [ -L "$evidence_directory" ] ||
  [ -e "$staging_directory" ] || [ -L "$staging_directory" ]; then
  command printf '%s\n' 'Fixed local evidence or stale staging already exists. Nothing was sent.' >&2
  exit 65
fi
for source_file in "$payload" "$validator" "$identity_file" "$known_hosts_file"; do
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    command printf '%s\n' 'A required pinned input is unavailable. Nothing was sent.' >&2
    exit 66
  fi
done

current_uid=$(/usr/bin/id -u) || exit 70
for credential in "$identity_file" "$known_hosts_file"; do
  credential_uid=$(/usr/bin/stat -f '%u' "$credential" 2>/dev/null) || exit 66
  if [ "$credential_uid" != "$current_uid" ]; then exit 66; fi
done
identity_mode=$(/usr/bin/stat -f '%Lp' "$identity_file" 2>/dev/null) || exit 66
known_hosts_mode=$(/usr/bin/stat -f '%Lp' "$known_hosts_file" 2>/dev/null) || exit 66
case "$identity_mode" in 400|600) ;; *) exit 66 ;; esac
case "$known_hosts_mode" in 400|440|444|600|640|644) ;; *) exit 66 ;; esac

if [ ! -d "$evidence_parent" ] || [ -L "$evidence_parent" ]; then
  command printf '%s\n' 'The fixed local evidence parent is unavailable. Nothing was sent.' >&2
  exit 66
fi

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-toolbox-attestation.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-toolbox-attestation.*) ;; *) exit 70 ;; esac
staged_payload="$temp_dir/payload.sh"
staged_validator="$temp_dir/validator.py"
staged_identity="$temp_dir/identity"
staged_known_hosts="$temp_dir/known-hosts"
archive_file="$temp_dir/toolbox.tar"
result_file="$temp_dir/result"
active_runner_pid=

stop_active_runner() {
  if [ -n "$active_runner_pid" ]; then
    /bin/kill -TERM "$active_runner_pid" 2>/dev/null
    wait "$active_runner_pid" 2>/dev/null
    active_runner_pid=
  fi
}

cleanup() {
  stop_active_runner
  /bin/rm -f "$staged_payload" "$staged_validator" "$staged_identity" \
    "$staged_known_hosts" "$archive_file" "$result_file" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}

handle_signal() {
  signal_number=$1
  signal_status=$2
  trap - 1 2 15
  if [ -n "$active_runner_pid" ]; then
    /bin/kill -"$signal_number" "$active_runner_pid" 2>/dev/null
    wait "$active_runner_pid" 2>/dev/null
    active_runner_pid=
  fi
  exit "$signal_status"
}

trap cleanup 0
trap 'handle_signal 1 129' 1
trap 'handle_signal 2 130' 2
trap 'handle_signal 15 143' 15

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
/bin/cp "$validator" "$staged_validator" || exit 70
/bin/cp "$identity_file" "$staged_identity" || exit 70
/bin/cp "$known_hosts_file" "$staged_known_hosts" || exit 70
/bin/chmod 400 "$staged_payload" "$staged_validator" "$staged_identity" "$staged_known_hosts" || exit 70

payload_sha=$(sha256_file "$staged_payload") || exit 65
validator_sha=$(sha256_file "$staged_validator") || exit 65
identity_sha=$(sha256_file "$staged_identity") || exit 65
known_hosts_sha=$(sha256_file "$staged_known_hosts") || exit 65
if [ "$payload_sha" != "$expected_payload_sha" ] ||
  [ "$validator_sha" != "$expected_validator_sha" ] ||
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


def kill_residual_group(process):
    # The child is a session/process-group leader. Even after it exits normally,
    # kill any descendant it failed to reap before the supervisor returns.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
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
kill_residual_group(process)
if status < 0:
    raise SystemExit(125)
raise SystemExit(status)'

run_bounded() (
  deadline=$1
  shift
  # macOS `ulimit -f` counts 512-byte blocks: 32,768 is 16 MiB.
  ulimit -f 32768 2>/dev/null || exit 70
  exec /usr/bin/env -i PATH="$PATH" LC_ALL=C \
    /usr/bin/python3 -I -S -c "$process_runner_code" "$deadline" "$@"
)

remote_command="exec 2>&-; set +euxv; env_path=; for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ -f \"\$candidate\" ] && [ ! -L \"\$candidate\" ] && [ -r \"\$candidate\" ] && [ -x \"\$candidate\" ] && [ ! -w \"\$candidate\" ]; then env_path=\$candidate; break; fi; done; shell_path=; for shell_candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash /var/jb/bin/bash /var/jb/usr/bin/bash; do if [ -f \"\$shell_candidate\" ] && [ ! -L \"\$shell_candidate\" ] && [ -r \"\$shell_candidate\" ] && [ -x \"\$shell_candidate\" ] && [ ! -w \"\$shell_candidate\" ]; then shell_path=\$shell_candidate; break; fi; done; if [ -z \"\$env_path\" ]; then exit 127; fi; if [ -z \"\$shell_path\" ]; then exit 126; fi; \"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C \"\$shell_path\" -s"

run_bounded 60 /usr/bin/ssh \
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
    "$ssh_user@$ssh_host" "$remote_command" \
    < "$staged_payload" > "$archive_file" 2>/dev/null &
active_runner_pid=$!
wait "$active_runner_pid"
ssh_status=$?
active_runner_pid=
if [ "$ssh_status" -ne 0 ]; then
  command printf 'SSH or the remote toolbox payload failed with status %s; archive discarded.\n' "$ssh_status" >&2
  exit 69
fi

run_bounded 20 /usr/bin/python3 -I -S \
  "$staged_validator" "$archive_file" "$evidence_directory" \
  > "$result_file" 2>/dev/null &
active_runner_pid=$!
wait "$active_runner_pid"
validator_status=$?
active_runner_pid=
if [ "$validator_status" -ne 0 ]; then
  command printf '%s\n' 'Installed toolbox evidence was rejected; no evidence was accepted.' >&2
  exit 65
fi

/usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/python3 -I -S -c 'import re
import sys

data = open(sys.argv[1], "rb").read()
if not re.fullmatch(b"PASS installed toolbox attestation [0-9a-f]{64}\\n", data):
    raise SystemExit(65)' "$result_file" || exit 65
/bin/cat "$result_file"
