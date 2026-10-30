#!/bin/sh
# Local transport for one owner-approved, read-only iPad payload.
# This wrapper must itself be reviewed and approved before use.
# Payload and credential digests use an isolated local Python helper that opens
# with O_NOFOLLOW, requires a regular single-link file, and hashes that opened FD.
#
# The `stage-state` selector streams the digest-pinned quarantine diagnostic to a
# fresh isolated shell, frames all output with a random nonce, and accepts only its
# seven fixed-label lines. It does not copy, open, hash, execute, alter, or remove
# the staged probe; normal SSH authentication/process/accounting logs may occur.
# The `staging-capabilities` selector similarly accepts only six fixed-label lines
# from fixed interpreter/tool capability checks and performs no persistent write.
# The `tar-capabilities` selector accepts seven fixed-label lines from version-only
# option-parser checks and never opens or extracts an archive.
# The `post-run-state` selector accepts ten fixed-label lines describing only the
# fixed probe/report paths and a count of fixed-pattern writer temporaries.
# The `app-versions` selector accepts exactly two sanitized app version/build
# lines from fixed application roots and never releases bundle paths or IDs.
# The `app-version-capabilities` selector accepts 25 fixed categorical lines for
# fixed tool and application-root paths without releasing link targets or paths.
# The `app-archive-capabilities` selector accepts eight fixed lines classifying
# the guarded tar-to-stdout operation without releasing paths or plist content.
# The `app-archive-variants` selector accepts twelve fixed lines comparing one
# byte direct reads and three guarded root-relative tar invocations.
# The `appsync-install-capabilities` selector accepts twenty-four fixed lines
# classifying three timeout-bounded package records and five fixed rootless
# paths. It never invokes appinst, package installation, AppSync code, or an
# iPad daemon.
# The `appsync-query-status` selector accepts three fixed numeric status lines;
# the payload discards all query stdout on-device.
# The `appsync-package-membership` selector accepts four fixed lines from one
# complete, on-device-filtered package-record scan; raw records stay on-device.

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

script_dir=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" 2>/dev/null && pwd -P)
if [ -z "$script_dir" ]; then
  command printf '%s\n' 'Unable to resolve the runner directory.' >&2
  exit 64
fi

if [ "$#" -ne 1 ]; then
  command printf '%s\n' 'Usage: run-approved-readonly-device-probe.sh service-counts|configuration-presence|query-status|stage-state|staging-capabilities|tar-capabilities|post-run-state|app-versions|app-version-capabilities|app-archive-capabilities|app-archive-variants|appsync-install-capabilities|appsync-query-status|appsync-package-membership' >&2
  exit 64
fi

probe_name=$1
case "$probe_name" in
  service-counts)
    payload="$script_dir/device/u1-readonly-service-counts.sh"
    expected_sha='ed836124f74ba95c3a2eebd277514072ebca3b43032fb7c5ca5cfaa76bba4759'
    ;;
  configuration-presence)
    payload="$script_dir/device/u1-readonly-configuration-presence.sh"
    expected_sha='4f086127908606ad38666e424c991590977e37a8177fb62a74776253a3411ed1'
    ;;
  query-status)
    payload="$script_dir/device/u1-readonly-query-status.sh"
    expected_sha='4b38229cc6fd34882d91f65b30f3d2500efef2c02e8f8381394abc2f2efca6a6'
    ;;
  stage-state)
    payload="$script_dir/device/u1-readonly-staged-probe-state.sh"
    expected_sha='4a5ccea5a40708da064744d6f25e079a13b06fe8332b687b965e398bb93af43e'
    ;;
  staging-capabilities)
    payload="$script_dir/device/u1-readonly-staging-capabilities.sh"
    expected_sha='17472e5139bf2e0666ee9a6964dc326478c82138be27d2c3588552729d5e59ec'
    ;;
  tar-capabilities)
    payload="$script_dir/device/u1-readonly-tar-capabilities.sh"
    expected_sha='2359b6f61c8fc7c123336bb6207697c68e9722a64f08468d03b9c1a99f195c62'
    ;;
  post-run-state)
    payload="$script_dir/device/u1-readonly-post-run-state.sh"
    expected_sha='ee0c4bf4c252f490d5c63acc4394d5371393fba1fabb34dc0e6a40518eb2d2a7'
    ;;
  app-versions)
    payload="$script_dir/device/u1-readonly-app-versions.sh"
    expected_sha='600e70460e873e45ae382d5dd966d2b8f02437f6569c24acd5e2abe75aa70924'
    ;;
  app-version-capabilities)
    payload="$script_dir/device/u1-readonly-app-version-capabilities.sh"
    expected_sha='408a260ecfb1225a0bfd8b02704f81d945e97aaae136f08c1183a2b00e701e58'
    ;;
  app-archive-capabilities)
    payload="$script_dir/device/u1-readonly-app-archive-capabilities.sh"
    expected_sha='9b5ad8e725a7bbe094e708cd6c2c11e0175734311ae8ff070d09e738c0d67104'
    ;;
  app-archive-variants)
    payload="$script_dir/device/u1-readonly-app-archive-variants.sh"
    expected_sha='416bcf319e134085cc092f1f450587017302c4acbacebaac510990526b1fc6d3'
    ;;
  appsync-install-capabilities)
    payload="$script_dir/device/u1-readonly-appsync-install-capabilities.sh"
    expected_sha='093a638ac0a050ec915980a2ca25f7a89af6c4ed3b4591c93f6c97cdaa11a790'
    ;;
  appsync-query-status)
    payload="$script_dir/device/u1-readonly-appsync-query-status.sh"
    expected_sha='d9618f40af94e95e9326aae1aa57c71bed8fd990317733d5c1811d4a5377f84c'
    ;;
  appsync-package-membership)
    payload="$script_dir/device/u1-readonly-appsync-package-membership.sh"
    expected_sha='eb0c7b08653e96b3cd5028f0cb0120dcbe0068c8158239c37d548de1027c5219'
    ;;
  *)
    command printf '%s\n' 'Unknown probe. Nothing was sent.' >&2
    exit 64
    ;;
esac

if [ ! -f "$payload" ] || [ -L "$payload" ]; then
  command printf '%s\n' 'Approved payload is missing or is a symbolic link. Nothing was sent.' >&2
  exit 65
fi
if [ ! -f "$identity_file" ] || [ -L "$identity_file" ]; then
  command printf '%s\n' 'SSH identity file is missing or is a symbolic link. Nothing was sent.' >&2
  exit 66
fi
if [ ! -f "$known_hosts_file" ] || [ -L "$known_hosts_file" ]; then
  command printf '%s\n' 'Pinned known-hosts file is missing or is a symbolic link. Nothing was sent.' >&2
  exit 66
fi

current_uid=$(/usr/bin/id -u) || exit 70
identity_uid=$(/usr/bin/stat -f '%u' "$identity_file" 2>/dev/null) || exit 66
known_hosts_uid=$(/usr/bin/stat -f '%u' "$known_hosts_file" 2>/dev/null) || exit 66
identity_mode=$(/usr/bin/stat -f '%Lp' "$identity_file" 2>/dev/null) || exit 66
known_hosts_mode=$(/usr/bin/stat -f '%Lp' "$known_hosts_file" 2>/dev/null) || exit 66
if [ "$identity_uid" != "$current_uid" ] || [ "$known_hosts_uid" != "$current_uid" ]; then
  command printf '%s\n' 'SSH identity or known-hosts file has the wrong owner. Nothing was sent.' >&2
  exit 66
fi
case "$identity_mode" in
  400|600) ;;
  *)
    command printf '%s\n' 'SSH identity permissions are not restricted to its owner. Nothing was sent.' >&2
    exit 66
    ;;
esac
case "$known_hosts_mode" in
  400|440|444|600|640|644) ;;
  *)
    command printf '%s\n' 'Pinned known-hosts permissions allow mutation or execution by another account. Nothing was sent.' >&2
    exit 66
    ;;
esac

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-ipad-probe.XXXXXX) || exit 70
case "$temp_dir" in
  /tmp/mac2jb-ipad-probe.*) ;;
  *)
    command printf '%s\n' 'Unexpected temporary path. Nothing was sent.' >&2
    exit 70
    ;;
esac

cleanup() {
  /bin/rm -f \
    "$temp_dir/payload.sh" \
    "$temp_dir/identity" \
    "$temp_dir/known_hosts" \
    "$temp_dir/raw_output" \
    "$temp_dir/output" \
    "$temp_dir/expected" \
    "$temp_dir/begin" \
    "$temp_dir/end" \
    "$temp_dir/prefix" \
    "$temp_dir/suffix" \
    "$temp_dir/bytes" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

staged_payload="$temp_dir/payload.sh"
staged_identity="$temp_dir/identity"
staged_known_hosts="$temp_dir/known_hosts"
raw_output_file="$temp_dir/raw_output"
output_file="$temp_dir/output"
expected_file="$temp_dir/expected"
begin_file="$temp_dir/begin"
end_file="$temp_dir/end"
prefix_file="$temp_dir/prefix"
suffix_file="$temp_dir/suffix"
bytes_file="$temp_dir/bytes"

sha256_file() {
  /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C \
    /usr/bin/python3 -I -S -c 'import hashlib
import os
import stat
import sys

file_fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
file_status = os.fstat(file_fd)
if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
    raise SystemExit(65)
digest = hashlib.sha256()
total = 0
while True:
    chunk = os.read(file_fd, 65536)
    if not chunk:
        break
    total += len(chunk)
    if total > 2097152:
        raise SystemExit(65)
    digest.update(chunk)
os.close(file_fd)
print(digest.hexdigest())' "$1" 2>/dev/null
}

/bin/cp "$payload" "$staged_payload" || exit 70
/bin/cp "$identity_file" "$staged_identity" || exit 70
/bin/cp "$known_hosts_file" "$staged_known_hosts" || exit 70
/bin/chmod 400 "$staged_payload" || exit 70
/bin/chmod 400 "$staged_identity" "$staged_known_hosts" || exit 70

actual_sha=$(sha256_file "$staged_payload") || exit 65
if [ "$actual_sha" != "$expected_sha" ]; then
  command printf '%s\n' 'Payload digest does not match the owner-approved revision. Nothing was sent.' >&2
  exit 65
fi
actual_identity_sha=$(sha256_file "$staged_identity") || exit 65
actual_known_hosts_sha=$(sha256_file "$staged_known_hosts") || exit 65
if [ "$actual_identity_sha" != "$expected_identity_sha" ]; then
  command printf '%s\n' 'SSH identity digest does not match the reviewed key. Nothing was sent.' >&2
  exit 66
fi
if [ "$actual_known_hosts_sha" != "$expected_known_hosts_sha" ]; then
  command printf '%s\n' 'Known-hosts digest does not match the owner-reviewed pin. Nothing was sent.' >&2
  exit 66
fi

nonce=$(/usr/bin/od -An -N16 -tx1 /dev/urandom 2>/dev/null | /usr/bin/tr -d ' \n')
case "$nonce" in
  ''|*[!0-9a-f]*)
    command printf '%s\n' 'Unable to create an output-frame nonce. Nothing was sent.' >&2
    exit 70
    ;;
esac
if [ "${#nonce}" -ne 32 ]; then
  command printf '%s\n' 'Output-frame nonce has the wrong length. Nothing was sent.' >&2
  exit 70
fi

begin_marker="MAC2JB_BEGIN_$nonce"
end_marker="MAC2JB_END_$nonce:0"
command printf '%s\n' "$begin_marker" > "$begin_file"
command printf '%s\n' "$end_marker" > "$end_file"

remote_command="exec 2>&-; set +euxv; command printf '%s\\n' '$begin_marker'; env_path=; for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ -f \"\$candidate\" ] && [ ! -L \"\$candidate\" ] && [ -r \"\$candidate\" ] && [ -x \"\$candidate\" ] && [ ! -w \"\$candidate\" ]; then env_path=\$candidate; break; fi; done; shell_path=; for shell_candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash /var/jb/bin/bash /var/jb/usr/bin/bash; do if [ -f \"\$shell_candidate\" ] && [ ! -L \"\$shell_candidate\" ] && [ -r \"\$shell_candidate\" ] && [ -x \"\$shell_candidate\" ] && [ ! -w \"\$shell_candidate\" ]; then shell_path=\$shell_candidate; break; fi; done; if [ -z \"\$env_path\" ]; then probe_status=127; elif [ -z \"\$shell_path\" ]; then probe_status=126; else \"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C \"\$shell_path\" -s; probe_status=\$?; fi; command printf '%s:%s\\n' 'MAC2JB_END_$nonce' \"\$probe_status\"; exit \"\$probe_status\""

# Bound the complete connected SSH session, not only connection establishment.
# The client runs in its own process group. HUP/INT/TERM are blocked across the
# spawn race, restored in the child, and handled in the watchdog by killing and
# reaping the entire client group before returning a fixed failure status.
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
        sys.argv[1:],
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
        status = process.wait(timeout=45)
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

# The outer redirection suppresses SSH and remote-shell diagnostics before the
# payload interpreter starts. The remote command closes stderr again, clears
# inherited tracing/verbose/error flags, and runs the payload in an empty
# environment before emitting its authenticated end marker.
(
  ulimit -f 4 2>/dev/null || exit 70
  exec /usr/bin/env -i PATH="$PATH" LC_ALL=C \
    /usr/bin/python3 -I -S -c "$process_runner_code" /usr/bin/ssh \
    -F /dev/null \
    -T \
    -p "$ssh_port" \
    -i "$staged_identity" \
    -o BatchMode=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey \
    -o IdentitiesOnly=yes \
    -o IdentityAgent=none \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$staged_known_hosts" \
    -o GlobalKnownHostsFile=/dev/null \
    -o KnownHostsCommand=none \
    -o UpdateHostKeys=no \
    -o ProxyCommand=none \
    -o ProxyJump=none \
    -o PermitLocalCommand=no \
    -o ForwardAgent=no \
    -o ForwardX11=no \
    -o ClearAllForwardings=yes \
    -o RequestTTY=no \
    -o ControlMaster=no \
    -o ControlPath=none \
    -o ConnectTimeout=10 \
    -o ConnectionAttempts=1 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2 \
    -o NumberOfPasswordPrompts=0 \
    -o LogLevel=ERROR \
    "$ssh_user@$ssh_host" \
    "$remote_command"
) < "$staged_payload" > "$raw_output_file" 2>/dev/null
ssh_status=$?

if [ "$ssh_status" -ne 0 ]; then
  command printf 'SSH or the remote probe failed with status %s; captured output was discarded.\n' "$ssh_status" >&2
  exit 69
fi

raw_size=$(/usr/bin/wc -c < "$raw_output_file" | /usr/bin/tr -d ' ')
begin_size=$(/usr/bin/wc -c < "$begin_file" | /usr/bin/tr -d ' ')
end_size=$(/usr/bin/wc -c < "$end_file" | /usr/bin/tr -d ' ')
case "$raw_size" in
  ''|*[!0-9]*)
    command printf '%s\n' 'Unable to measure the framed probe output. Output was discarded.' >&2
    exit 65
    ;;
esac
case "$begin_size" in
  ''|*[!0-9]*)
    command printf '%s\n' 'Unable to measure the framed probe output. Output was discarded.' >&2
    exit 65
    ;;
esac
case "$end_size" in
  ''|*[!0-9]*)
    command printf '%s\n' 'Unable to measure the framed probe output. Output was discarded.' >&2
    exit 65
    ;;
esac
if [ "$raw_size" -lt $((begin_size + end_size)) ]; then
  command printf '%s\n' 'Probe output did not contain the complete frame and was discarded.' >&2
  exit 65
fi

body_size=$((raw_size - begin_size - end_size))
end_offset=$((raw_size - end_size))
/bin/dd if="$raw_output_file" of="$prefix_file" bs=1 count="$begin_size" 2>/dev/null || exit 65
/bin/dd if="$raw_output_file" of="$suffix_file" bs=1 skip="$end_offset" count="$end_size" 2>/dev/null || exit 65
if ! /usr/bin/cmp -s "$prefix_file" "$begin_file" || ! /usr/bin/cmp -s "$suffix_file" "$end_file"; then
  command printf '%s\n' 'SSH startup or trailing output fell outside the authenticated probe frame. Output was discarded.' >&2
  exit 65
fi
/bin/dd if="$raw_output_file" of="$output_file" bs=1 skip="$begin_size" count="$body_size" 2>/dev/null || exit 65

case "$probe_name" in
  service-counts)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { state = 0; digits = 0; valid = 1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (state >= 2) {
            valid = 0
          } else if (byte >= 48 && byte <= 57) {
            digits++
          } else if (byte == 10 && digits > 0) {
            state++
            digits = 0
          } else {
            valid = 0
          }
        }
      }
      END { exit !(valid && state == 2 && digits == 0) }
    ' "$bytes_file"; then
      command printf '%s\n' 'Probe output did not match two decimal lines and was discarded.' >&2
      exit 65
    fi
    ;;
  configuration-presence)
    command printf '%s\n' 'configuration-string: present' > "$expected_file"
    if ! /usr/bin/cmp -s "$output_file" "$expected_file"; then
      command printf '%s\n' 'configuration-string: not observed' > "$expected_file"
      if ! /usr/bin/cmp -s "$output_file" "$expected_file"; then
        command printf '%s\n' 'Probe output did not match either fixed presence label and was discarded.' >&2
        exit 65
      fi
    fi
    ;;
  query-status)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'Status output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^controller-query-status: [0-9]+$/ { valid = 0 }
      NR == 2 && $0 !~ /^controller-service-count: [0-9]+$/ { valid = 0 }
      NR == 3 && $0 !~ /^interface-query-status: [0-9]+$/ { valid = 0 }
      NR == 4 && $0 !~ /^interface-service-count: [0-9]+$/ { valid = 0 }
      NR == 5 && $0 !~ /^configuration-query-status: [0-9]+$/ { valid = 0 }
      NR == 6 && $0 !~ /^configuration-string: (present|not observed)$/ { valid = 0 }
      NR > 6 { valid = 0 }
      END { exit !(valid && NR == 6) }
    ' "$output_file"; then
      command printf '%s\n' 'Status output did not match the six-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  stage-state)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'Stage-state output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^env-candidate: (present|not observed)$/ { valid = 0 }
      NR == 2 && $0 !~ /^python-candidate: (present|not observed)$/ { valid = 0 }
      NR == 3 && $0 !~ /^documents-directory: (present|not observed)$/ { valid = 0 }
      NR == 4 && $0 !~ /^target-type: (absent|regular file|symbolic link|other object)$/ { valid = 0 }
      NR == 5 && $0 !~ /^target-readable: (yes|no)$/ { valid = 0 }
      NR == 6 && $0 !~ /^target-writable: (yes|no)$/ { valid = 0 }
      NR == 7 && $0 !~ /^target-executable: (yes|no)$/ { valid = 0 }
      NR > 7 { valid = 0 }
      END { exit !(valid && NR == 7) }
    ' "$output_file"; then
      command printf '%s\n' 'Stage-state output did not match the seven-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  staging-capabilities)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'Staging-capability output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^perl-candidate: (present|not observed)$/ { valid = 0 }
      NR == 2 && $0 !~ /^perl-open-hash-primitives: (present|not observed)$/ { valid = 0 }
      NR == 3 && $0 !~ /^node-candidate: (present|not observed)$/ { valid = 0 }
      NR == 4 && $0 !~ /^node-full-stager-primitives: (present|not observed)$/ { valid = 0 }
      NR == 5 && $0 !~ /^tar-candidate: (present|not observed)$/ { valid = 0 }
      NR == 6 && $0 !~ /^dd-exclusive-flags: (present|not observed)$/ { valid = 0 }
      NR > 6 { valid = 0 }
      END { exit !(valid && NR == 6) }
    ' "$output_file"; then
      command printf '%s\n' 'Staging-capability output did not match the six-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  tar-capabilities)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'Tar-capability output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^tar-candidate: (rootless bsdtar|rootless tar|system tar|not observed)$/ { valid = 0 }
      NR == 2 && $0 !~ /^tar-family: (libarchive|gnu|other|not observed)$/ { valid = 0 }
      NR == 3 && $0 !~ /^tar-keep-old-files: (present|not observed)$/ { valid = 0 }
      NR == 4 && $0 !~ /^tar-safe-writes: (present|not observed)$/ { valid = 0 }
      NR == 5 && $0 !~ /^tar-no-same-owner: (present|not observed)$/ { valid = 0 }
      NR == 6 && $0 !~ /^tar-no-same-permissions: (present|not observed)$/ { valid = 0 }
      NR == 7 && $0 !~ /^tar-no-extended-metadata: (present|not observed)$/ { valid = 0 }
      NR > 7 { valid = 0 }
      END { exit !(valid && NR == 7) }
    ' "$output_file"; then
      command printf '%s\n' 'Tar-capability output did not match the seven-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  post-run-state)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'Post-run state output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^probe-type: (absent|regular file|symbolic link|other object)$/ { valid = 0 }
      NR == 2 && $0 !~ /^probe-readable: (yes|no)$/ { valid = 0 }
      NR == 3 && $0 !~ /^probe-writable: (yes|no)$/ { valid = 0 }
      NR == 4 && $0 !~ /^probe-executable: (yes|no)$/ { valid = 0 }
      NR == 5 && $0 !~ /^report-type: (absent|regular file|symbolic link|other object)$/ { valid = 0 }
      NR == 6 && $0 !~ /^report-readable: (yes|no)$/ { valid = 0 }
      NR == 7 && $0 !~ /^report-writable: (yes|no)$/ { valid = 0 }
      NR == 8 && $0 !~ /^report-executable: (yes|no)$/ { valid = 0 }
      NR == 9 && $0 !~ /^report-nonempty: (yes|no)$/ { valid = 0 }
      NR == 10 && $0 !~ /^report-temp-count: [0-9]+$/ { valid = 0 }
      NR > 10 { valid = 0 }
      END { exit !(valid && NR == 10) }
    ' "$output_file"; then
      command printf '%s\n' 'Post-run state output did not match the ten-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  app-versions)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'App-version output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^dopamine-app: (not-observed|version=[0-9A-Za-z][0-9A-Za-z.+_() -]* build=[0-9A-Za-z][0-9A-Za-z.+_() -]* bundle-family=standard)$/ { valid = 0 }
      NR == 2 && $0 !~ /^trollstore-app: (not-observed|version=[0-9A-Za-z][0-9A-Za-z.+_() -]* build=[0-9A-Za-z][0-9A-Za-z.+_() -]* bundle-family=(standard|stealth))$/ { valid = 0 }
      NR > 2 { valid = 0 }
      END { exit !(valid && NR == 2) }
    ' "$output_file"; then
      command printf '%s\n' 'App-version output did not match the two-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  app-version-capabilities)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'App-version capability output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; type = "(absent|regular-file|symbolic-link|directory|other-object)" }
      NR == 1 && $0 !~ ("^system-plutil-type: " type "$") { valid = 0 }
      NR == 2 && $0 !~ /^system-plutil-readable: (yes|no)$/ { valid = 0 }
      NR == 3 && $0 !~ /^system-plutil-writable: (yes|no)$/ { valid = 0 }
      NR == 4 && $0 !~ /^system-plutil-executable: (yes|no)$/ { valid = 0 }
      NR == 5 && $0 !~ ("^rootless-usr-plutil-type: " type "$") { valid = 0 }
      NR == 6 && $0 !~ /^rootless-usr-plutil-readable: (yes|no)$/ { valid = 0 }
      NR == 7 && $0 !~ /^rootless-usr-plutil-writable: (yes|no)$/ { valid = 0 }
      NR == 8 && $0 !~ /^rootless-usr-plutil-executable: (yes|no)$/ { valid = 0 }
      NR == 9 && $0 !~ ("^rootless-bin-plutil-type: " type "$") { valid = 0 }
      NR == 10 && $0 !~ /^rootless-bin-plutil-readable: (yes|no)$/ { valid = 0 }
      NR == 11 && $0 !~ /^rootless-bin-plutil-writable: (yes|no)$/ { valid = 0 }
      NR == 12 && $0 !~ /^rootless-bin-plutil-executable: (yes|no)$/ { valid = 0 }
      NR == 13 && $0 !~ ("^rootless-plistutil-type: " type "$") { valid = 0 }
      NR == 14 && $0 !~ /^rootless-plistutil-readable: (yes|no)$/ { valid = 0 }
      NR == 15 && $0 !~ /^rootless-plistutil-writable: (yes|no)$/ { valid = 0 }
      NR == 16 && $0 !~ /^rootless-plistutil-executable: (yes|no)$/ { valid = 0 }
      NR == 17 && $0 !~ ("^container-app-root-type: " type "$") { valid = 0 }
      NR == 18 && $0 !~ /^container-app-root-readable: (yes|no)$/ { valid = 0 }
      NR == 19 && $0 !~ /^container-app-root-searchable: (yes|no)$/ { valid = 0 }
      NR == 20 && $0 !~ ("^system-app-root-type: " type "$") { valid = 0 }
      NR == 21 && $0 !~ /^system-app-root-readable: (yes|no)$/ { valid = 0 }
      NR == 22 && $0 !~ /^system-app-root-searchable: (yes|no)$/ { valid = 0 }
      NR == 23 && $0 !~ ("^rootless-app-root-type: " type "$") { valid = 0 }
      NR == 24 && $0 !~ /^rootless-app-root-readable: (yes|no)$/ { valid = 0 }
      NR == 25 && $0 !~ /^rootless-app-root-searchable: (yes|no)$/ { valid = 0 }
      NR > 25 { valid = 0 }
      END { exit !(valid && NR == 25) }
    ' "$output_file"; then
      command printf '%s\n' 'App-version capability output did not match the 25-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  app-archive-capabilities)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'Unable to inspect every output byte. Output was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'App-archive capability output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^timeout-guard: (not-observed|canary-passed|canary-failed)$/ { valid = 0 }
      NR == 2 && $0 !~ /^tar-family: (gnu|libarchive|other|not-observed)$/ { valid = 0 }
      NR == 3 && $0 !~ /^target-candidate-count: [0-9]+$/ { valid = 0 }
      NR == 4 && $0 !~ /^target-path-length: (none|at-most-100|over-100)$/ { valid = 0 }
      NR == 5 && $0 !~ /^single-file-success-count: [0-9]+$/ { valid = 0 }
      NR == 6 && $0 !~ /^single-file-failure-count: [0-9]+$/ { valid = 0 }
      NR == 7 && $0 !~ /^empty-archive-status: [0-9]+$/ { valid = 0 }
      NR == 8 && $0 !~ /^combined-archive-status: [0-9]+$/ { valid = 0 }
      NR > 8 { valid = 0 }
      END { exit !(valid && NR == 8) }
    ' "$output_file"; then
      command printf '%s\n' 'App-archive capability output did not match the eight-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  app-archive-variants)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'App-archive variant output could not be inspected and was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'App-archive variant output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^timeout-guard: (not-observed|canary-passed|canary-failed)$/ { valid = 0 }
      NR == 2 && $0 !~ /^tar-family: (gnu|libarchive|other|not-observed)$/ { valid = 0 }
      NR == 3 && $0 !~ /^dd-candidate: (present|not-observed)$/ { valid = 0 }
      NR == 4 && $0 !~ /^target-candidate-count: [0-9]+$/ { valid = 0 }
      NR == 5 && $0 !~ /^direct-read-success-count: [0-9]+$/ { valid = 0 }
      NR == 6 && $0 !~ /^direct-read-failure-count: [0-9]+$/ { valid = 0 }
      NR == 7 && $0 !~ /^relative-ustar-success-count: [0-9]+$/ { valid = 0 }
      NR == 8 && $0 !~ /^relative-ustar-failure-count: [0-9]+$/ { valid = 0 }
      NR == 9 && $0 !~ /^relative-default-success-count: [0-9]+$/ { valid = 0 }
      NR == 10 && $0 !~ /^relative-default-failure-count: [0-9]+$/ { valid = 0 }
      NR == 11 && $0 !~ /^relative-minimal-success-count: [0-9]+$/ { valid = 0 }
      NR == 12 && $0 !~ /^relative-minimal-failure-count: [0-9]+$/ { valid = 0 }
      NR > 12 { valid = 0 }
      END { exit !(valid && NR == 12) }
    ' "$output_file"; then
      command printf '%s\n' 'App-archive variant output did not match the twelve-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  appsync-install-capabilities)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'AppSync capability output could not be inspected and was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'AppSync capability output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN {
        valid = 1
        package = "(not-installed|installed version=[0-9A-Za-z][0-9A-Za-z.+:~_-]* architecture=[0-9A-Za-z][0-9A-Za-z_-]*)"
        type = "(not-observed|absent|regular-file|symbolic-link|other-object)"
      }
      NR == 1 && $0 != "dpkg-query: present" { valid = 0 }
      NR == 2 && $0 !~ ("^appsync-package: " package "$") { valid = 0 }
      NR == 3 && $0 !~ ("^appinst-package: " package "$") { valid = 0 }
      NR == 4 && $0 !~ ("^ellekit-package: " package "$") { valid = 0 }
      NR == 5 { path_type[1] = $2; if ($0 !~ ("^appinst-binary-type: " type "$")) valid = 0 }
      NR == 6 { path_readable[1] = $2; if ($0 !~ /^appinst-binary-readable: (yes|no)$/) valid = 0 }
      NR == 7 { path_writable[1] = $2; if ($0 !~ /^appinst-binary-writable: (yes|no)$/) valid = 0 }
      NR == 8 { path_executable[1] = $2; if ($0 !~ /^appinst-binary-executable: (yes|no)$/) valid = 0 }
      NR == 9 { path_type[2] = $2; if ($0 !~ ("^appsync-installd-dylib-type: " type "$")) valid = 0 }
      NR == 10 { path_readable[2] = $2; if ($0 !~ /^appsync-installd-dylib-readable: (yes|no)$/) valid = 0 }
      NR == 11 { path_writable[2] = $2; if ($0 !~ /^appsync-installd-dylib-writable: (yes|no)$/) valid = 0 }
      NR == 12 { path_executable[2] = $2; if ($0 !~ /^appsync-installd-dylib-executable: (yes|no)$/) valid = 0 }
      NR == 13 { path_type[3] = $2; if ($0 !~ ("^appsync-installd-filter-type: " type "$")) valid = 0 }
      NR == 14 { path_readable[3] = $2; if ($0 !~ /^appsync-installd-filter-readable: (yes|no)$/) valid = 0 }
      NR == 15 { path_writable[3] = $2; if ($0 !~ /^appsync-installd-filter-writable: (yes|no)$/) valid = 0 }
      NR == 16 { path_executable[3] = $2; if ($0 !~ /^appsync-installd-filter-executable: (yes|no)$/) valid = 0 }
      NR == 17 { path_type[4] = $2; if ($0 !~ ("^appsync-frontboard-dylib-type: " type "$")) valid = 0 }
      NR == 18 { path_readable[4] = $2; if ($0 !~ /^appsync-frontboard-dylib-readable: (yes|no)$/) valid = 0 }
      NR == 19 { path_writable[4] = $2; if ($0 !~ /^appsync-frontboard-dylib-writable: (yes|no)$/) valid = 0 }
      NR == 20 { path_executable[4] = $2; if ($0 !~ /^appsync-frontboard-dylib-executable: (yes|no)$/) valid = 0 }
      NR == 21 { path_type[5] = $2; if ($0 !~ ("^appsync-frontboard-filter-type: " type "$")) valid = 0 }
      NR == 22 { path_readable[5] = $2; if ($0 !~ /^appsync-frontboard-filter-readable: (yes|no)$/) valid = 0 }
      NR == 23 { path_writable[5] = $2; if ($0 !~ /^appsync-frontboard-filter-writable: (yes|no)$/) valid = 0 }
      NR == 24 { path_executable[5] = $2; if ($0 !~ /^appsync-frontboard-filter-executable: (yes|no)$/) valid = 0 }
      NR > 24 { valid = 0 }
      END {
        for (path_index = 1; path_index <= 5; path_index++) {
          if (path_type[path_index] != "regular-file" &&
              (path_readable[path_index] != "no" || path_writable[path_index] != "no" ||
               path_executable[path_index] != "no")) valid = 0
        }
        exit !(valid && NR == 24)
      }
    ' "$output_file"; then
      command printf '%s\n' 'AppSync capability output did not match the twenty-four-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  appsync-query-status)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'AppSync query-status output could not be inspected and was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'AppSync query-status output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1 }
      NR == 1 && $0 !~ /^appsync-query-status: [0-9]+$/ { valid = 0 }
      NR == 2 && $0 !~ /^appinst-query-status: [0-9]+$/ { valid = 0 }
      NR == 3 && $0 !~ /^ellekit-query-status: [0-9]+$/ { valid = 0 }
      NR >= 1 && NR <= 3 {
        if (($2 + 0) < 0 || ($2 + 0) > 255 || $2 !~ /^[0-9]+$/) valid = 0
      }
      NR > 3 { valid = 0 }
      END { exit !(valid && NR == 3) }
    ' "$output_file"; then
      command printf '%s\n' 'AppSync query-status output did not match the three-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
  appsync-package-membership)
    /usr/bin/od -An -tu1 -v "$output_file" > "$bytes_file"
    od_status=$?
    if [ "$od_status" -ne 0 ]; then
      command printf '%s\n' 'AppSync membership output could not be inspected and was discarded.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; last = -1 }
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte != 10 && (byte < 32 || byte > 126)) valid = 0
          last = byte
        }
      }
      END { exit !(valid && last == 10) }
    ' "$bytes_file"; then
      command printf '%s\n' 'AppSync membership output contained a disallowed byte or lacked its final newline.' >&2
      exit 65
    fi
    if ! /usr/bin/awk '
      BEGIN { valid = 1; membership = "(installed|installed-error|record-not-installed|not-observed)" }
      NR == 1 && $0 != "dpkg-list-status: 0" { valid = 0 }
      NR == 2 && $0 !~ ("^appsync-membership: " membership "$") { valid = 0 }
      NR == 3 && $0 !~ ("^appinst-membership: " membership "$") { valid = 0 }
      NR == 4 && $0 !~ ("^ellekit-membership: " membership "$") { valid = 0 }
      NR > 4 { valid = 0 }
      END { exit !(valid && NR == 4) }
    ' "$output_file"; then
      command printf '%s\n' 'AppSync membership output did not match the four-line fixed grammar and was discarded.' >&2
      exit 65
    fi
    ;;
esac

/bin/cat "$output_file"
