#!/bin/sh
# Read-only batch runner for the staged, entitlement-free diagnostic phase probe.
# Do not run until the exact binary and this runner pass adversarial review.
#
# What this script does:
# 1. Pins the SSH key, host record, and staged diagnostic SHA-256 with isolated
#    local helpers, then checks the fixed remote path by a complete SCP readback.
# 2. Runs sixteen fixed phases sequentially, each in a fresh key-only SSH session.
#    A fixed, non-writable timeout executable terminates a phase after twelve
#    seconds and force-kills it one second later if needed. A controlled timeout
#    is recorded; an ambiguous kill or transport failure stops further access.
# 3. The diagnostic binary has no report writer. Each invocation emits only fixed
#    unbuffered markers. This runner accepts only an exact prefix of the expected
#    marker sequence and records status, marker count, and output validity.
# 4. Bounds both SCP transfers and every SSH session with a local process-group
#    watchdog, then re-downloads and hashes the diagnostic after the batch before
#    releasing the checked sixteen-line local summary.
#
# Device effects and boundaries:
# - The batch creates no report and intentionally makes no persistent device write.
# - Match/metadata/configuration/symbol/entitlement/serialization phases are reads.
#   Open/close and private controller/description phases can create transient IOKit
#   or driver state and logs, but the reviewed binary imports no audited mutation API.
# - SSH/authentication/process/accounting logs and access-time metadata may persist.
# - The fixed path is executed by pathname. Pre/post complete hashes detect lasting
#   replacement, not a hostile same-UID replace-and-restore race during launch.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly expected_probe_sha='87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'
readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'
readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'
readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'
readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'
readonly ssh_host='127.0.0.1'
readonly ssh_port='2222'
readonly ssh_user='mobile'
readonly remote_probe='/var/mobile/Documents/mac2jb-ios-probe-diagnostic-87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: run-diagnostic-phase-batch.sh' >&2
  exit 64
fi
for source_file in "$identity_file" "$known_hosts_file"; do
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    command printf '%s\n' 'An SSH credential is missing, non-regular, or a symbolic link. Nothing was run.' >&2
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

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-diag-batch.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-diag-batch.*) ;; *) exit 70 ;; esac
cleanup() {
  /bin/rm -f "$temp_dir/identity" "$temp_dir/known_hosts" \
    "$temp_dir/probe-before" "$temp_dir/probe-after" "$temp_dir/output" \
    "$temp_dir/expected" "$temp_dir/expected-prefix" "$temp_dir/results" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

staged_identity="$temp_dir/identity"
staged_known_hosts="$temp_dir/known_hosts"
probe_before="$temp_dir/probe-before"
probe_after="$temp_dir/probe-after"
phase_output="$temp_dir/output"
expected_output="$temp_dir/expected"
expected_prefix="$temp_dir/expected-prefix"
results_file="$temp_dir/results"

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

# Run one local SSH or SCP client in its own process group. The child inherits
# this script's already-bounded stdout. On a local deadline, kill and reap the
# entire client group and return 125. That status means remote teardown was not
# observed, so the caller must perform no later iPad access in this batch.
process_runner_code='import os
import signal
import subprocess
import sys

process = subprocess.Popen(
    sys.argv[1:],
    stdin=subprocess.DEVNULL,
    stdout=None,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
try:
    return_code = process.wait(timeout=20,)
except subprocess.TimeoutExpired:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
    raise SystemExit(125)
if return_code < 0:
    raise SystemExit(125)
raise SystemExit(return_code)'

/bin/cp "$identity_file" "$staged_identity" || exit 70
/bin/cp "$known_hosts_file" "$staged_known_hosts" || exit 70
/bin/chmod 400 "$staged_identity" "$staged_known_hosts" || exit 70
identity_sha=$(sha256_file "$staged_identity") || exit 65
known_hosts_sha=$(sha256_file "$staged_known_hosts") || exit 65
if [ "$identity_sha" != "$expected_identity_sha" ] || [ "$known_hosts_sha" != "$expected_known_hosts_sha" ]; then
  command printf '%s\n' 'A staged SSH digest differs from its reviewed value. Nothing was run.' >&2
  exit 65
fi

scp_from_device() {
  remote_path=$1
  local_path=$2
  /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C \
    /usr/bin/python3 -I -S -c "$process_runner_code" /usr/bin/scp \
    -F /dev/null -q -P "$ssh_port" -i "$staged_identity" \
    -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$staged_known_hosts" \
    -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o UpdateHostKeys=no \
    -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no \
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes \
    -o RequestTTY=no -o ControlMaster=no -o ControlPath=none \
    -o ConnectTimeout=10 -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=0 \
    -o LogLevel=ERROR "$ssh_user@$ssh_host:$remote_path" "$local_path" 2>/dev/null
}

if ! (ulimit -f 2048 2>/dev/null && scp_from_device "$remote_probe" "$probe_before"); then
  command printf '%s\n' 'The staged diagnostic could not be read back. Nothing was run.' >&2
  exit 74
fi
probe_sha=$(sha256_file "$probe_before") || exit 65
if [ "$probe_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'The staged diagnostic digest differs from the reviewed binary. Nothing was run.' >&2
  exit 65
fi

write_step() {
  command printf 'MAC2JB_DIAG_STEP v1 %s %s begin\n' "$1" "$2" >> "$expected_output" || return 70
  command printf 'MAC2JB_DIAG_STEP v1 %s %s ok\n' "$1" "$2" >> "$expected_output" || return 70
}

write_expected() {
  phase=$1
  : > "$expected_output" || return 70
  command printf '%s\n' 'MAC2JB_DIAG_PROCESS v1' >> "$expected_output" || return 70
  command printf 'MAC2JB_DIAG_BEGIN v1 %s\n' "$phase" >> "$expected_output" || return 70
  case "$phase" in
    launch) ;;
    identity) write_step "$phase" identity ;;
    serialization) write_step "$phase" encode ;;
    configuration-file) write_step "$phase" read-file ;;
    device-tree) write_step "$phase" read-tree ;;
    symbols) write_step "$phase" resolve ;;
    mutation-symbols) write_step "$phase" resolve-only ;;
    entitlements) write_step "$phase" read ;;
    controller-match|interface-match) write_step "$phase" match ;;
    controller-metadata) write_step "$phase" match || return 70; write_step "$phase" inspect || return 70 ;;
    interface-metadata) write_step "$phase" match || return 70; write_step "$phase" inspect || return 70 ;;
    controller-open) write_step "$phase" match || return 70; write_step "$phase" open-close || return 70 ;;
    interface-open) write_step "$phase" match || return 70; write_step "$phase" open-close || return 70 ;;
    private-readback) write_step "$phase" readback ;;
    full-no-report) write_step "$phase" collect-encode ;;
    *) exit 64 ;;
  esac
  command printf 'MAC2JB_DIAG_END v1 %s ok\n' "$phase" >> "$expected_output" || return 70
}

append_result() {
  command printf 'phase-result: %s status=%s markers=%s output=%s\n' \
    "$1" "$2" "$3" "$4" >> "$results_file"
}

emit_results() {
  /bin/cat "$results_file"
}

batch_valid=1
: > "$results_file" || exit 70
for phase in \
  launch identity serialization configuration-file device-tree symbols mutation-symbols entitlements \
  controller-match controller-metadata interface-match interface-metadata \
  controller-open interface-open private-readback full-no-report
do
  write_expected "$phase" || exit 70
  # The remote shell creates no files. It selects fixed, non-writable timeout and
  # sleep candidates and requires a harmless sleep canary to return exactly 124.
  # It then replaces itself with timeout as the probe's direct parent. A forced
  # KILL can return ambiguous status 137, which this runner handles by aborting.
  remote_command="exec 2>&-; set +euxv; env_path=; timeout_path=; sleep_path=; for env_candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ ! -L \"\$env_candidate\" ] && [ -f \"\$env_candidate\" ] && [ -r \"\$env_candidate\" ] && [ ! -w \"\$env_candidate\" ] && [ -x \"\$env_candidate\" ]; then env_path=\$env_candidate; break; fi; done; if [ -z \"\$env_path\" ]; then exit 66; fi; for timeout_candidate in /var/jb/usr/bin/timeout /var/jb/bin/timeout /usr/bin/timeout /bin/timeout /var/jb/usr/bin/gtimeout /var/jb/bin/gtimeout /usr/bin/gtimeout /bin/gtimeout; do if [ ! -L \"\$timeout_candidate\" ] && [ -f \"\$timeout_candidate\" ] && [ -r \"\$timeout_candidate\" ] && [ ! -w \"\$timeout_candidate\" ] && [ -x \"\$timeout_candidate\" ]; then timeout_path=\$timeout_candidate; break; fi; done; if [ -z \"\$timeout_path\" ]; then exit 67; fi; for sleep_candidate in /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep; do if [ ! -L \"\$sleep_candidate\" ] && [ -f \"\$sleep_candidate\" ] && [ -r \"\$sleep_candidate\" ] && [ ! -w \"\$sleep_candidate\" ] && [ -x \"\$sleep_candidate\" ]; then sleep_path=\$sleep_candidate; break; fi; done; if [ -z \"\$sleep_path\" ]; then exit 68; fi; if [ -L /var/mobile/Documents ] || [ ! -d /var/mobile/Documents ] || [ -L '$remote_probe' ] || [ ! -f '$remote_probe' ] || [ ! -r '$remote_probe' ] || [ -w '$remote_probe' ] || [ ! -x '$remote_probe' ]; then exit 69; fi; \"\$timeout_path\" -k 1 0.1 \"\$sleep_path\" 1 </dev/null >/dev/null 2>&1; timeout_status=\$?; if [ \"\$timeout_status\" -ne 124 ]; then exit 70; fi; exec \"\$timeout_path\" -k 1 12 \"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C '$remote_probe' --diagnostic-phase '$phase'"
  (
    ulimit -f 4 2>/dev/null || exit 70
    exec /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C \
      /usr/bin/python3 -I -S -c "$process_runner_code" /usr/bin/ssh \
      -F /dev/null -T -p "$ssh_port" -i "$staged_identity" \
      -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
      -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o IdentityAgent=none \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$staged_known_hosts" \
      -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o UpdateHostKeys=no \
      -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no \
      -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes \
      -o RequestTTY=no -o ControlMaster=no -o ControlPath=none \
      -o ConnectTimeout=10 -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=0 \
      -o LogLevel=ERROR "$ssh_user@$ssh_host" "$remote_command"
  ) > "$phase_output" 2>/dev/null
  phase_status=$?

  output_valid='valid'
  actual_size=$(/usr/bin/wc -c < "$phase_output" | /usr/bin/tr -d ' ')
  expected_size=$(/usr/bin/wc -c < "$expected_output" | /usr/bin/tr -d ' ')
  case "$actual_size:$expected_size" in *[!0-9:]*|:*|*:) output_valid='invalid' ;; esac
  if [ "$output_valid" = 'valid' ] && [ "$actual_size" -gt "$expected_size" ]; then output_valid='invalid'; fi
  if [ "$output_valid" = 'valid' ] && [ "$actual_size" -gt 0 ]; then
    /bin/dd if="$expected_output" of="$expected_prefix" bs=1 count="$actual_size" 2>/dev/null || output_valid='invalid'
    if [ "$output_valid" = 'valid' ] && ! /usr/bin/cmp -s "$phase_output" "$expected_prefix"; then output_valid='invalid'; fi
    last_byte=$(/usr/bin/od -An -tu1 -j $((actual_size - 1)) -N 1 "$phase_output" 2>/dev/null | /usr/bin/tr -d ' ')
    if [ "$last_byte" != '10' ]; then output_valid='invalid'; fi
  fi
  marker_count=$(/usr/bin/wc -l < "$phase_output" | /usr/bin/tr -d ' ')
  case "$marker_count" in ''|*[!0-9]*) marker_count=0; output_valid='invalid' ;; esac
  if [ "$phase_status" -eq 0 ] && ! /usr/bin/cmp -s "$phase_output" "$expected_output"; then output_valid='invalid'; fi
  if [ "$marker_count" -lt 2 ]; then output_valid='invalid'; fi
  case "$phase_status" in 0) ;; *) batch_valid=0 ;; esac
  if [ "$output_valid" != 'valid' ]; then batch_valid=0; fi
  append_result "$phase" "$phase_status" "$marker_count" "$output_valid" || exit 70
  case "$phase_status" in
    0|124) ;;
    125|137|255)
      emit_results || exit 70
      command printf '%s\n' 'Process teardown was ambiguous; no later iPad access was attempted.' >&2
      exit 75
      ;;
    *)
      emit_results || exit 70
      command printf '%s\n' 'An unexpected remote status stopped the batch before later iPad access.' >&2
      exit 75
      ;;
  esac
done

result_count=$(/usr/bin/wc -l < "$results_file" | /usr/bin/tr -d ' ')
if [ "$result_count" != 16 ]; then exit 70; fi

if ! (ulimit -f 2048 2>/dev/null && scp_from_device "$remote_probe" "$probe_after"); then
  command printf '%s\n' 'The staged diagnostic could not be read back after the batch.' >&2
  exit 74
fi
probe_sha=$(sha256_file "$probe_after") || exit 65
if [ "$probe_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'The staged diagnostic digest changed during the batch.' >&2
  exit 65
fi

emit_results || exit 70
if [ "$batch_valid" -ne 1 ]; then exit 65; fi
