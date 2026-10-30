#!/bin/sh
# Read-only boundary isolator for the staged diagnostic probe's launch chain.
# Do not run until this exact revision passes adversarial review with an explicit
# finding that no reachable command makes a persistent device change.
#
# What this script does:
# 1. Pins the SSH key and host record. Default mode also verifies the staged
#    diagnostic by complete SCP readback before any remote command; root trust
#    mode never opens or accesses the diagnostic.
# 2. In the default mode, opens a fresh key-only `mobile` SSH session for each
#    boundary: remote shell, rootless env/tool selection, timeout behavior,
#    read-only trust-cache membership, and two marker-only diagnostic launches.
#    The `root-trust-only` mode instead uses key-only `root` SSH for one bounded
#    read-only membership stage, then exits without launching the diagnostic.
# 3. Runs only the diagnostic binary's `launch` phase. That phase emits its
#    process/begin/end markers and performs no inventory, IOKit, symbol, registry,
#    configuration, user-client, or report operation.
# 4. Accepts only exact fixed marker prefixes. Any nonzero status, malformed
#    output, disconnect, or ambiguous local timeout stops all later iPad access.
#    A fully successful sequence finishes with a second complete SCP readback.
#
# Device effects and boundaries:
# - No remote file is created, replaced, renamed, removed, or opened for writing.
# - SCP opens the fixed staged binary for reading; execution may update ordinary
#   access/accounting metadata and SSH or process logs.
# - The timeout canary starts and terminates only a fixed one-second sleep process.
# - Fixed noninteractive `sudo` first runs a bounded `true` canary, then runs only
#   `jbctl trustcache info`, which Dopamine implements as a read-only XPC query.
#   A device-side timeout and 64-KiB parser bound apply; cache contents are
#   suppressed and no mutation subcommand exists.
# - The two launch stages execute the already staged, entitlement-free diagnostic
#   by pathname. Its audited launch phase writes only fixed stdout markers.
# - A local watchdog can close an SSH client after twenty seconds. If teardown is
#   not observed, the runner returns status 125 and performs no later device access.

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
readonly remote_probe='/var/mobile/Documents/mac2jb-ios-probe-diagnostic-87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'

runner_mode='mobile-launch'
case "$#:$*" in
  0:) ;;
  1:root-trust-only) runner_mode='root-trust-only' ;;
  *)
    command printf '%s\n' 'Usage: run-diagnostic-launch-isolation.sh [root-trust-only]' >&2
    exit 64
    ;;
esac
case "$runner_mode" in
  mobile-launch) ssh_user='mobile' ;;
  root-trust-only) ssh_user='root' ;;
  *) exit 64 ;;
esac
readonly runner_mode ssh_user

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

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-diag-isolation.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-diag-isolation.*) ;; *) exit 70 ;; esac
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
stage_output="$temp_dir/output"
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

# Each local SSH/SCP client receives a private process group. A local deadline
# kills and reaps that whole client group and returns 125; callers treat it as
# ambiguous remote teardown and make no later iPad access.
process_runner_code='import os
import signal
import subprocess
import sys

handled_signals = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
received_signal = 0


class RunnerInterrupted(Exception):
    pass


def handle_signal(signum, _frame):
    global received_signal
    received_signal = signum
    signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
    raise RunnerInterrupted()


def kill_and_reap(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait()
    except ChildProcessError:
        pass


previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
for handled_signal in handled_signals:
    signal.signal(handled_signal, handle_signal)


def restore_child_mask():
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


try:
    process = subprocess.Popen(
        sys.argv[1:],
        stdin=subprocess.DEVNULL,
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
        return_code = process.wait(timeout=20,)
    except subprocess.TimeoutExpired:
        kill_and_reap(process)
        raise SystemExit(125)
except RunnerInterrupted:
    kill_and_reap(process)
    raise SystemExit(128 + received_signal)
except BaseException:
    kill_and_reap(process)
    raise

if return_code < 0:
    kill_and_reap(process)
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

if [ "$runner_mode" = 'mobile-launch' ]; then
  if ! (ulimit -f 2048 2>/dev/null && scp_from_device "$remote_probe" "$probe_before"); then
    command printf '%s\n' 'The staged diagnostic could not be read back. Nothing was run.' >&2
    exit 74
  fi
  probe_sha=$(sha256_file "$probe_before") || exit 65
  if [ "$probe_sha" != "$expected_probe_sha" ]; then
    command printf '%s\n' 'The staged diagnostic digest differs from the reviewed binary. Nothing was run.' >&2
    exit 65
  fi
fi

write_expected() {
  stage=$1
  : > "$expected_output" || return 70
  command printf 'MAC2JB_ISO v1 %s begin\n' "$stage" >> "$expected_output" || return 70
  case "$stage" in
    diagnostic-direct|diagnostic-timeout)
      command printf '%s\n' \
        'MAC2JB_DIAG_PROCESS v1' \
        'MAC2JB_DIAG_BEGIN v1 launch' \
        'MAC2JB_DIAG_END v1 launch ok' >> "$expected_output" || return 70
      ;;
    shell|env-select|tools-select|env-canary|timeout-canary)
      command printf 'MAC2JB_ISO v1 %s ok\n' "$stage" >> "$expected_output" || return 70
      ;;
    trustcache-membership)
      command printf '%s\n' 'MAC2JB_ISO v1 trustcache-membership member' >> "$expected_output" || return 70
      ;;
    *) return 64 ;;
  esac
}

emit_results() {
  /bin/cat "$results_file"
}

run_stage() {
  stage=$1
  remote_command=$2
  write_expected "$stage" || exit 70
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
  ) > "$stage_output" 2>/dev/null
  stage_status=$?

  output_valid='valid'
  stage_detail=''
  if [ "$stage" = 'trustcache-membership' ] && [ "$stage_status" -eq 0 ]; then
    if /usr/bin/cmp -s "$stage_output" "$expected_output"; then
      stage_detail='member'
    else
      : > "$expected_output" || exit 70
      command printf '%s\n' \
        'MAC2JB_ISO v1 trustcache-membership begin' \
        'MAC2JB_ISO v1 trustcache-membership not-member' > "$expected_output" || exit 70
      if /usr/bin/cmp -s "$stage_output" "$expected_output"; then stage_detail='not-member'; fi
    fi
  fi
  actual_size=$(/usr/bin/wc -c < "$stage_output" | /usr/bin/tr -d ' ')
  expected_size=$(/usr/bin/wc -c < "$expected_output" | /usr/bin/tr -d ' ')
  case "$actual_size:$expected_size" in *[!0-9:]*|:*|*:) output_valid='invalid' ;; esac
  if [ "$output_valid" = 'valid' ] && [ "$actual_size" -gt "$expected_size" ]; then output_valid='invalid'; fi
  if [ "$output_valid" = 'valid' ] && [ "$actual_size" -gt 0 ]; then
    /bin/dd if="$expected_output" of="$expected_prefix" bs=1 count="$actual_size" 2>/dev/null || output_valid='invalid'
    if [ "$output_valid" = 'valid' ] && ! /usr/bin/cmp -s "$stage_output" "$expected_prefix"; then output_valid='invalid'; fi
    last_byte=$(/usr/bin/od -An -tu1 -j $((actual_size - 1)) -N 1 "$stage_output" 2>/dev/null | /usr/bin/tr -d ' ')
    if [ "$last_byte" != '10' ]; then output_valid='invalid'; fi
  fi
  marker_count=$(/usr/bin/wc -l < "$stage_output" | /usr/bin/tr -d ' ')
  case "$marker_count" in ''|*[!0-9]*) marker_count=0; output_valid='invalid' ;; esac
  if [ "$marker_count" -lt 1 ]; then output_valid='invalid'; fi
  if [ "$stage_status" -eq 0 ] && ! /usr/bin/cmp -s "$stage_output" "$expected_output"; then output_valid='invalid'; fi

  if [ "$stage" = 'trustcache-membership' ] && [ -n "$stage_detail" ]; then
    command printf 'isolation-result: %s status=%s markers=%s output=%s detail=%s\n' \
      "$stage" "$stage_status" "$marker_count" "$output_valid" "$stage_detail" >> "$results_file" || exit 70
  else
    command printf 'isolation-result: %s status=%s markers=%s output=%s\n' \
      "$stage" "$stage_status" "$marker_count" "$output_valid" >> "$results_file" || exit 70
  fi

  if [ "$stage_status" -ne 0 ] || [ "$output_valid" != 'valid' ]; then
    emit_results || exit 70
    command printf '%s\n' 'The boundary failed or was ambiguous; no later iPad access was attempted.' >&2
    exit 75
  fi
}

select_env_code='env_path=; for env_candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ ! -L "$env_candidate" ] && [ -f "$env_candidate" ] && [ -r "$env_candidate" ] && [ ! -w "$env_candidate" ] && [ -x "$env_candidate" ]; then env_path=$env_candidate; break; fi; done; if [ -z "$env_path" ]; then exit 66; fi'
select_timeout_code='timeout_path=; for timeout_candidate in /var/jb/usr/bin/timeout /var/jb/bin/timeout /usr/bin/timeout /bin/timeout /var/jb/usr/bin/gtimeout /var/jb/bin/gtimeout /usr/bin/gtimeout /bin/gtimeout; do if [ ! -L "$timeout_candidate" ] && [ -f "$timeout_candidate" ] && [ -r "$timeout_candidate" ] && [ ! -w "$timeout_candidate" ] && [ -x "$timeout_candidate" ]; then timeout_path=$timeout_candidate; break; fi; done; if [ -z "$timeout_path" ]; then exit 67; fi'
select_sleep_code='sleep_path=; for sleep_candidate in /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep; do if [ ! -L "$sleep_candidate" ] && [ -f "$sleep_candidate" ] && [ -r "$sleep_candidate" ] && [ ! -w "$sleep_candidate" ] && [ -x "$sleep_candidate" ]; then sleep_path=$sleep_candidate; break; fi; done; if [ -z "$sleep_path" ]; then exit 68; fi'
select_jbctl_code='jbctl_path=; for jbctl_candidate in /var/jb/basebin/jbctl /var/jb/usr/bin/jbctl; do if [ ! -L "$jbctl_candidate" ] && [ -f "$jbctl_candidate" ] && [ -r "$jbctl_candidate" ] && [ ! -w "$jbctl_candidate" ] && [ -x "$jbctl_candidate" ]; then jbctl_path=$jbctl_candidate; break; fi; done; if [ -z "$jbctl_path" ]; then exit 72; fi'
select_sudo_code='sudo_path=; for sudo_candidate in /var/jb/usr/bin/sudo /var/jb/bin/sudo /usr/bin/sudo; do if [ ! -L "$sudo_candidate" ] && [ -f "$sudo_candidate" ] && [ -r "$sudo_candidate" ] && [ ! -w "$sudo_candidate" ] && [ -x "$sudo_candidate" ]; then sudo_path=$sudo_candidate; break; fi; done; if [ -z "$sudo_path" ]; then exit 75; fi'
select_head_code='head_path=; for head_candidate in /var/jb/usr/bin/head /var/jb/bin/head /usr/bin/head /bin/head; do if [ ! -L "$head_candidate" ] && [ -f "$head_candidate" ] && [ -r "$head_candidate" ] && [ ! -w "$head_candidate" ] && [ -x "$head_candidate" ]; then head_path=$head_candidate; break; fi; done; if [ -z "$head_path" ]; then exit 76; fi'
select_grep_code='grep_path=; for grep_candidate in /var/jb/usr/bin/grep /var/jb/bin/grep /usr/bin/grep /bin/grep; do if [ ! -L "$grep_candidate" ] && [ -f "$grep_candidate" ] && [ -r "$grep_candidate" ] && [ ! -w "$grep_candidate" ] && [ -x "$grep_candidate" ]; then grep_path=$grep_candidate; break; fi; done; if [ -z "$grep_path" ]; then exit 77; fi'
select_true_code='true_path=; for true_candidate in /usr/bin/true /bin/true /var/jb/usr/bin/true /var/jb/bin/true; do if [ ! -L "$true_candidate" ] && [ -f "$true_candidate" ] && [ -r "$true_candidate" ] && [ ! -w "$true_candidate" ] && [ -x "$true_candidate" ]; then true_path=$true_candidate; break; fi; done; if [ -z "$true_path" ]; then exit 94; fi'
select_root_trust_tools_code='stat_path=; for stat_candidate in /usr/bin/stat /bin/stat /var/jb/usr/bin/stat /var/jb/bin/stat; do if [ ! -L "$stat_candidate" ] && [ -f "$stat_candidate" ] && [ -r "$stat_candidate" ] && [ -x "$stat_candidate" ]; then stat_path=$stat_candidate; break; fi; done; if [ -z "$stat_path" ]; then exit 95; fi; root_tool_ok() { tool_path=$1; if [ -L "$tool_path" ] || [ ! -f "$tool_path" ] || [ ! -r "$tool_path" ] || [ ! -x "$tool_path" ]; then return 1; fi; tool_meta=$("$stat_path" -f "%u:%Lp" "$tool_path" 2>/dev/null) || return 1; case "$tool_meta" in 0:[0-7][0-7][0-7]) tool_mode=${tool_meta#*:} ;; 0:[0-7][0-7][0-7][0-7]) tool_mode=${tool_meta#*:}; tool_mode=${tool_mode#?} ;; *) return 1 ;; esac; group_digit=${tool_mode#?}; group_digit=${group_digit%?}; other_digit=${tool_mode#??}; case "$group_digit$other_digit" in *[2367]*) return 1 ;; esac; return 0; }; if ! root_tool_ok "$stat_path"; then exit 95; fi; timeout_path=; for timeout_candidate in /var/jb/usr/bin/timeout /var/jb/bin/timeout /usr/bin/timeout /bin/timeout /var/jb/usr/bin/gtimeout /var/jb/bin/gtimeout /usr/bin/gtimeout /bin/gtimeout; do if root_tool_ok "$timeout_candidate"; then timeout_path=$timeout_candidate; break; fi; done; if [ -z "$timeout_path" ]; then exit 96; fi; sleep_path=; for sleep_candidate in /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep; do if root_tool_ok "$sleep_candidate"; then sleep_path=$sleep_candidate; break; fi; done; if [ -z "$sleep_path" ]; then exit 97; fi; jbctl_path=; for jbctl_candidate in /var/jb/basebin/jbctl /var/jb/usr/bin/jbctl; do if root_tool_ok "$jbctl_candidate"; then jbctl_path=$jbctl_candidate; break; fi; done; if [ -z "$jbctl_path" ]; then exit 98; fi; head_path=; for head_candidate in /var/jb/usr/bin/head /var/jb/bin/head /usr/bin/head /bin/head; do if root_tool_ok "$head_candidate"; then head_path=$head_candidate; break; fi; done; if [ -z "$head_path" ]; then exit 99; fi; grep_path=; for grep_candidate in /var/jb/usr/bin/grep /var/jb/bin/grep /usr/bin/grep /bin/grep; do if root_tool_ok "$grep_candidate"; then grep_path=$grep_candidate; break; fi; done; if [ -z "$grep_path" ]; then exit 100; fi'
validate_probe_code="if [ -L /var/mobile/Documents ] || [ ! -d /var/mobile/Documents ] || [ -L '$remote_probe' ] || [ ! -f '$remote_probe' ] || [ ! -r '$remote_probe' ] || [ -w '$remote_probe' ] || [ ! -x '$remote_probe' ]; then exit 69; fi"
clean_path='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
diagnostic_cdhash='d4afc7698e19545e4714f1c8cc6cd74976276738'

: > "$results_file" || exit 70

if [ "$runner_mode" = 'root-trust-only' ]; then
  run_stage 'trustcache-membership' \
    "exec 2>&-; set +euxv; stage_tag='trustcache-membership'; command printf '%s\\n' 'MAC2JB_ISO v1 trustcache-membership begin'; $select_root_trust_tools_code; \"\$timeout_path\" -k 1 0.1 \"\$sleep_path\" 1 </dev/null >/dev/null 2>&1; canary_status=\$?; if [ \"\$canary_status\" -ne 124 ]; then exit 70; fi; trustcache_capture=\$( { \"\$timeout_path\" -k 1 5 \"\$jbctl_path\" trustcache info 2>&-; query_status=\$?; command printf '\\nMAC2JB_QUERY_STATUS:%s' \"\$query_status\"; } | \"\$head_path\" -c 65537; command printf 'Z'; ); case \"\$trustcache_capture\" in *Z) trustcache_output=\${trustcache_capture%Z} ;; *) exit 73 ;; esac; if [ \"\${#trustcache_output}\" -gt 65536 ]; then exit 74; fi; case \"\$trustcache_output\" in *MAC2JB_QUERY_STATUS:*) query_status=\${trustcache_output##*MAC2JB_QUERY_STATUS:} ;; *) exit 73 ;; esac; case \"\$query_status\" in ''|*[!0-9]*) exit 73 ;; 0) ;; 1) exit 85 ;; 2) exit 86 ;; 3) exit 87 ;; 124) exit 88 ;; 125) exit 89 ;; 126) exit 90 ;; 127) exit 91 ;; *) if [ \"\$query_status\" -ge 128 ]; then exit 92; fi; exit 93 ;; esac; command printf '%s\\n' \"\$trustcache_output\" | \"\$grep_path\" -E -q '^\\| [0-9]+:[[:space:]]+$diagnostic_cdhash\$'; grep_status=\$?; case \"\$grep_status\" in 0) trustcache_label='member' ;; 1) trustcache_label='not-member' ;; *) exit 78 ;; esac; command printf 'MAC2JB_ISO v1 trustcache-membership %s\\n' \"\$trustcache_label\""

  result_count=$(/usr/bin/wc -l < "$results_file" | /usr/bin/tr -d ' ')
  if [ "$result_count" != 1 ]; then exit 70; fi
  emit_results || exit 70
  exit 0
fi

run_stage 'shell' \
  "exec 2>&-; set +euxv; stage_tag='shell'; command printf '%s\\n' 'MAC2JB_ISO v1 shell begin' 'MAC2JB_ISO v1 shell ok'"

run_stage 'env-select' \
  "exec 2>&-; set +euxv; stage_tag='env-select'; command printf '%s\\n' 'MAC2JB_ISO v1 env-select begin'; $select_env_code; command printf '%s\\n' 'MAC2JB_ISO v1 env-select ok'"

run_stage 'tools-select' \
  "exec 2>&-; set +euxv; stage_tag='tools-select'; command printf '%s\\n' 'MAC2JB_ISO v1 tools-select begin'; $select_timeout_code; $select_sleep_code; command printf '%s\\n' 'MAC2JB_ISO v1 tools-select ok'"

run_stage 'env-canary' \
  "exec 2>&-; set +euxv; stage_tag='env-canary'; command printf '%s\\n' 'MAC2JB_ISO v1 env-canary begin'; $select_env_code; $select_sleep_code; \"\$env_path\" -i PATH='$clean_path' LC_ALL=C \"\$sleep_path\" 0 </dev/null >/dev/null 2>&1; canary_status=\$?; if [ \"\$canary_status\" -ne 0 ]; then exit 70; fi; command printf '%s\\n' 'MAC2JB_ISO v1 env-canary ok'"

run_stage 'timeout-canary' \
  "exec 2>&-; set +euxv; stage_tag='timeout-canary'; command printf '%s\\n' 'MAC2JB_ISO v1 timeout-canary begin'; $select_timeout_code; $select_sleep_code; \"\$timeout_path\" -k 1 0.1 \"\$sleep_path\" 1 </dev/null >/dev/null 2>&1; canary_status=\$?; if [ \"\$canary_status\" -ne 124 ]; then exit 70; fi; command printf '%s\\n' 'MAC2JB_ISO v1 timeout-canary ok'"

run_stage 'trustcache-membership' \
  "exec 2>&-; set +euxv; stage_tag='trustcache-membership'; command printf '%s\\n' 'MAC2JB_ISO v1 trustcache-membership begin'; $select_timeout_code; $select_jbctl_code; $select_sudo_code; $select_head_code; $select_grep_code; $select_true_code; \"\$sudo_path\" -n -- \"\$timeout_path\" -k 1 3 \"\$true_path\" </dev/null >/dev/null 2>&1; sudo_canary_status=\$?; if [ \"\$sudo_canary_status\" -ne 0 ]; then exit 79; fi; trustcache_capture=\$( { \"\$sudo_path\" -n -- \"\$timeout_path\" -k 1 5 \"\$jbctl_path\" trustcache info 2>&-; query_status=\$?; command printf '\\nMAC2JB_QUERY_STATUS:%s' \"\$query_status\"; } | \"\$head_path\" -c 65537; command printf 'Z'; ); case \"\$trustcache_capture\" in *Z) trustcache_output=\${trustcache_capture%Z} ;; *) exit 73 ;; esac; if [ \"\${#trustcache_output}\" -gt 65536 ]; then exit 74; fi; case \"\$trustcache_output\" in *MAC2JB_QUERY_STATUS:*) query_status=\${trustcache_output##*MAC2JB_QUERY_STATUS:} ;; *) exit 73 ;; esac; case \"\$query_status\" in ''|*[!0-9]*) exit 73 ;; 0) ;; 1) exit 85 ;; 2) exit 86 ;; 3) exit 87 ;; 124) exit 88 ;; 125) exit 89 ;; 126) exit 90 ;; 127) exit 91 ;; *) if [ \"\$query_status\" -ge 128 ]; then exit 92; fi; exit 93 ;; esac; command printf '%s\\n' \"\$trustcache_output\" | \"\$grep_path\" -E -q '^\\| [0-9]+:[[:space:]]+$diagnostic_cdhash\$'; grep_status=\$?; case \"\$grep_status\" in 0) trustcache_label='member' ;; 1) trustcache_label='not-member' ;; *) exit 78 ;; esac; command printf 'MAC2JB_ISO v1 trustcache-membership %s\\n' \"\$trustcache_label\""

run_stage 'diagnostic-direct' \
  "exec 2>&-; set +euxv; stage_tag='diagnostic-direct'; command printf '%s\\n' 'MAC2JB_ISO v1 diagnostic-direct begin'; $select_env_code; $validate_probe_code; exec \"\$env_path\" -i PATH='$clean_path' LC_ALL=C '$remote_probe' --diagnostic-phase 'launch'"

run_stage 'diagnostic-timeout' \
  "exec 2>&-; set +euxv; stage_tag='diagnostic-timeout'; command printf '%s\\n' 'MAC2JB_ISO v1 diagnostic-timeout begin'; $select_env_code; $select_timeout_code; $select_sleep_code; $validate_probe_code; \"\$timeout_path\" -k 1 0.1 \"\$sleep_path\" 1 </dev/null >/dev/null 2>&1; canary_status=\$?; if [ \"\$canary_status\" -ne 124 ]; then exit 70; fi; exec \"\$timeout_path\" -k 1 12 \"\$env_path\" -i PATH='$clean_path' LC_ALL=C '$remote_probe' --diagnostic-phase 'launch'"

result_count=$(/usr/bin/wc -l < "$results_file" | /usr/bin/tr -d ' ')
if [ "$result_count" != 8 ]; then exit 70; fi

if ! (ulimit -f 2048 2>/dev/null && scp_from_device "$remote_probe" "$probe_after"); then
  command printf '%s\n' 'The staged diagnostic could not be read back after isolation.' >&2
  exit 74
fi
probe_sha=$(sha256_file "$probe_after") || exit 65
if [ "$probe_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'The staged diagnostic digest changed during isolation.' >&2
  exit 65
fi

emit_results || exit 70
exit 0
