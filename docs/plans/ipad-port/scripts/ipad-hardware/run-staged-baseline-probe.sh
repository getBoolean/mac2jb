#!/bin/sh
# Device-writing step: execute the staged baseline probe and retrieve one report.
# Do not run without adversarial PASS and explicit native device-write approval.
#
# What this script does:
# 1. Stages and verifies the approved SSH key and pinned host record locally.
# 2. Downloads and hashes the staged probe through isolated, no-follow local file
#    helpers, then requires the fixed remote path to be a readable, non-writable,
#    executable regular file immediately before launch. The iPad has no reviewed
#    Python/FD-exec helper, so execution uses the fixed absolute pathname under a
#    clean environment and repeats the mode checks plus full SCP hash afterward.
# 3. Executes only that baseline with fixed operator-supplied target/setup claims,
#    client type, and report path. Remote diagnostics are closed, umask is 077, and
#    a local isolated watchdog limits the SSH invocation to 60 seconds.
# 4. Requires the exact report-path line plus exact report-byte and topology SHA-256
#    lines, downloads the JSON under a local size cap, and checks both hashes and
#    the fixed invocation fields.
# 5. Publishes the raw report through an exclusive hard link inside the gitignored
#    build/ipad-hardware/device-reports directory, so it cannot overwrite a local file.
#
# Device effects and failure behavior:
# - The baseline performs read-only IOKit discovery/open/readback operations. Its
#   writer creates one random mode-0600 temporary file, exclusively renames it to
#   the fixed JSON report on success, and deletes only that temp on handled failure.
#   Normal SSH authentication/process/accounting logs may also occur.
# - It never transfers another executable, overwrites a report, invokes a USB
#   configuration setter, or changes registry properties.
# - A kill or timeout can leave a partial or complete `.mac2jb-probe-*.tmp` file,
#   or the final report if the rename completed. A retrieval/validation failure
#   leaves the final report in place. Any cleanup needs separate review and approval.
# - Because execution must resolve a pathname, a hostile concurrent process running
#   as `mobile` could replace and restore it inside the launch window. Pre/post full
#   hashes detect ordinary replacement, not that same-UID adversarial race.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly expected_probe_sha='878ab27771fd7a660ba9f3997427b9ef92573bd524cad43bb89aded354d6d118'
readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'
readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'
readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'
readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'
readonly ssh_host='127.0.0.1'
readonly ssh_port='2222'
readonly ssh_user='mobile'
readonly remote_probe='/var/mobile/Documents/mac2jb-ios-probe-baseline-878ab27771fd7a660ba9f3997427b9ef92573bd524cad43bb89aded354d6d118'
readonly remote_report='/var/mobile/Documents/mac2jb-probe-baseline-capture-host-a.json'

script_dir=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" 2>/dev/null && pwd -P) || exit 64
repo_root=$(CDPATH= cd -P "$script_dir/../../../../.." 2>/dev/null && pwd -P) || exit 64
local_report_dir="$repo_root/build/ipad-hardware/device-reports"
local_report="$local_report_dir/baseline-capture-host-a.json"
local_report_temp=''

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: run-staged-baseline-probe.sh' >&2
  exit 64
fi
if [ -e "$local_report" ] || [ -L "$local_report" ]; then
  command printf '%s\n' 'Local report destination already exists. Nothing was run.' >&2
  exit 73
fi
for credential in "$identity_file" "$known_hosts_file"; do
  if [ ! -f "$credential" ] || [ -L "$credential" ]; then
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

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-run-probe.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-run-probe.*) ;; *) exit 70 ;; esac
cleanup() {
  /bin/rm -f "$temp_dir/identity" "$temp_dir/known_hosts" "$temp_dir/probe-roundtrip" \
    "$temp_dir/probe-post-roundtrip" \
    "$temp_dir/stdout" "$temp_dir/stdout-bytes" "$local_report_temp" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

staged_identity="$temp_dir/identity"
staged_known_hosts="$temp_dir/known_hosts"
probe_roundtrip="$temp_dir/probe-roundtrip"
probe_post_roundtrip="$temp_dir/probe-post-roundtrip"
stdout_file="$temp_dir/stdout"
stdout_bytes="$temp_dir/stdout-bytes"

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
  /usr/bin/scp \
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

if ! (ulimit -f 2048 2>/dev/null && scp_from_device "$remote_probe" "$probe_roundtrip"); then
  command printf '%s\n' 'The staged probe could not be read back. Nothing was run.' >&2
  exit 74
fi
probe_sha=$(sha256_file "$probe_roundtrip") || exit 65
if [ "$probe_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'The staged probe digest differs from the reviewed binary. Nothing was run.' >&2
  exit 65
fi

remote_command="exec 2>&-; set +euxv; env_path=; for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ -x \"\$candidate\" ]; then env_path=\$candidate; break; fi; done; if [ -z \"\$env_path\" ]; then exit 127; fi; if [ -L /var/mobile/Documents ] || [ ! -d /var/mobile/Documents ] || [ -L '$remote_probe' ] || [ ! -f '$remote_probe' ] || [ ! -r '$remote_probe' ] || [ -w '$remote_probe' ] || [ ! -x '$remote_probe' ]; then exit 65; fi; umask 077; \"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C '$remote_probe' --soc T8112 --port-family thunderbolt-usb4 --dopamine-build unknown --trollstore-build unknown --peer-kind capture-host --peer-id operator-claimed-capture-host-primary --cable-id operator-claimed-usb-c-cable-primary --orientation a --power-state operator-claimed-charging-external --client-type 0 --output '$remote_report'; probe_status=\$?; if [ \"\$probe_status\" -ne 0 ]; then exit \"\$probe_status\"; fi; if [ -L '$remote_probe' ] || [ ! -f '$remote_probe' ] || [ ! -r '$remote_probe' ] || [ -w '$remote_probe' ] || [ ! -x '$remote_probe' ]; then exit 65; fi"
ssh_runner_code='import subprocess
import sys

try:
    completed = subprocess.run(
        sys.argv[1:],
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(completed.returncode)'

(
  ulimit -f 2 2>/dev/null || exit 70
  exec /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C \
    /usr/bin/python3 -I -S -c "$ssh_runner_code" /usr/bin/ssh \
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
) > "$stdout_file" 2>/dev/null
run_status=$?
if [ "$run_status" -ne 0 ]; then
  command printf 'Baseline probe failed with status %s; no report was accepted.\n' "$run_status" >&2
  exit 69
fi
if ! (ulimit -f 2048 2>/dev/null && scp_from_device "$remote_probe" "$probe_post_roundtrip"); then
  command printf '%s\n' 'The staged probe could not be read back after execution; no report was accepted.' >&2
  exit 74
fi
probe_post_sha=$(sha256_file "$probe_post_roundtrip") || exit 65
if [ "$probe_post_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'The staged probe digest changed during execution; no report was accepted.' >&2
  exit 65
fi
/usr/bin/od -An -tu1 -v "$stdout_file" > "$stdout_bytes" || exit 65
if ! /usr/bin/awk '
  BEGIN { valid = 1; last = -1 }
  { for (i = 1; i <= NF; i++) { byte = $i + 0; if (byte != 10 && (byte < 32 || byte > 126)) valid = 0; last = byte } }
  END { exit !(valid && last == 10) }
' "$stdout_bytes"; then
  command printf '%s\n' 'Baseline probe stdout contained a disallowed byte or lacked its final newline.' >&2
  exit 65
fi
if ! /usr/bin/awk -v report="$remote_report" '
  BEGIN {
    valid = 1
    report_prefix = "MAC2JB_REPORT_SHA256 "
    topology_prefix = "MAC2JB_TOPOLOGY_SHA256 "
  }
  NR == 1 && $0 != "MAC2JB_PROBE_REPORT " report { valid = 0 }
  NR == 2 {
    digest = substr($0, length(report_prefix) + 1)
    if (substr($0, 1, length(report_prefix)) != report_prefix || length(digest) != 64 || digest !~ /^[0-9a-f]+$/) valid = 0
  }
  NR == 3 {
    digest = substr($0, length(topology_prefix) + 1)
    if (substr($0, 1, length(topology_prefix)) != topology_prefix || length(digest) != 64 || digest !~ /^[0-9a-f]+$/) valid = 0
  }
  NR > 3 { valid = 0 }
  END { exit !(valid && NR == 3) }
' "$stdout_file"; then
  command printf '%s\n' 'Baseline probe stdout did not match the exact three-line success grammar.' >&2
  exit 65
fi
printed_report_sha=$(/usr/bin/awk 'NR == 2 { print $2 }' "$stdout_file")
printed_topology_sha=$(/usr/bin/awk 'NR == 3 { print $2 }' "$stdout_file")

/bin/mkdir -p "$local_report_dir" || exit 70
if [ ! -d "$local_report_dir" ] || [ -L "$local_report_dir" ]; then exit 70; fi
local_report_temp=$(/usr/bin/mktemp "$local_report_dir/.baseline-capture-host-a.XXXXXX") || exit 70
/bin/chmod 600 "$local_report_temp" || exit 70

(
  ulimit -f 2048 2>/dev/null || exit 70
  scp_from_device "$remote_report" "$local_report_temp"
) || {
  command printf '%s\n' 'The device report could not be retrieved or exceeded the local size cap.' >&2
  exit 74
}
if [ ! -s "$local_report_temp" ] || [ -L "$local_report_temp" ]; then exit 65; fi
/usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C /usr/bin/python3 -I -S -c '
import hashlib
import json
import os
import stat
import sys

def require(condition):
    if not condition:
        raise SystemExit(65)

path, expected_sha, topology = sys.argv[1:]
report_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
report_status = os.fstat(report_fd)
require(stat.S_ISREG(report_status.st_mode) and report_status.st_nlink == 1)
data = bytearray()
while True:
    chunk = os.read(report_fd, 65536)
    if not chunk:
        break
    data.extend(chunk)
    require(len(data) <= 2097152)
os.close(report_fd)
require(hashlib.sha256(data).hexdigest() == expected_sha)
document = json.loads(data)
require(document.get("schemaVersion") == 1)
target = document["target"]
require(target["productType"] == "iPad14,5")
require(target["boardIdentifier"] == "J620AP")
require(target["soc"] == "T8112")
require(target["portFamily"] == "thunderbolt-usb4")
require(target["dopamineBuild"] == "unknown")
require(target["trollStoreBuild"] == "unknown")
role = document["role"]
require(role["peerKind"] == "capture-host")
require(role["orientation"] == "a")
require(role["powerState"] == "operator-claimed-charging-external")
require(role["peerIdentity"] == {"algorithm": "sha256", "digest": hashlib.sha256(b"operator-claimed-capture-host-primary").hexdigest()})
require(role["cableIdentity"] == {"algorithm": "sha256", "digest": hashlib.sha256(b"operator-claimed-usb-c-cable-primary").hexdigest()})
require(document["topologyFingerprint"] == topology)
for key in ("controllers", "functions", "symbols", "entitlements", "operations"):
    require(isinstance(document[key], list))
for service in document["controllers"] + document["functions"]:
    require(isinstance(service, dict))
    open_results = service.get("openResults")
    require(isinstance(open_results, list) and len(open_results) == 1)
    require(isinstance(open_results[0], dict) and open_results[0].get("clientType") == 0)
' "$local_report_temp" "$printed_report_sha" "$printed_topology_sha" || exit 65

if [ -e "$local_report" ] || [ -L "$local_report" ]; then exit 73; fi
/bin/ln "$local_report_temp" "$local_report" || exit 73
/bin/rm -f "$local_report_temp" || exit 70
local_report_temp=''
report_sha=$(sha256_file "$local_report") || exit 65
if [ "$report_sha" != "$printed_report_sha" ]; then exit 65; fi
command printf 'ACCEPTED_REPORT %s %s\n' "$report_sha" "$local_report"
