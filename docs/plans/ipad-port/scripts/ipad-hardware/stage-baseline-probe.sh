#!/bin/sh
# Device-writing step: stage one allowlisted, digest-pinned probe on the iPad.
# Do not run without adversarial PASS and explicit native device-write approval.
#
# What this script does:
# 1. With no argument, selects the historical baseline. With the exact `diagnostic`
#    argument, selects the entitlement-free no-report phase probe. No other target
#    is accepted. It resolves that local binary and verifies its approved SHA-256.
#    Every local digest uses an isolated Python helper that opens with O_NOFOLLOW,
#    requires a regular single-link file, bounds input to 2 MiB, and hashes that FD.
# 2. Copies the SSH key and pinned host record into a private local temp directory,
#    then verifies their owner, mode, and approved digests.
# 3. Opens a key-only, host-pinned SSH session with user config, forwarding,
#    agents, proxies, TTYs, and connection sharing disabled.
# 4. Builds a local one-member ustar archive with fixed owner/group metadata and a
#    mode-0500 regular-file member and fixed 2020-01-01 UTC mtime. Every local tar
#    operation runs under env -i. An isolated local Python feeder opens the archive
#    once without following symlinks, buffers and verifies its pinned SHA-256, and
#    streams those same verified bytes to allowlisted rootless GNU tar under env -i.
#    `--keep-old-files` refuses any existing target; owner/permission restoration
#    is suppressed and remote umask is 077.
# 5. Requires the extracted fixed path to be a readable, non-writable, executable
#    regular file, then downloads it and compares its complete SHA-256 locally.
#
# Device effects and failure behavior:
# - This script creates one device file and changes its mode; those are persistent
#   device writes. Normal SSH authentication/process/accounting logs may also occur.
# - It never executes the selected probe, creates a report, changes USB state,
#   overwrites an existing path, or deletes device files.
# - GNU tar does not expose safe-writes on this target. A failed or interrupted
#   extraction may leave a partial or complete target, potentially executable.
#   The separate run script still hashes it before launch. Any leftover requires a
#   separately reviewed cleanup; this staging script never removes device files.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'
readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'
readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'
readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'
readonly ssh_host='127.0.0.1'
readonly ssh_port='2222'
readonly ssh_user='mobile'
script_dir=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" 2>/dev/null && pwd -P) || exit 64
repo_root=$(CDPATH= cd -P "$script_dir/../../../../.." 2>/dev/null && pwd -P) || exit 64

if [ "$#" -eq 0 ]; then
  readonly expected_probe_sha='878ab27771fd7a660ba9f3997427b9ef92573bd524cad43bb89aded354d6d118'
  readonly expected_archive_sha='0061f5b19afd6a7db57ea5cf2d8bed73b4aa0f92167c1f5e52326c59abe1587c'
  readonly remote_basename='mac2jb-ios-probe-baseline-878ab27771fd7a660ba9f3997427b9ef92573bd524cad43bb89aded354d6d118'
  probe="$repo_root/build/ipad-hardware/mac2jb-ios-probe-baseline"
elif [ "$#" -eq 1 ] && [ "$1" = 'diagnostic' ]; then
  readonly expected_probe_sha='87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'
  readonly expected_archive_sha='08d7c84491c0c7b399fa1b604aefe17f0c3480c78b3b68d89fac378d553953a0'
  readonly remote_basename='mac2jb-ios-probe-diagnostic-87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'
  probe="$repo_root/build/ipad-hardware/mac2jb-ios-probe-diagnostic"
else
  command printf '%s\n' 'Usage: stage-baseline-probe.sh [diagnostic]' >&2
  exit 64
fi
readonly remote_probe="/var/mobile/Documents/$remote_basename"
for source_file in "$probe" "$identity_file" "$known_hosts_file"; do
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    command printf '%s\n' 'A required source is missing, non-regular, or a symbolic link. Nothing was sent.' >&2
    exit 65
  fi
done

current_uid=$(/usr/bin/id -u) || exit 70
for credential in "$identity_file" "$known_hosts_file"; do
  credential_uid=$(/usr/bin/stat -f '%u' "$credential" 2>/dev/null) || exit 66
  if [ "$credential_uid" != "$current_uid" ]; then
    command printf '%s\n' 'An SSH credential file has the wrong owner. Nothing was sent.' >&2
    exit 66
  fi
done
identity_mode=$(/usr/bin/stat -f '%Lp' "$identity_file" 2>/dev/null) || exit 66
known_hosts_mode=$(/usr/bin/stat -f '%Lp' "$known_hosts_file" 2>/dev/null) || exit 66
case "$identity_mode" in 400|600) ;; *) exit 66 ;; esac
case "$known_hosts_mode" in 400|440|444|600|640|644) ;; *) exit 66 ;; esac

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-stage-probe.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-stage-probe.*) ;; *) exit 70 ;; esac
feeder_pid=''
cleanup() {
  if [ -n "$feeder_pid" ]; then
    /bin/kill "$feeder_pid" 2>/dev/null
    wait "$feeder_pid" 2>/dev/null
  fi
  /bin/rm -f "$temp_dir/probe" "$temp_dir/identity" "$temp_dir/known_hosts" \
    "$temp_dir/roundtrip" "$temp_dir/transfer-stdout" "$temp_dir/expected-stdout" \
    "$temp_dir/probe.tar" "$temp_dir/archive-listing" "$temp_dir/expected-listing" \
    "$temp_dir/archive-feed" "$temp_dir/archive-root/$remote_basename" \
    "$temp_dir/audit-root/$remote_basename" 2>/dev/null
  /bin/rmdir "$temp_dir/archive-root" "$temp_dir/audit-root" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

staged_probe="$temp_dir/probe"
staged_identity="$temp_dir/identity"
staged_known_hosts="$temp_dir/known_hosts"
roundtrip="$temp_dir/roundtrip"
transfer_stdout="$temp_dir/transfer-stdout"
expected_stdout="$temp_dir/expected-stdout"
archive_file="$temp_dir/probe.tar"
archive_listing="$temp_dir/archive-listing"
expected_listing="$temp_dir/expected-listing"
archive_fifo="$temp_dir/archive-feed"
archive_root="$temp_dir/archive-root"
archive_member="$archive_root/$remote_basename"
audit_root="$temp_dir/audit-root"
audit_member="$audit_root/$remote_basename"

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

/bin/cp "$probe" "$staged_probe" || exit 70
/bin/cp "$identity_file" "$staged_identity" || exit 70
/bin/cp "$known_hosts_file" "$staged_known_hosts" || exit 70
/bin/chmod 500 "$staged_probe" || exit 70
/bin/chmod 400 "$staged_identity" "$staged_known_hosts" || exit 70

probe_sha=$(sha256_file "$staged_probe") || exit 65
identity_sha=$(sha256_file "$staged_identity") || exit 65
known_hosts_sha=$(sha256_file "$staged_known_hosts") || exit 65
if [ "$probe_sha" != "$expected_probe_sha" ] ||
   [ "$identity_sha" != "$expected_identity_sha" ] ||
   [ "$known_hosts_sha" != "$expected_known_hosts_sha" ]; then
  command printf '%s\n' 'A staged digest differs from its reviewed value. Nothing was sent.' >&2
  exit 65
fi

/bin/mkdir "$archive_root" "$audit_root" || exit 70
/bin/chmod 700 "$archive_root" "$audit_root" || exit 70
/usr/bin/mkfifo "$archive_fifo" || exit 70
/bin/chmod 600 "$archive_fifo" || exit 70
/bin/cp "$staged_probe" "$archive_member" || exit 70
/bin/chmod 500 "$archive_member" || exit 70
/usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C TZ=UTC \
  /usr/bin/touch -t 202001010000.00 "$archive_member" || exit 70
(
  umask 077
  exec /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C COPYFILE_DISABLE=1 \
    /usr/bin/tar \
    --create --file "$archive_file" --format ustar \
    --uid 0 --gid 0 --uname root --gname root \
    --no-xattrs --no-acls --no-fflags \
    --directory "$archive_root" "$remote_basename"
) || exit 70
/bin/chmod 400 "$archive_file" || exit 70
if [ ! -f "$archive_file" ] || [ -L "$archive_file" ]; then exit 65; fi
archive_sha=$(sha256_file "$archive_file") || exit 65
if [ "$archive_sha" != "$expected_archive_sha" ]; then
  command printf '%s\n' 'The local archive digest differs from the reviewed bytes. Nothing was sent.' >&2
  exit 65
fi
/usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C COPYFILE_DISABLE=1 \
  /usr/bin/tar --list --file "$archive_file" > "$archive_listing" 2>/dev/null || exit 65
command printf '%s\n' "$remote_basename" > "$expected_listing"
if ! /usr/bin/cmp -s "$archive_listing" "$expected_listing"; then
  command printf '%s\n' 'The local archive does not contain exactly the approved member. Nothing was sent.' >&2
  exit 65
fi
(
  umask 077
  exec /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C COPYFILE_DISABLE=1 \
    /usr/bin/tar \
    --extract --file "$archive_file" --directory "$audit_root" \
    --keep-old-files --no-same-owner --no-same-permissions \
    --no-xattrs --no-acls --no-fflags
) >/dev/null 2>&1 || exit 65
if [ ! -f "$audit_member" ] || [ -L "$audit_member" ]; then exit 65; fi
audit_mode=$(/usr/bin/stat -f '%Lp' "$audit_member" 2>/dev/null) || exit 65
audit_sha=$(sha256_file "$audit_member") || exit 65
if [ "$audit_mode" != '500' ] || [ "$audit_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'The locally extracted archive member failed mode or digest validation. Nothing was sent.' >&2
  exit 65
fi
archive_sha=$(sha256_file "$archive_file") || exit 65
if [ "$archive_sha" != "$expected_archive_sha" ]; then
  command printf '%s\n' 'The local archive changed during semantic validation. Nothing was sent.' >&2
  exit 65
fi

ssh_common() {
  /usr/bin/ssh \
    -F /dev/null -T -p "$ssh_port" -i "$staged_identity" \
    -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$staged_known_hosts" \
    -o GlobalKnownHostsFile=/dev/null -o KnownHostsCommand=none -o UpdateHostKeys=no \
    -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no \
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes \
    -o RequestTTY=no -o ControlMaster=no -o ControlPath=none \
    -o ConnectTimeout=10 -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=0 \
    -o LogLevel=ERROR "$ssh_user@$ssh_host" "$1"
}

remote_stage_command="exec 2>&-; set +euxv; env_path=; for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ -x \"\$candidate\" ]; then env_path=\$candidate; break; fi; done; tar_path=; for candidate in /var/jb/usr/bin/bsdtar /var/jb/usr/bin/tar /var/jb/bin/tar /usr/bin/tar /bin/tar; do if [ -x \"\$candidate\" ]; then tar_path=\$candidate; break; fi; done; if [ -z \"\$env_path\" ] || [ -z \"\$tar_path\" ]; then exit 127; fi; if [ -L /var/mobile/Documents ] || [ ! -d /var/mobile/Documents ]; then exit 65; fi; tar_version=\$(\"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C \"\$tar_path\" --version 2>&-); case \"\$tar_version\" in *GNU*tar*) ;; *) exit 65 ;; esac; umask 077; \"\$env_path\" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C \"\$tar_path\" --extract --file - --directory /var/mobile/Documents --keep-old-files --no-same-owner --no-same-permissions >/dev/null || exit 74; if [ -L '$remote_probe' ] || [ ! -f '$remote_probe' ] || [ ! -r '$remote_probe' ] || [ -w '$remote_probe' ] || [ ! -x '$remote_probe' ]; then exit 65; fi; command printf '%s\n' 'STAGED $expected_probe_sha $remote_probe'"
archive_feeder_code='import hashlib
import os
import stat
import sys

path, expected = sys.argv[1:]
archive_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
archive_status = os.fstat(archive_fd)
if not stat.S_ISREG(archive_status.st_mode) or archive_status.st_nlink != 1 or stat.S_IMODE(archive_status.st_mode) != 0o400:
    raise SystemExit(65)
data = bytearray()
while True:
    chunk = os.read(archive_fd, 65536)
    if not chunk:
        break
    data.extend(chunk)
    if len(data) > 1048576:
        raise SystemExit(65)
os.close(archive_fd)
if hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit(65)
view = memoryview(data)
while view:
    written = os.write(1, view)
    if written <= 0:
        raise SystemExit(74)
    view = view[written:]'
command printf 'STAGED %s %s\n' "$expected_probe_sha" "$remote_probe" > "$expected_stdout"
/usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' LC_ALL=C \
  /usr/bin/python3 -I -S -c "$archive_feeder_code" "$archive_file" "$expected_archive_sha" \
  > "$archive_fifo" 2>/dev/null &
feeder_pid=$!
(
  ulimit -f 2 2>/dev/null || exit 70
  ssh_common "$remote_stage_command"
) < "$archive_fifo" > "$transfer_stdout" 2>/dev/null
transfer_status=$?
/bin/kill -0 "$feeder_pid" 2>/dev/null
feeder_running=$?
if [ "$feeder_running" -eq 0 ] && [ "$transfer_status" -ne 0 ]; then /bin/kill "$feeder_pid" 2>/dev/null; fi
wait "$feeder_pid"
feeder_status=$?
feeder_pid=''
if [ "$transfer_status" -ne 0 ] || [ "$feeder_status" -ne 0 ] || ! /usr/bin/cmp -s "$transfer_stdout" "$expected_stdout"; then
  command printf '%s\n' 'Probe transfer failed or emitted unexpected output; a remote file may remain and must not be executed.' >&2
  exit 74
fi

(
  ulimit -f 2048 2>/dev/null || exit 70
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
    -o LogLevel=ERROR "$ssh_user@$ssh_host:$remote_probe" "$roundtrip" 2>/dev/null
) || exit 74

roundtrip_sha=$(sha256_file "$roundtrip") || exit 65
if [ "$roundtrip_sha" != "$expected_probe_sha" ]; then
  command printf '%s\n' 'Round-trip digest mismatch; the remote file must not be executed.' >&2
  exit 65
fi

command printf 'STAGED %s %s\n' "$expected_probe_sha" "$remote_probe"
