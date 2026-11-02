#!/bin/sh
# Establish a new local SSH host-key pin from the physically bound USB target.
#
# This is a trust-anchor recovery path for when the previous /tmp known-hosts
# bytes cannot be reconstructed from the target's current public keys. It is not
# a network trust-on-first-use flow: the exact prerequisite is the separately
# reviewed iproxy process pinned by UDID to the single physically connected USB
# device and bound only to 127.0.0.1:2222.
#
# What this script does:
# 1. Accepts no arguments, refuses any existing destination, and verifies fixed
#    Apple ssh-keyscan/Python binaries plus two privately staged helpers.
# 2. Performs one five-second-bounded, pre-authentication Ed25519 host-key
#    handshake through that USB tunnel. It opens no SSH session and runs no iPad
#    command.
# 3. Canonicalizes only the fixed localhost Ed25519 record. Raw keys and tool
#    diagnostics never reach stdout or stderr.
# 4. Hashes the canonical private candidate and publishes it with exact-path,
#    atomic, no-replace link(2). A raced file, symlink, or directory is rejected.
# 5. Reconciles handled signals or a helper failure after linking only when the
#    destination is current-UID, mode 0600, regular, non-symlink, and has the
#    exact candidate digest from this invocation.
#
# The only lasting change is /tmp/mac2jb-ipad-known-hosts on the Mac. No iPad
# file or SSH/USB configuration is changed. Normal pre-authentication logs,
# process accounting, access metadata, caches, and transient transport activity
# may occur. Review applies only to these bytes and the exact clean-environment
# invocation recorded with the hardware-feasibility evidence.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly ssh_keyscan='/usr/bin/ssh-keyscan'
readonly python='/usr/bin/python3'
readonly expected_ssh_keyscan_sha='05aa5eeca64dd2e610932b08accd02f905417972b583e0b5af2e46cd574eb093'
readonly expected_python_sha='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
readonly expected_link_helper_sha='acdf79bab678a6da4e1a74281be75cc31ee795f79ce31c1b7e6c495711511a47'
readonly expected_canonical_helper_sha='87f444b61b9a352ade308e7d88ce24d63546d5cbf8e2dea7d47f693e07fe8e99'
readonly destination='/tmp/mac2jb-ipad-known-hosts'

sha256_file() {
  if [ "$#" -ne 1 ]; then
    return 1
  fi
  digest_line=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
    /usr/bin/shasum -a 256 "$1" 2>/dev/null) || return 1
  digest_value=${digest_line%% *}
  if [ "${#digest_value}" -ne 64 ]; then
    return 1
  fi
  case "$digest_value" in
    *[!0123456789abcdef]*) return 1 ;;
  esac
  command printf '%s\n' "$digest_value"
}

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: pin-current-usb-ssh-host.sh' >&2
  exit 64
fi
script_dir=$(
  {
    parent_dir=$(/usr/bin/dirname "$0" 2>/dev/null) || exit 1
    CDPATH= cd -P "$parent_dir" || exit 1
    pwd -P
  } 2>/dev/null
) || exit 65
link_helper_source="$script_dir/exact-link-no-replace.py"
canonical_helper_source="$script_dir/canonicalize-usb-known-hosts.py"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  command printf '%s\n' 'Pinned known-hosts destination already exists; nothing was changed.' >&2
  exit 65
fi
if [ ! -f "$ssh_keyscan" ] || [ -L "$ssh_keyscan" ] || [ -w "$ssh_keyscan" ] ||
   [ ! -f "$python" ] || [ -L "$python" ] || [ -w "$python" ] ||
   [ ! -f "$link_helper_source" ] || [ -L "$link_helper_source" ] ||
   [ ! -f "$canonical_helper_source" ] || [ -L "$canonical_helper_source" ]; then
  command printf '%s\n' 'A fixed USB host-pin tool failed its path check.' >&2
  exit 65
fi
actual_scanner_sha=$(sha256_file "$ssh_keyscan") || exit 65
actual_python_sha=$(sha256_file "$python") || exit 65
if [ "$actual_scanner_sha" != "$expected_ssh_keyscan_sha" ] ||
   [ "$actual_python_sha" != "$expected_python_sha" ]; then
  command printf '%s\n' 'A fixed USB host-pin tool digest changed.' >&2
  exit 65
fi
current_uid=$(/usr/bin/id -u 2>/dev/null) || exit 65

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-current-usb-host-pin.XXXXXX 2>/dev/null) || exit 70
case "$temp_dir" in
  /tmp/mac2jb-current-usb-host-pin.*) ;;
  *) exit 70 ;;
esac
capture="$temp_dir/keyscan-capture"
candidate="$temp_dir/known-hosts"
link_helper="$temp_dir/exact-link-no-replace.py"
canonical_helper="$temp_dir/canonicalize-usb-known-hosts.py"
committed_sha=''

cleanup() {
  /bin/rm -f "$capture" "$candidate" "$link_helper" "$canonical_helper" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null || :
}
published_pin_is_valid() {
  case "$committed_sha" in
    ''|*[!0123456789abcdef]*) return 1 ;;
  esac
  [ "${#committed_sha}" -eq 64 ] || return 1
  [ -f "$destination" ] || return 1
  [ ! -L "$destination" ] || return 1
  published_mode=$(/usr/bin/stat -f '%Lp' "$destination" 2>/dev/null) || return 1
  published_uid=$(/usr/bin/stat -f '%u' "$destination" 2>/dev/null) || return 1
  [ "$published_mode" = 600 ] || return 1
  [ "$published_uid" = "$current_uid" ] || return 1
  published_sha=$(sha256_file "$destination") || return 1
  [ "$published_sha" = "$committed_sha" ]
}
on_signal() {
  signal_status=$1
  trap - EXIT
  trap '' HUP INT TERM
  if published_pin_is_valid; then
    cleanup
    exit 0
  fi
  cleanup
  exit "$signal_status"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

/bin/cp "$link_helper_source" "$link_helper" 2>/dev/null || exit 70
/bin/cp "$canonical_helper_source" "$canonical_helper" 2>/dev/null || exit 70
/bin/chmod 500 "$link_helper" "$canonical_helper" 2>/dev/null || exit 70
actual_link_helper_sha=$(sha256_file "$link_helper") || exit 65
actual_canonical_helper_sha=$(sha256_file "$canonical_helper") || exit 65
if [ "$actual_link_helper_sha" != "$expected_link_helper_sha" ] ||
   [ "$actual_canonical_helper_sha" != "$expected_canonical_helper_sha" ]; then
  command printf '%s\n' 'A USB host-pin helper digest changed.' >&2
  exit 65
fi

if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$ssh_keyscan" -T 5 -p 2222 -t ed25519 127.0.0.1 2>/dev/null >"$capture"; then
  command printf '%s\n' 'The bounded USB host-key handshake failed; no pin was created.' >&2
  exit 66
fi
capture_size=$(/usr/bin/stat -f '%z' "$capture" 2>/dev/null) || exit 66
if [ "$capture_size" -lt 1 ] || [ "$capture_size" -gt 16384 ]; then
  command printf '%s\n' 'The captured USB host-key set had an invalid size; no pin was created.' >&2
  exit 66
fi
if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$python" -I -S -B "$canonical_helper" "$capture" "$candidate" 2>/dev/null; then
  command printf '%s\n' 'The USB host-key set failed strict canonicalization.' >&2
  exit 66
fi
candidate_size=$(/usr/bin/stat -f '%z' "$candidate" 2>/dev/null) || exit 66
if [ "$candidate_size" -lt 1 ] || [ "$candidate_size" -gt 16384 ]; then
  command printf '%s\n' 'The canonical USB host-key pin had an invalid size.' >&2
  exit 66
fi
candidate_sha=$(sha256_file "$candidate") || exit 66
committed_sha=$candidate_sha
/bin/chmod 600 "$candidate" 2>/dev/null || exit 70
if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$python" -I -S -B "$link_helper" "$candidate" "$destination" 2>/dev/null; then
  if published_pin_is_valid; then
    cleanup
    exit 0
  fi
  command printf '%s\n' 'No-replace USB host-pin publication failed.' >&2
  exit 70
fi
cleanup
exit 0
