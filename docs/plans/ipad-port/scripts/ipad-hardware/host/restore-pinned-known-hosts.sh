#!/bin/sh
# Restore the previously reviewed localhost SSH host-key pin after /tmp loss.
#
# What this script does:
# 1. Accepts no arguments and refuses an existing destination of any kind.
# 2. Uses the fixed root-owned Apple ssh-keyscan binary only when its exact
#    SHA-256 digest matches the reviewed value below.
# 3. Performs five-second-bounded localhost SSH host-key handshakes through the
#    already reviewed USB tunnel, requesting ssh-keyscan's default key set. This
#    reproduces the original multi-key known-hosts capture rather than accepting
#    or repinning any new key.
# 4. Keeps all captured key bytes in one private temporary directory and emits
#    no raw key or diagnostic. A digest-pinned isolated helper accepts only the
#    fixed localhost records and reconstructs permutations of nonempty subsets;
#    it creates a candidate only when one exact byte sequence matches the prior
#    full-file digest. It cannot accept a changed key or hostname.
# 5. Runs a second digest-pinned helper under fixed Apple Python. The helper calls the
#    exact-path link(2) primitive, so a raced-in file, symlink, or directory can
#    never trigger command-line "target directory" behavior. It then verifies
#    source and destination are the same regular inode.
# 6. Removes only its fixed private temporary files and directory.
#
# This script does not authenticate, request an SSH session, or execute an iPad
# command. It cannot edit an iPad file or SSH/USB configuration. The handshake
# and transient processes can cause ordinary connection/accounting logs, access
# metadata, and cache activity. Review applies only to these exact bytes while
# the reviewed tunnel is pinned to the intended physical device.

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
readonly expected_reconstruct_helper_sha='0077d87c75650ba8e0e0afb1483c10e231c244da86f7fc355c99fa0af1383c11'
readonly destination='/tmp/mac2jb-ipad-known-hosts'
readonly expected_pin_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'

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
  command printf '%s\n' 'Usage: restore-pinned-known-hosts.sh' >&2
  exit 64
fi
script_dir=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" 2>/dev/null && pwd -P) || exit 65
link_helper_source="$script_dir/exact-link-no-replace.py"
reconstruct_helper_source="$script_dir/reconstruct-pinned-known-hosts.py"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  command printf '%s\n' 'Pinned known-hosts destination already exists; nothing was changed.' >&2
  exit 65
fi
if [ ! -f "$ssh_keyscan" ] || [ -L "$ssh_keyscan" ] || [ -w "$ssh_keyscan" ] ||
   [ ! -f "$python" ] || [ -L "$python" ] || [ -w "$python" ] ||
   [ ! -f "$link_helper_source" ] || [ -L "$link_helper_source" ] ||
   [ ! -f "$reconstruct_helper_source" ] || [ -L "$reconstruct_helper_source" ]; then
  command printf '%s\n' 'A fixed host-pin tool failed its path check.' >&2
  exit 65
fi
actual_scanner_sha=$(sha256_file "$ssh_keyscan") || exit 65
actual_python_sha=$(sha256_file "$python") || exit 65
if [ "$actual_scanner_sha" != "$expected_ssh_keyscan_sha" ] ||
   [ "$actual_python_sha" != "$expected_python_sha" ]; then
  command printf '%s\n' 'A fixed host-pin tool digest changed.' >&2
  exit 65
fi
current_uid=$(/usr/bin/id -u) || exit 65

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-ipad-host-pin.XXXXXX) || exit 70
case "$temp_dir" in
  /tmp/mac2jb-ipad-host-pin.*) ;;
  *) exit 70 ;;
esac
capture="$temp_dir/keyscan-capture"
candidate="$temp_dir/known-hosts"
link_helper="$temp_dir/exact-link-no-replace.py"
reconstruct_helper="$temp_dir/reconstruct-pinned-known-hosts.py"

cleanup() {
  /bin/rm -f "$capture" "$candidate" "$link_helper" "$reconstruct_helper"
  /bin/rmdir "$temp_dir" 2>/dev/null || :
}
published_pin_is_valid() {
  [ -f "$destination" ] || return 1
  [ ! -L "$destination" ] || return 1
  published_mode=$(/usr/bin/stat -f '%Lp' "$destination" 2>/dev/null) || return 1
  published_uid=$(/usr/bin/stat -f '%u' "$destination" 2>/dev/null) || return 1
  [ "$published_mode" = 600 ] || return 1
  [ "$published_uid" = "$current_uid" ] || return 1
  published_sha=$(sha256_file "$destination") || return 1
  [ "$published_sha" = "$expected_pin_sha" ]
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

/bin/cp "$link_helper_source" "$link_helper" || exit 70
/bin/cp "$reconstruct_helper_source" "$reconstruct_helper" || exit 70
/bin/chmod 500 "$link_helper" "$reconstruct_helper" || exit 70
actual_link_helper_sha=$(sha256_file "$link_helper") || exit 65
actual_reconstruct_helper_sha=$(sha256_file "$reconstruct_helper") || exit 65
if [ "$actual_link_helper_sha" != "$expected_link_helper_sha" ] ||
   [ "$actual_reconstruct_helper_sha" != "$expected_reconstruct_helper_sha" ]; then
  command printf '%s\n' 'A host-pin helper digest changed.' >&2
  exit 65
fi

if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$ssh_keyscan" -T 5 -p 2222 127.0.0.1 >"$capture" 2>/dev/null; then
  command printf '%s\n' 'The bounded host-key handshake failed; no pin was restored.' >&2
  exit 66
fi
capture_size=$(/usr/bin/stat -f '%z' "$capture" 2>/dev/null) || exit 66
if [ "$capture_size" -lt 1 ] || [ "$capture_size" -gt 16384 ]; then
  command printf '%s\n' 'The captured host-key record had an invalid size; no pin was restored.' >&2
  exit 66
fi
if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$python" -I -S -B "$reconstruct_helper" "$capture" "$candidate" "$expected_pin_sha"; then
  command printf '%s\n' 'No current host-key ordering or subset matched the prior pin.' >&2
  exit 66
fi
candidate_size=$(/usr/bin/stat -f '%z' "$candidate" 2>/dev/null) || exit 66
if [ "$candidate_size" -lt 1 ] || [ "$candidate_size" -gt 16384 ]; then
  command printf '%s\n' 'The reconstructed host-key pin had an invalid size.' >&2
  exit 66
fi
candidate_sha=$(sha256_file "$candidate") || exit 66
if [ "$candidate_sha" != "$expected_pin_sha" ]; then
  command printf '%s\n' 'The captured host-key record did not match the prior pin; no pin was restored.' >&2
  exit 66
fi
/bin/chmod 600 "$candidate" || exit 70
if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$python" -I -S -B "$link_helper" "$candidate" "$destination"; then
  if published_pin_is_valid; then
    cleanup
    exit 0
  fi
  command printf '%s\n' 'No-replace host-pin publication failed.' >&2
  exit 70
fi
# The successful hard link is the commit point: it names the same private inode
# whose complete bytes were already verified above. From here, cleanup is
# idempotent and every handled signal treats that exact valid pin as success.
cleanup
exit 0
