#!/bin/sh
# Redacted classifier for the current Ed25519 host-key scan over pinned USB.
#
# The exact prerequisite is the separately reviewed iproxy process pinned by
# identifier to the sole physically connected target and bound to loopback port
# 2222. This script performs one five-second-bounded, pre-authentication Ed25519
# handshake. It does not authenticate, open a session, or run an iPad command.
#
# The private capture is passed to a staged digest-pinned isolated classifier.
# Only nine fixed categorical lines may be emitted: record count, newline/CR/NUL
# state, field shape, host form, algorithm form, and Base64 shape. The public key
# bytes, host key fingerprint, paths, identifiers, and diagnostics are never
# emitted or retained. All temporary files are removed on handled paths.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly ssh_keyscan='/usr/bin/ssh-keyscan'
readonly python='/usr/bin/python3'
readonly expected_ssh_keyscan_sha='05aa5eeca64dd2e610932b08accd02f905417972b583e0b5af2e46cd574eb093'
readonly expected_python_sha='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
readonly expected_classifier_sha='27ad1a08cff30e33b18e58f504d666557c0f972e17d0df314ff5adbb4406dc0e'

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
  command printf '%s\n' 'Usage: classify-current-usb-ssh-host.sh' >&2
  exit 64
fi
script_dir=$(
  {
    parent_dir=$(/usr/bin/dirname "$0" 2>/dev/null) || exit 1
    CDPATH= cd -P "$parent_dir" || exit 1
    pwd -P
  } 2>/dev/null
) || exit 65
classifier_source="$script_dir/classify-usb-known-hosts.py"
if [ ! -f "$ssh_keyscan" ] || [ -L "$ssh_keyscan" ] || [ -w "$ssh_keyscan" ] ||
   [ ! -f "$python" ] || [ -L "$python" ] || [ -w "$python" ] ||
   [ ! -f "$classifier_source" ] || [ -L "$classifier_source" ]; then
  command printf '%s\n' 'A fixed USB host-key classifier tool failed its path check.' >&2
  exit 65
fi
actual_scanner_sha=$(sha256_file "$ssh_keyscan") || exit 65
actual_python_sha=$(sha256_file "$python") || exit 65
if [ "$actual_scanner_sha" != "$expected_ssh_keyscan_sha" ] ||
   [ "$actual_python_sha" != "$expected_python_sha" ]; then
  command printf '%s\n' 'A fixed USB host-key classifier tool digest changed.' >&2
  exit 65
fi

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-usb-host-classify.XXXXXX 2>/dev/null) || exit 70
case "$temp_dir" in
  /tmp/mac2jb-usb-host-classify.*) ;;
  *) exit 70 ;;
esac
capture="$temp_dir/keyscan-capture"
classifier="$temp_dir/classify-usb-known-hosts.py"

cleanup() {
  /bin/rm -f "$capture" "$classifier" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null || :
}
on_signal() {
  signal_status=$1
  trap - EXIT
  trap '' HUP INT TERM
  cleanup
  exit "$signal_status"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

/bin/cp "$classifier_source" "$classifier" 2>/dev/null || exit 70
/bin/chmod 500 "$classifier" 2>/dev/null || exit 70
actual_classifier_sha=$(sha256_file "$classifier") || exit 65
if [ "$actual_classifier_sha" != "$expected_classifier_sha" ]; then
  command printf '%s\n' 'The USB host-key classifier digest changed.' >&2
  exit 65
fi

if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$ssh_keyscan" -T 5 -p 2222 -t ed25519 127.0.0.1 2>/dev/null >"$capture"; then
  command printf '%s\n' 'The bounded USB host-key handshake failed.' >&2
  exit 66
fi
capture_size=$(/usr/bin/stat -f '%z' "$capture" 2>/dev/null) || exit 66
if [ "$capture_size" -lt 1 ] || [ "$capture_size" -gt 16384 ]; then
  command printf '%s\n' 'The captured USB host-key set had an invalid size.' >&2
  exit 66
fi
if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR=/tmp \
  "$python" -I -S -B "$classifier" "$capture" 2>/dev/null; then
  command printf '%s\n' 'The USB host-key classifier failed.' >&2
  exit 66
fi
cleanup
exit 0
