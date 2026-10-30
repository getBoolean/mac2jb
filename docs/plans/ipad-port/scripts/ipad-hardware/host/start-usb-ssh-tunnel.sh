#!/bin/sh
# Start the local USB-to-SSH transport used by the reviewed iPad probes.
#
# What this script does:
# 1. Accepts no arguments and uses fixed, non-writable Homebrew binaries whose
#    SHA-256 digests are pinned below.
# 2. Asks usbmuxd for the USB-device list, validates one bounded identifier in
#    memory, and proceeds only when exactly one USB device is attached. It never
#    prints or writes that identifier.
# 3. Refuses to disturb an existing listener on localhost TCP port 2222.
# 4. Runs iproxy in the foreground, bound only to 127.0.0.1, forwarding local
#    port 2222 to port 22 on that one USB device. Potentially identifying iproxy
#    diagnostics are discarded rather than retained or emitted.
#
# Device effects are limited to transient usbmux/USB transport activity. This
# script runs no remote shell or iPad command, changes no SSH/USB configuration,
# and creates, edits, or removes no iPad file. The tunnel ends when this process
# exits. Normal host/device transport logs and transient cache activity may still
# occur. Review and authorization apply only to these exact bytes and invocation.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

readonly idevice_id='/opt/homebrew/Cellar/libimobiledevice/1.4.0/bin/idevice_id'
readonly iproxy='/opt/homebrew/Cellar/libusbmuxd/2.1.1/bin/iproxy'
readonly idevice_id_sha='c92ca2658642568b49533eee9b88f92ec04812509397b51876446a08a35a5636'
readonly iproxy_sha='ef91b0b2cd8964be4216aa4b5b859955f015337d95a1202d16b75489e4f9d230'

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: start-usb-ssh-tunnel.sh' >&2
  exit 64
fi

for tool in "$idevice_id" "$iproxy"; do
  if [ ! -f "$tool" ] || [ -L "$tool" ] || [ -w "$tool" ]; then
    command printf '%s\n' 'A required transport tool failed its fixed-path check.' >&2
    exit 65
  fi
done

actual_idevice_id_sha=$(/usr/bin/shasum -a 256 "$idevice_id" 2>/dev/null | /usr/bin/awk 'NR == 1 { print $1 }') || exit 65
actual_iproxy_sha=$(/usr/bin/shasum -a 256 "$iproxy" 2>/dev/null | /usr/bin/awk 'NR == 1 { print $1 }') || exit 65
if [ "$actual_idevice_id_sha" != "$idevice_id_sha" ] || [ "$actual_iproxy_sha" != "$iproxy_sha" ]; then
  command printf '%s\n' 'A required transport tool digest changed.' >&2
  exit 65
fi

device_record=$("$idevice_id" -l 2>/dev/null) || exit 66
device_count=$(command printf '%s\n' "$device_record" | /usr/bin/awk 'NF { count++ } END { print count + 0 }') || exit 66
device_bytes=$(command printf '%s' "$device_record" | /usr/bin/wc -c | /usr/bin/tr -d ' ') || exit 66
if [ "$device_count" != 1 ] || [ "$device_bytes" -lt 1 ] || [ "$device_bytes" -gt 80 ]; then
  command printf '%s\n' 'Exactly one USB device is required; no tunnel was started.' >&2
  exit 66
fi
case "$device_record" in
  *[!0123456789abcdefABCDEF-]*)
    command printf '%s\n' 'The USB-device identifier has an unexpected form; no tunnel was started.' >&2
    exit 66
    ;;
esac

if /usr/sbin/lsof -nP -iTCP:2222 -sTCP:LISTEN >/dev/null 2>&1; then
  command printf '%s\n' 'Local TCP port 2222 already has a listener; nothing was changed.' >&2
  exit 67
fi

exec "$iproxy" -l -u "$device_record" -s 127.0.0.1 2222:22 >/dev/null 2>&1
