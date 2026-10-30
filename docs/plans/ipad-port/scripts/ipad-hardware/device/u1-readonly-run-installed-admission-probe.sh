#!/bin/sh
# Read-only U1 launcher for one already-attested MAC2JB admission executable.
#
# What this code does:
# 1. Accepts only one of two fixed executable variants, one of two peer labels,
#    one USB-C orientation, one bounded operator-observed power label, and the
#    lowercase SHA-256 recorded by the successful post-install attestation.
# 2. Selects non-symlink, non-mobile-writable env/timeout/sleep tools from fixed
#    absolute paths and proves timeout status 124 with a harmless sleep canary.
# 3. Finds exactly one fixed-name installed admission app beneath the three reviewed
#    app roots. The app, immediate container, optional Probes directory, and
#    selected executable must be non-symlinks with the exact TrollStore-observed
#    owners and modes. It hashes the executable before and after launch and
#    requires both hashes to equal the attested signed-file SHA-256.
# 4. Runs the selected stdout-only probe once in a clean environment with fixed
#    target/build/peer/cable arguments and user-client types 0 and 123. A
#    twenty-second timeout plus one-second kill grace bounds execution.
#
# The launched probe enumerates registry state, resolves private symbols, reads
# controller metadata, and opens then immediately closes requested user clients.
# Its audited build has no report writer and never invokes a mutation operation.
# This launcher does not install, create, edit, rename, chmod, chown, or delete
# any iPad file. It emits only the probe's JSON stdout. Reads, process state,
# access metadata, and ordinary SSH/system logs may still occur.
#
# Security boundary: this launcher assumes the authenticated `mobile` account
# is honest and no concurrent same-UID process is replacing installed app paths.
# The pre/post hashes detect lasting replacement, not a swap-and-restore race
# between pathname hashing and kernel execution. Darwin provides no usable
# fexecve path here; a hostile same-UID process is outside this authorization.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 5 ]; then
  exit 64
fi

variant=$1
peer_kind=$2
orientation=$3
power_state=$4
expected_probe_sha=$5

case "$variant" in
  platform-only) executable_relative='mac2jb-u1-platform-only' ;;
  platform-setdescription) executable_relative='Probes/mac2jb-u1-platform-setdescription' ;;
  *) exit 64 ;;
esac
case "$peer_kind" in
  capture-host) peer_identity='mac2jb-generic-capture-host-primary' ;;
  switch) peer_identity='mac2jb-nintendo-switch-primary' ;;
  *) exit 64 ;;
esac
case "$orientation" in a|b) ;; *) exit 64 ;; esac
case "$power_state" in
  operator-observed-vbus-charging|operator-observed-vbus-not-charging|operator-observed-no-vbus|operator-not-observed) ;;
  *) exit 64 ;;
esac
case "$expected_probe_sha" in
  ''|*[!0-9a-f]*) exit 64 ;;
esac
if [ "${#expected_probe_sha}" -ne 64 ]; then
  exit 64
fi

env_path=
for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    env_path=$candidate
    break
  fi
done

timeout_path=
for candidate in \
  /var/jb/usr/bin/timeout \
  /var/jb/bin/timeout \
  /usr/bin/timeout \
  /bin/timeout \
  /var/jb/usr/bin/gtimeout \
  /var/jb/bin/gtimeout \
  /usr/bin/gtimeout \
  /bin/gtimeout
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    timeout_path=$candidate
    break
  fi
done

sleep_path=
for candidate in /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    sleep_path=$candidate
    break
  fi
done

stat_path=
# This target has rootless GNU stat; its -c formatter was checked against
# Python lstat on installed TrollStore apps. BSD stat -f does not work here.
for candidate in /var/jb/usr/bin/stat /var/jb/bin/stat
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    stat_path=$candidate
    break
  fi
done

sha256_path=
sha256_kind=
for candidate in \
  /var/jb/usr/bin/sha256sum \
  /var/jb/bin/sha256sum \
  /usr/bin/sha256sum \
  /bin/sha256sum
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    sha256_path=$candidate
    sha256_kind=sha256sum
    break
  fi
done
if [ -z "$sha256_path" ]; then
  for candidate in /usr/bin/shasum /bin/shasum /var/jb/usr/bin/shasum /var/jb/bin/shasum
  do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
      [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
      sha256_path=$candidate
      sha256_kind=shasum
      break
    fi
  done
fi

if [ -z "$env_path" ] || [ -z "$timeout_path" ] || [ -z "$sleep_path" ] ||
  [ -z "$stat_path" ] || [ -z "$sha256_path" ]; then
  exit 67
fi
"$timeout_path" -k 1 0.1 "$sleep_path" 1 </dev/null >/dev/null 2>&1
if [ "$?" -ne 124 ]; then
  exit 67
fi

for application_root in \
  /var/containers/Bundle/Application \
  /Applications \
  /var/jb/Applications
do
  if [ -d "$application_root" ] &&
    { [ ! -r "$application_root" ] || [ ! -x "$application_root" ]; }; then
    exit 66
  fi
done

set --
bundle_count=0
for app_directory in \
  /var/containers/Bundle/Application/*/Mac2JBU1-Admission.app \
  /Applications/Mac2JBU1-Admission.app \
  /var/jb/Applications/Mac2JBU1-Admission.app
do
  if [ ! -d "$app_directory" ]; then
    continue
  fi
  if [ -L "$app_directory" ] || [ ! -r "$app_directory" ] ||
    [ ! -x "$app_directory" ]; then
    exit 66
  fi
  container_directory=${app_directory%/*}
  if [ -L "$container_directory" ]; then
    exit 66
  fi
app_metadata=$("$stat_path" -c '%u:%g:%a' "$app_directory" 2>/dev/null) || exit 66
  if [ "$app_metadata" != '0:0:755' ]; then
    exit 66
  fi
  bundle_count=$((bundle_count + 1))
  if [ "$bundle_count" -gt 1 ]; then
    exit 65
  fi
  set -- "$app_directory"
done
if [ "$bundle_count" -ne 1 ]; then
  exit 68
fi

probe_path=$1/$executable_relative
probe_parent=${probe_path%/*}
if [ "$probe_parent" != "$1" ]; then
  if [ ! -d "$probe_parent" ] || [ -L "$probe_parent" ] ||
    [ ! -r "$probe_parent" ] || [ ! -x "$probe_parent" ]; then
    exit 66
  fi
  parent_metadata=$("$stat_path" -c '%u:%g:%a' "$probe_parent" 2>/dev/null) || exit 66
  if [ "$parent_metadata" != '33:33:755' ]; then
    exit 66
  fi
fi
if [ ! -f "$probe_path" ] || [ -L "$probe_path" ] ||
  [ ! -r "$probe_path" ] || [ ! -x "$probe_path" ]; then
  exit 66
fi
probe_metadata=$("$stat_path" -c '%u:%g:%a' "$probe_path" 2>/dev/null) || exit 66
if [ "$probe_metadata" != '33:33:755' ]; then
  exit 66
fi

hash_probe() {
  if [ "$sha256_kind" = sha256sum ]; then
    hash_output=$("$sha256_path" "$probe_path" 2>/dev/null) || return 1
  else
    hash_output=$("$sha256_path" -a 256 "$probe_path" 2>/dev/null) || return 1
  fi
  observed_sha=${hash_output%% *}
  hash_suffix=${hash_output#"$observed_sha"}
  case "$hash_suffix" in
    "  $probe_path"|" *$probe_path") ;;
    *) return 1 ;;
  esac
  case "$observed_sha" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#observed_sha}" -eq 64 ] || return 1
  command printf '%s\n' "$observed_sha"
}

before_sha=$(hash_probe) || exit 66
if [ "$before_sha" != "$expected_probe_sha" ]; then
  exit 66
fi

"$env_path" -i PATH="$PATH" LC_ALL=C \
  "$timeout_path" -k 1 20 "$probe_path" \
  --soc T8112 \
  --port-family thunderbolt-usb4 \
  --dopamine-build '3.0.12-1' \
  --trollstore-build '2.1.1' \
  --peer-kind "$peer_kind" \
  --peer-id "$peer_identity" \
  --cable-id 'mac2jb-known-good-usbc-cable-primary' \
  --orientation "$orientation" \
  --power-state "$power_state" \
  --client-type 0 \
  --client-type 123
probe_status=$?

after_sha=$(hash_probe) || exit 74
if [ "$after_sha" != "$expected_probe_sha" ]; then
  exit 74
fi
exit "$probe_status"
