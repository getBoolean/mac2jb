#!/bin/sh
# Read-only U1 payload that streams app Info.plists as a tar archive.
#
# What this code does:
# 1. Selects fixed, regular, non-symlink, readable, executable, and
#    non-mobile-writable tar, timeout, and sleep binaries from absolute-path
#    allowlists. A harmless sleep canary must prove the timeout behavior first.
# 2. Enumerates only regular, non-symlink, readable `Info.plist` files from
#    `Dopamine*.app` and `TrollStore*.app` candidates beneath the three fixed
#    iOS application roots. It rejects symlinked app/container parents and stops
#    above eight files. Each accepted absolute pathname is converted only by
#    removing its leading slash.
# 3. Changes tar's process-local working directory to `/` and creates one ustar
#    stream from those root-relative paths with recursion disabled. The tar is
#    device-timeout bounded to twelve seconds with a one-second forced-kill
#    window. It creates no archive or other file on the iPad; the separately
#    reviewed host runner size-caps the stream, validates every member, parses
#    plists locally, and deletes the private local archive before exit.
#
# This payload does not install, launch, edit, create, rename, or delete anything
# on the iPad. Reading files may affect access metadata, and SSH/tar processes may
# create ordinary logs or transient state.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then
  exit 64
fi

tar_path=
for candidate in \
  /var/jb/usr/bin/bsdtar \
  /var/jb/usr/bin/tar \
  /var/jb/bin/tar \
  /usr/bin/tar \
  /bin/tar
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    tar_path=$candidate
    break
  fi
done
if [ -z "$tar_path" ]; then
  exit 66
fi

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
if [ -z "$timeout_path" ] || [ -z "$sleep_path" ]; then
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
plist_count=0
for plist in \
  /var/containers/Bundle/Application/*/Dopamine*.app/Info.plist \
  /var/containers/Bundle/Application/*/TrollStore*.app/Info.plist \
  /Applications/Dopamine*.app/Info.plist \
  /Applications/TrollStore*.app/Info.plist \
  /var/jb/Applications/Dopamine*.app/Info.plist \
  /var/jb/Applications/TrollStore*.app/Info.plist
do
  if [ ! -f "$plist" ] || [ -L "$plist" ] || [ ! -r "$plist" ]; then
    continue
  fi
  app_directory=${plist%/Info.plist}
  container_directory=${app_directory%/*}
  if [ -L "$app_directory" ] || [ -L "$container_directory" ]; then
    continue
  fi
  plist_count=$((plist_count + 1))
  if [ "$plist_count" -gt 8 ]; then
    exit 65
  fi
  relative_plist=${plist#/}
  set -- "$@" "$relative_plist"
done

if [ "$plist_count" -eq 0 ]; then
  exec "$timeout_path" -k 1 12 "$tar_path" \
    --create --file - --format=ustar -C / --files-from /dev/null
fi
exec "$timeout_path" -k 1 12 "$tar_path" \
  --create --file - --format=ustar --no-recursion -C / -- "$@"
