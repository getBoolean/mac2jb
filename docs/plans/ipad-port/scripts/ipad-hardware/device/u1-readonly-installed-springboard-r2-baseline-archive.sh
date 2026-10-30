#!/bin/sh
# Read-only U1 payload that streams the installed SpringBoard R2 baseline bundle.
#
# What this code does:
# 1. Selects fixed, regular, non-symlink, readable, executable, and
#    non-mobile-writable tar, timeout, and sleep binaries from absolute-path
#    allowlists. A harmless sleep canary must prove timeout status 124 first.
# 2. Searches only three fixed application roots for the exact app-directory
#    name `Mac2JBU1-R2Baseline.app`. It requires exactly one readable, searchable,
#    non-symlink app and rejects a symlinked immediate container.
# 3. Runs rootless GNU tar from `/` with the one root-relative app path and
#    streams a ustar archive to stdout. Tar recursion captures unexpected files
#    and symlinks as evidence but does not dereference symlinks. A separately
#    reviewed host validator rejects anything outside the exact expected layout.
# 4. Bounds tar to twelve seconds plus a one-second forced-kill window. It does
#    not create a remote archive, temporary, report, output file, or directory.
#
# This payload does not install, launch, execute, edit, create, rename, chmod,
# chown, or delete any iPad file. Reads may affect access metadata; SSH, timeout,
# and tar can create ordinary logs and transient process state.

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
bundle_count=0
for app_directory in \
  /var/containers/Bundle/Application/*/Mac2JBU1-R2Baseline.app \
  /Applications/Mac2JBU1-R2Baseline.app \
  /var/jb/Applications/Mac2JBU1-R2Baseline.app
do
  if [ ! -d "$app_directory" ] || [ -L "$app_directory" ] ||
    [ ! -r "$app_directory" ] || [ ! -x "$app_directory" ]; then
    continue
  fi
  container_directory=${app_directory%/*}
  if [ -L "$container_directory" ]; then
    continue
  fi
  bundle_count=$((bundle_count + 1))
  if [ "$bundle_count" -gt 1 ]; then
    exit 65
  fi
  relative_app=${app_directory#/}
  set -- "$relative_app"
done

if [ "$bundle_count" -ne 1 ]; then
  exit 68
fi

exec "$timeout_path" -k 1 12 "$tar_path" \
  --create --file - --format=ustar -C / -- "$1"
