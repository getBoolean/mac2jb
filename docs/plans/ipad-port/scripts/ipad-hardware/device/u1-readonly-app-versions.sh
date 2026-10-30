#!/bin/sh
# Read-only U1 payload for exact Dopamine and TrollStore app versions.
#
# What this code does:
# 1. Selects one fixed, non-writable `plutil` executable from an absolute-path
#    allowlist. It never invokes a package manager, app launcher, or database.
# 2. Reads only `Info.plist` files beneath the three fixed iOS application roots.
#    Shell globs enumerate bundles; no identifier, path, name, serial, or UDID is
#    printed. A 512-file ceiling stops an unexpectedly large traversal.
# 3. Accepts only the official Dopamine bundle ID and the standard or stealth
#    TrollStore ID family, then requires string-typed version/build values with
#    `plutil -extract ... raw -expect string -n -o -` (stdout only). A sentinel
#    preserves embedded or trailing newlines for the sanitizer to reject.
# 4. Emits exactly two sanitized ASCII lines after the complete scan. Duplicate,
#    malformed, or unsafe matching metadata makes the payload fail before output.
#
# The payload does not create, edit, rename, delete, launch, install, or transfer
# anything on the iPad. SSH authentication/process/accounting logs and file-access
# metadata remain possible incidental effects of the separately reviewed runner.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then
  exit 64
fi

plist_tool=
for candidate in /usr/bin/plutil /var/jb/usr/bin/plutil; do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    plist_tool=$candidate
    break
  fi
done
if [ -z "$plist_tool" ]; then
  exit 66
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

safe_value() {
  value=$1
  if [ -z "$value" ] || [ "${#value}" -gt 64 ]; then
    return 1
  fi
  case "$value" in
    [0-9A-Za-z]*[!0-9A-Za-z.+_\(\)\ -]*|[!0-9A-Za-z]*) return 1 ;;
    *) return 0 ;;
  esac
}

read_metadata() {
  metadata_plist=$1
  metadata_key=$2
  metadata_capture=$(
    "$plist_tool" -extract "$metadata_key" raw -expect string -n -o - -- \
      "$metadata_plist" 2>/dev/null
    metadata_status=$?
    command printf '%s' '__MAC2JB_PLIST_VALUE_END__'
    exit "$metadata_status"
  ) || return 1
  case "$metadata_capture" in
    *__MAC2JB_PLIST_VALUE_END__)
      metadata_value=${metadata_capture%__MAC2JB_PLIST_VALUE_END__}
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

dopamine_count=0
dopamine_version=not-observed
dopamine_build=not-observed
trollstore_count=0
trollstore_version=not-observed
trollstore_build=not-observed
trollstore_family=standard
scanned_count=0

for plist in \
  /var/containers/Bundle/Application/*/*.app/Info.plist \
  /Applications/*.app/Info.plist \
  /var/jb/Applications/*.app/Info.plist
do
  if [ ! -f "$plist" ] || [ -L "$plist" ]; then
    continue
  fi
  app_directory=${plist%/Info.plist}
  container_directory=${app_directory%/*}
  if [ -L "$app_directory" ] || [ -L "$container_directory" ]; then
    continue
  fi
  scanned_count=$((scanned_count + 1))
  if [ "$scanned_count" -gt 512 ]; then
    exit 65
  fi

  if ! read_metadata "$plist" CFBundleIdentifier; then
    continue
  fi
  bundle_id=$metadata_value
  case "$bundle_id" in
    com.opa334.Dopamine)
      label=dopamine
      family=standard
      ;;
    com.opa334.TrollStore)
      label=trollstore
      family=standard
      ;;
    com.opa334.TrollStore.TS_*)
      label=trollstore
      family=stealth
      ;;
    *)
      continue
      ;;
  esac

  if ! read_metadata "$plist" CFBundleShortVersionString; then exit 65; fi
  version=$metadata_value
  if ! read_metadata "$plist" CFBundleVersion; then exit 65; fi
  build=$metadata_value
  if ! safe_value "$version"; then exit 65; fi
  if ! safe_value "$build"; then exit 65; fi

  case "$label" in
    dopamine)
      dopamine_count=$((dopamine_count + 1))
      dopamine_version=$version
      dopamine_build=$build
      ;;
    trollstore)
      trollstore_count=$((trollstore_count + 1))
      trollstore_version=$version
      trollstore_build=$build
      trollstore_family=$family
      ;;
  esac
done

if [ "$dopamine_count" -gt 1 ] || [ "$trollstore_count" -gt 1 ]; then
  exit 66
fi

if [ "$dopamine_count" -eq 0 ]; then
  command printf '%s\n' 'dopamine-app: not-observed'
else
  command printf 'dopamine-app: version=%s build=%s bundle-family=standard\n' \
    "$dopamine_version" "$dopamine_build"
fi
if [ "$trollstore_count" -eq 0 ]; then
  command printf '%s\n' 'trollstore-app: not-observed'
else
  command printf 'trollstore-app: version=%s build=%s bundle-family=%s\n' \
    "$trollstore_version" "$trollstore_build" "$trollstore_family"
fi
