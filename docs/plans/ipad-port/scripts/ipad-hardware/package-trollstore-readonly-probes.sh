#!/bin/bash
set -euo pipefail
umask 022

# Purpose
# -------
# Package the four already-built MAC2JB_STDOUT_ONLY iOS probe variants as
# deterministic TrollStore .tipa archives, plus one toolbox archive containing
# all four exact executables. The toolbox reduces later device installation to
# one owner-approved action. This script runs only on the Mac: it does not
# connect to, install on, launch on, or otherwise modify an iPad.
#
# Safety properties
# -----------------
# 1. The source binaries are re-audited before packaging. That audit requires
#    the persistent report writer and direct USB/registry mutation imports to
#    be absent from every executable.
# 2. Each app is signed only after its final Info.plist and layout exist, so the
#    package has a valid CodeResources seal. Each executable gets one explicit
#    entitlement profile. The baseline's get-task-allow=false avoids TrollStore
#    2.1.1's no-entitlement fallback without granting debug authority.
# 3. The test harness removes signatures from temporary copies and proves the
#    packaged code payload still matches the audited build input. It separately
#    verifies the final bundle and each final entitlement profile.
# 4. Fixed mtimes, modes, member order, and stripped ZIP metadata make repeated
#    runs produce identical bytes when the inputs have not changed.
# 5. The toolbox keeps each entitlement profile on a separate executable; its
#    baseline executable is the bundle entry point and the other three live in
#    the Probes directory for fixed-path command-line execution.
# 6. This script deliberately stops at local package creation. Installing a
#    .tipa is a persistent iPad mutation and requires its own reviewed action
#    plus explicit owner approval.

readonly repo_root="$(cd -P "$(dirname "$0")" && cd -P ../../../../.. && pwd)"
readonly build_dir="$repo_root/build/ipad-hardware"
readonly build_tool="$repo_root/scripts/ipad-hardware/collect-inventory.sh"
readonly executable_name='mac2jb-u1-probe'
readonly fixed_timestamp='202601010000'
readonly sign_identity="${SIGN_IDENTITY:--}"

usage() {
  cat <<'EOF'
Usage: package-trollstore-readonly-probes.sh

Prerequisite:
  ./scripts/ipad-hardware/collect-inventory.sh build-stdout-only

Outputs:
  build/ipad-hardware/mac2jb-u1-stdout-{baseline,setdescription,
  controller-client,interface-client}.tipa
  build/ipad-hardware/mac2jb-u1-stdout-toolbox.tipa (recommended single install)
EOF
}

[[ $# -eq 0 ]] || { usage >&2; exit 2; }

for tool in /usr/bin/plutil /usr/bin/zip /usr/bin/cmp /usr/bin/shasum /usr/bin/codesign; do
  [[ -x "$tool" ]] || { echo "Missing required local tool: $tool" >&2; exit 1; }
done

# Refuse to package stale or unverified binaries.
"$build_tool" audit-stdout-only

staging_root="$(mktemp -d "${TMPDIR:-/tmp}/mac2jb-trollstore-package.XXXXXX")"
cleanup() {
  /bin/rm -rf "$staging_root"
}
trap cleanup EXIT

write_info_plist() {
  local plist="$1"
  local variant="$2"
  local bundle_id="$3"
  local bundle_executable="$4"
  /usr/bin/plutil -create xml1 "$plist"
  /usr/bin/plutil -insert CFBundleDevelopmentRegion -string en "$plist"
  /usr/bin/plutil -insert CFBundleDisplayName -string "MAC2JB U1 $variant" "$plist"
  /usr/bin/plutil -insert CFBundleExecutable -string "$bundle_executable" "$plist"
  /usr/bin/plutil -insert CFBundleIdentifier -string "$bundle_id" "$plist"
  /usr/bin/plutil -insert CFBundleInfoDictionaryVersion -string 6.0 "$plist"
  /usr/bin/plutil -insert CFBundleName -string MAC2JBU1Probe "$plist"
  /usr/bin/plutil -insert CFBundlePackageType -string APPL "$plist"
  /usr/bin/plutil -insert CFBundleShortVersionString -string 0.1.0 "$plist"
  /usr/bin/plutil -insert CFBundleSupportedPlatforms -json '["iPhoneOS"]' "$plist"
  /usr/bin/plutil -insert CFBundleVersion -string 1 "$plist"
  /usr/bin/plutil -insert LSRequiresIPhoneOS -bool true "$plist"
  /usr/bin/plutil -insert MinimumOSVersion -string 17.0 "$plist"
  /usr/bin/plutil -insert UIDeviceFamily -json '[2]' "$plist"
  /usr/bin/plutil -insert UIRequiredDeviceCapabilities -json '["arm64"]' "$plist"
  /usr/bin/plutil -lint "$plist" >/dev/null
  /bin/chmod 0644 "$plist"
}

create_archive() {
  local package_root="$1"
  local archive="$2"
  local app_name="$3"
  (
    cd "$package_root"
    COPYFILE_DISABLE=1 TZ=UTC /usr/bin/zip -X -q "$archive" \
      "Payload/$app_name/Info.plist" \
      "Payload/$app_name/$executable_name" \
      "Payload/$app_name/_CodeSignature/CodeResources"
  )
}

package_variant() {
  local variant="$1"
  local bundle_id="$2"
  local source="$build_dir/mac2jb-ios-probe-stdout-$variant"
  local app_name="Mac2JBU1-$variant.app"
  local package_root="$staging_root/$variant-root"
  local app_dir="$package_root/Payload/$app_name"
  local first_archive="$staging_root/$variant-first.tipa"
  local second_archive="$staging_root/$variant-second.tipa"
  local output="$build_dir/mac2jb-u1-stdout-$variant.tipa"

  [[ -x "$source" ]] || {
    echo "Missing audited input: $source; run build-stdout-only first." >&2
    exit 1
  }

  mkdir -p "$app_dir"
  cp "$source" "$app_dir/$executable_name"
  chmod 0755 "$app_dir/$executable_name"
  write_info_plist "$app_dir/Info.plist" "$variant" "$bundle_id" "$executable_name"
  local entitlements=''
  case "$variant" in
    baseline) entitlements="$repo_root/ios/entitlements/probe-baseline.plist" ;;
    setdescription) entitlements="$repo_root/ios/entitlements/probe.plist" ;;
    controller-client) entitlements="$repo_root/ios/entitlements/probe-controller.plist" ;;
    interface-client) entitlements="$repo_root/ios/entitlements/probe-interface.plist" ;;
  esac
  if [[ -n "$entitlements" ]]; then
    /usr/bin/codesign --force --sign "$sign_identity" --identifier "$bundle_id" \
      --entitlements "$entitlements" "$app_dir"
  else
    /usr/bin/codesign --force --sign "$sign_identity" --identifier "$bundle_id" "$app_dir"
  fi
  /usr/bin/codesign --verify --deep --strict "$app_dir"
  /bin/chmod 0644 "$app_dir/_CodeSignature/CodeResources"
  TZ=UTC touch -t "$fixed_timestamp" \
    "$app_dir/Info.plist" \
    "$app_dir/$executable_name" \
    "$app_dir/_CodeSignature/CodeResources"

  create_archive "$package_root" "$first_archive" "$app_name"
  create_archive "$package_root" "$second_archive" "$app_name"
  if ! /usr/bin/cmp -s "$first_archive" "$second_archive"; then
    echo "Packaging was not deterministic for $variant." >&2
    exit 1
  fi
  mv -f "$first_archive" "$output"
  printf '%s  %s\n' "$(/usr/bin/shasum -a 256 "$output" | awk '{print $1}')" "$output"
}

create_toolbox_archive() {
  local package_root="$1"
  local archive="$2"
  local app_name="$3"
  (
    cd "$package_root"
    COPYFILE_DISABLE=1 TZ=UTC /usr/bin/zip -X -q "$archive" \
      "Payload/$app_name/Info.plist" \
      "Payload/$app_name/mac2jb-u1-baseline" \
      "Payload/$app_name/Probes/mac2jb-u1-setdescription" \
      "Payload/$app_name/Probes/mac2jb-u1-controller-client" \
      "Payload/$app_name/Probes/mac2jb-u1-interface-client" \
      "Payload/$app_name/_CodeSignature/CodeResources"
  )
}

package_toolbox() {
  local app_name='Mac2JBU1-Toolbox.app'
  local package_root="$staging_root/toolbox-root"
  local app_dir="$package_root/Payload/$app_name"
  local probes_dir="$app_dir/Probes"
  local first_archive="$staging_root/toolbox-first.tipa"
  local second_archive="$staging_root/toolbox-second.tipa"
  local output="$build_dir/mac2jb-u1-stdout-toolbox.tipa"
  local variant source destination entitlements

  mkdir -p "$probes_dir"
  source="$build_dir/mac2jb-ios-probe-stdout-baseline"
  destination="$app_dir/mac2jb-u1-baseline"
  cp "$source" "$destination"
  chmod 0755 "$destination"

  for variant in setdescription controller-client interface-client; do
    source="$build_dir/mac2jb-ios-probe-stdout-$variant"
    destination="$probes_dir/mac2jb-u1-$variant"
    cp "$source" "$destination"
    chmod 0755 "$destination"
    case "$variant" in
      setdescription) entitlements="$repo_root/ios/entitlements/probe.plist" ;;
      controller-client) entitlements="$repo_root/ios/entitlements/probe-controller.plist" ;;
      interface-client) entitlements="$repo_root/ios/entitlements/probe-interface.plist" ;;
    esac
    /usr/bin/codesign --force --sign "$sign_identity" \
      --identifier "dev.mac2jb.u1probe.toolbox.$variant" \
      --entitlements "$entitlements" "$destination"
  done
  write_info_plist \
    "$app_dir/Info.plist" toolbox 'dev.mac2jb.u1probe.toolbox' 'mac2jb-u1-baseline'
  /usr/bin/codesign --force --sign "$sign_identity" \
    --identifier 'dev.mac2jb.u1probe.toolbox' \
    --entitlements "$repo_root/ios/entitlements/probe-baseline.plist" "$app_dir"
  /usr/bin/codesign --verify --deep --strict "$app_dir"
  /bin/chmod 0644 "$app_dir/_CodeSignature/CodeResources"
  TZ=UTC touch -t "$fixed_timestamp" \
    "$app_dir/Info.plist" \
    "$app_dir/mac2jb-u1-baseline" \
    "$probes_dir/mac2jb-u1-setdescription" \
    "$probes_dir/mac2jb-u1-controller-client" \
    "$probes_dir/mac2jb-u1-interface-client" \
    "$app_dir/_CodeSignature/CodeResources"

  create_toolbox_archive "$package_root" "$first_archive" "$app_name"
  create_toolbox_archive "$package_root" "$second_archive" "$app_name"
  if ! /usr/bin/cmp -s "$first_archive" "$second_archive"; then
    echo 'Packaging was not deterministic for the toolbox.' >&2
    exit 1
  fi
  mv -f "$first_archive" "$output"
  printf '%s  %s\n' "$(/usr/bin/shasum -a 256 "$output" | awk '{print $1}')" "$output"
}

package_variant baseline 'dev.mac2jb.u1probe.baseline'
package_variant setdescription 'dev.mac2jb.u1probe.setdescription'
package_variant controller-client 'dev.mac2jb.u1probe.controller-client'
package_variant interface-client 'dev.mac2jb.u1probe.interface-client'
package_toolbox

echo 'PASS created four deterministic variant packages and one toolbox; no iPad action was performed'
