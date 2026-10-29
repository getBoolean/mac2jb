#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$ROOT/build/ipad-hardware"
MODULE_CACHE="$BUILD/module-cache"
IOS_TARGET="${IOS_TARGET:-arm64-apple-ios17.0}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"

usage() {
  cat <<'EOF'
Usage:
  collect-inventory.sh test
  collect-inventory.sh build
  collect-inventory.sh audit
  collect-inventory.sh compare REPORT_A REPORT_B
  collect-inventory.sh run-local VARIANT [probe arguments]

Variants: baseline, setdescription, controller-client, interface-client.
run-local is intended for the jailbroken target after copying build/ipad-hardware
to it. Probe arguments must include the target, peer, cable, orientation, power,
runtime-version, and output fields printed by the binary on error.
EOF
}

compile_tests() {
  local test_dir
  test_dir="$(mktemp -d "${TMPDIR:-/tmp}/mac2jb-probe-tests.XXXXXX")"
  trap 'rm -rf "$test_dir"' RETURN
  xcrun swiftc -parse-as-library -swift-version 5 -target arm64-apple-macos14.0 \
    -module-cache-path "$test_dir/module-cache" \
    "$ROOT/ios/probes/ProbeResult.swift" "$ROOT/ios/tests/ProbeResultTests.swift" \
    -o "$test_dir/ProbeResultTests"
  "$test_dir/ProbeResultTests"
}

build_probe() {
  mkdir -p "$BUILD" "$MODULE_CACHE"
  xcrun --sdk iphoneos clang -target "$IOS_TARGET" -std=c11 -O2 -Wall -Wextra -Werror \
    -I "$ROOT/ios/probes" -c "$ROOT/ios/probes/MAC2JBProbeShim.c" -o "$BUILD/MAC2JBProbeShim.o"
  xcrun --sdk iphoneos swiftc -swift-version 5 -O -target "$IOS_TARGET" \
    -module-cache-path "$MODULE_CACHE" -I "$ROOT/ios/probes" \
    -framework Foundation -framework CryptoKit -framework IOKit \
    "$ROOT/ios/probes/ProbeResult.swift" "$ROOT/ios/probes/main.swift" \
    "$BUILD/MAC2JBProbeShim.o" -o "$BUILD/mac2jb-ios-probe-unsigned"

  cp "$BUILD/mac2jb-ios-probe-unsigned" "$BUILD/mac2jb-ios-probe-baseline"
  codesign --force --sign "$SIGN_IDENTITY" "$BUILD/mac2jb-ios-probe-baseline"

  local variant plist
  for variant in setdescription controller-client interface-client; do
    case "$variant" in
      setdescription) plist="$ROOT/ios/entitlements/probe.plist" ;;
      controller-client) plist="$ROOT/ios/entitlements/probe-controller.plist" ;;
      interface-client) plist="$ROOT/ios/entitlements/probe-interface.plist" ;;
    esac
    cp "$BUILD/mac2jb-ios-probe-unsigned" "$BUILD/mac2jb-ios-probe-$variant"
    codesign --force --sign "$SIGN_IDENTITY" --entitlements "$plist" "$BUILD/mac2jb-ios-probe-$variant"
  done
  audit_probe
  echo "Built read-only probe variants in $BUILD"
}

audit_probe() {
  local source="$ROOT/ios/probes/main.swift"
  local shim="$ROOT/ios/probes/MAC2JBProbeShim.c"
  local controller_plist="$ROOT/ios/entitlements/probe-controller.plist"
  local interface_plist="$ROOT/ios/entitlements/probe-interface.plist"
  local entitlement_audit_dir
  entitlement_audit_dir="$(mktemp -d "${TMPDIR:-/tmp}/mac2jb-entitlements.XXXXXX")"
  trap "rm -rf '$entitlement_audit_dir'" EXIT
  if rg -n 'IOUSBDeviceController(SetDescription|SendCommand|GoOffAndOnBus|ForceOffBus)[[:space:]]*\(' "$source" "$shim"; then
    echo 'A USB mutation API is directly callable from the probe.' >&2
    exit 1
  fi
  if rg -n 'IORegistryEntrySetCF(Propert|Properties)[[:space:]]*\(' "$source" "$shim"; then
    echo 'An IOKit registry mutation API is directly callable from the probe.' >&2
    exit 1
  fi
  if /usr/libexec/PlistBuddy -c 'Print :com.apple.private.usbdevice.setdescription' "$controller_plist" >/dev/null 2>&1; then
    echo 'Controller-client profile must not include setdescription authority.' >&2
    exit 1
  fi
  if /usr/libexec/PlistBuddy -c 'Print :com.apple.private.usbdevice.setdescription' "$interface_plist" >/dev/null 2>&1; then
    echo 'Interface-client profile must not include setdescription authority.' >&2
    exit 1
  fi
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.exception.iokit-user-client-class:0' "$controller_plist")" == 'IOUSBDeviceControllerUserClient' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.exception.iokit-user-client-class:0' "$interface_plist")" == 'IOUSBDeviceInterfaceUserClient' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :platform-application' "$controller_plist")" == 'true' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :platform-application' "$interface_plist")" == 'true' ]]
  for binary in "$BUILD"/mac2jb-ios-probe-{baseline,setdescription,controller-client,interface-client}; do
    [[ -x "$binary" ]] || { echo "Missing probe variant: $binary" >&2; exit 1; }
    codesign --verify --strict "$binary"
  done
  codesign -d --entitlements :- "$BUILD/mac2jb-ios-probe-setdescription" \
    > "$entitlement_audit_dir/setdescription.plist" 2>/dev/null
  codesign -d --entitlements :- "$BUILD/mac2jb-ios-probe-controller-client" \
    > "$entitlement_audit_dir/controller.plist" 2>/dev/null
  codesign -d --entitlements :- "$BUILD/mac2jb-ios-probe-interface-client" \
    > "$entitlement_audit_dir/interface.plist" 2>/dev/null

  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.private.usbdevice.setdescription' "$entitlement_audit_dir/setdescription.plist")" == 'true' ]]
  if /usr/libexec/PlistBuddy -c 'Print :com.apple.private.usbdevice.setdescription' "$entitlement_audit_dir/controller.plist" >/dev/null 2>&1; then
    echo 'Signed controller-client variant includes setdescription authority.' >&2
    exit 1
  fi
  if /usr/libexec/PlistBuddy -c 'Print :com.apple.private.usbdevice.setdescription' "$entitlement_audit_dir/interface.plist" >/dev/null 2>&1; then
    echo 'Signed interface-client variant includes setdescription authority.' >&2
    exit 1
  fi
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.exception.iokit-user-client-class:0' "$entitlement_audit_dir/controller.plist")" == 'IOUSBDeviceControllerUserClient' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.exception.iokit-user-client-class:0' "$entitlement_audit_dir/interface.plist")" == 'IOUSBDeviceInterfaceUserClient' ]]
  echo 'PASS read-only probe audit'
}

compare_reports() {
  [[ $# -eq 2 ]] || { usage >&2; exit 2; }
  node - "$1" "$2" <<'NODE'
const fs = require('fs');
const [aPath, bPath] = process.argv.slice(2);
const a = JSON.parse(fs.readFileSync(aPath, 'utf8'));
const b = JSON.parse(fs.readFileSync(bPath, 'utf8'));
if (!a.topologyFingerprint || !b.topologyFingerprint) throw new Error('Report lacks topologyFingerprint');
if (a.topologyFingerprint !== b.topologyFingerprint) {
  console.error(`Topology mismatch: ${a.topologyFingerprint} != ${b.topologyFingerprint}`);
  process.exit(1);
}
console.log(`PASS equivalent topology ${a.topologyFingerprint}`);
NODE
}

run_local() {
  [[ $# -ge 1 ]] || { usage >&2; exit 2; }
  local variant="$1"
  shift
  case "$variant" in
    baseline|setdescription|controller-client|interface-client) ;;
    *) echo "Unknown probe variant: $variant" >&2; exit 2 ;;
  esac
  local binary="$BUILD/mac2jb-ios-probe-$variant"
  [[ -x "$binary" ]] || { echo "Missing $binary; run build on the Mac first." >&2; exit 1; }
  exec "$binary" "$@"
}

case "${1:-}" in
  test) compile_tests ;;
  build) build_probe ;;
  audit) audit_probe ;;
  compare) shift; compare_reports "$@" ;;
  run-local) shift; run_local "$@" ;;
  *) usage >&2; exit 2 ;;
esac
