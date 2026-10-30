#!/bin/bash
set -euo pipefail

ROOT="$(cd -P "$(dirname "$0")" && cd -P ../../../../.. && pwd)"
BUILD="$ROOT/build/ipad-hardware"
MODULE_CACHE="$BUILD/module-cache"
IOS_TARGET="${IOS_TARGET:-arm64-apple-ios17.0}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"

usage() {
  cat <<'EOF'
Usage:
  collect-inventory.sh test
  collect-inventory.sh build
  collect-inventory.sh build-stdout-only
  collect-inventory.sh build-diagnostic
  collect-inventory.sh audit
  collect-inventory.sh audit-stdout-only
  collect-inventory.sh audit-diagnostic
  collect-inventory.sh compare REPORT_A REPORT_B
  collect-inventory.sh run-local VARIANT [probe arguments]

Variants: baseline, setdescription, controller-client, interface-client.
The stdout-only build is the device-safe collection artifact: it rejects
--output and emits canonical JSON only to standard output. Its binary audit
must confirm that the persistent report writer was removed.
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
    "$ROOT/ios/probes/ProbeOptions.swift" \
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
    "$ROOT/ios/probes/ProbeOptions.swift" "$ROOT/ios/probes/ProbeResult.swift" \
    "$ROOT/ios/probes/main.swift" \
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

build_stdout_probe() {
  mkdir -p "$BUILD" "$MODULE_CACHE"
  xcrun --sdk iphoneos clang -target "$IOS_TARGET" -std=c11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I "$ROOT/ios/probes" -c "$ROOT/ios/probes/MAC2JBProbeShim.c" \
    -o "$BUILD/MAC2JBProbeShimStdout.o"
  xcrun --sdk iphoneos swiftc -swift-version 5 -O -D MAC2JB_STDOUT_ONLY -target "$IOS_TARGET" \
    -module-cache-path "$MODULE_CACHE" -I "$ROOT/ios/probes" \
    -framework Foundation -framework CryptoKit -framework IOKit \
    -Xlinker -dead_strip \
    "$ROOT/ios/probes/ProbeOptions.swift" "$ROOT/ios/probes/ProbeResult.swift" \
    "$ROOT/ios/probes/main.swift" \
    "$BUILD/MAC2JBProbeShimStdout.o" -o "$BUILD/mac2jb-ios-probe-stdout-unsigned"

  cp "$BUILD/mac2jb-ios-probe-stdout-unsigned" "$BUILD/mac2jb-ios-probe-stdout-baseline"
  codesign --force --sign "$SIGN_IDENTITY" "$BUILD/mac2jb-ios-probe-stdout-baseline"

  local variant plist
  for variant in setdescription controller-client interface-client; do
    case "$variant" in
      setdescription) plist="$ROOT/ios/entitlements/probe.plist" ;;
      controller-client) plist="$ROOT/ios/entitlements/probe-controller.plist" ;;
      interface-client) plist="$ROOT/ios/entitlements/probe-interface.plist" ;;
    esac
    cp "$BUILD/mac2jb-ios-probe-stdout-unsigned" "$BUILD/mac2jb-ios-probe-stdout-$variant"
    codesign --force --sign "$SIGN_IDENTITY" --entitlements "$plist" \
      "$BUILD/mac2jb-ios-probe-stdout-$variant"
  done
  audit_stdout_probe
  echo "Built stdout-only read-only probe variants in $BUILD"
}

build_diagnostic() {
  mkdir -p "$BUILD" "$MODULE_CACHE"
  xcrun --sdk iphoneos clang -target "$IOS_TARGET" -std=c11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I "$ROOT/ios/probes" -c "$ROOT/ios/probes/MAC2JBProbeShim.c" \
    -o "$BUILD/MAC2JBProbeShimDiagnostic.o"
  xcrun --sdk iphoneos swiftc -swift-version 5 -O -D MAC2JB_DIAGNOSTIC -target "$IOS_TARGET" \
    -module-cache-path "$MODULE_CACHE" -I "$ROOT/ios/probes" \
    -framework Foundation -framework CryptoKit -framework IOKit \
    -Xlinker -dead_strip \
    "$ROOT/ios/probes/ProbeOptions.swift" "$ROOT/ios/probes/ProbeResult.swift" \
    "$ROOT/ios/probes/main.swift" \
    "$BUILD/MAC2JBProbeShimDiagnostic.o" -o "$BUILD/mac2jb-ios-probe-diagnostic-unsigned"

  cp "$BUILD/mac2jb-ios-probe-diagnostic-unsigned" "$BUILD/mac2jb-ios-probe-diagnostic"
  codesign --force --sign "$SIGN_IDENTITY" "$BUILD/mac2jb-ios-probe-diagnostic"
  audit_diagnostic
  echo "Built diagnostic-only probe in $BUILD"
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
  if rg -n 'IORegistryEntrySetCFPropert(y|ies)[[:space:]]*\(' "$source" "$shim"; then
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

audit_stdout_probe() {
  local source="$ROOT/ios/probes/main.swift"
  local shim="$ROOT/ios/probes/MAC2JBProbeShim.c"
  local audit_dir
  audit_dir="$(mktemp -d "${TMPDIR:-/tmp}/mac2jb-stdout-audit.XXXXXX")"
  trap "/bin/rm -rf '$audit_dir'" RETURN

  if rg -n 'IOUSBDeviceController(SetDescription|SendCommand|GoOffAndOnBus|ForceOffBus)[[:space:]]*\(' "$source" "$shim"; then
    echo 'A USB mutation API is directly callable from the stdout-only probe sources.' >&2
    exit 1
  fi
  if rg -n 'IORegistryEntrySetCFPropert(y|ies)[[:space:]]*\(' "$source" "$shim"; then
    echo 'An IOKit registry mutation API is directly callable from the stdout-only probe sources.' >&2
    exit 1
  fi

  local variant binary entitlements symbols undefined_symbols strings
  for variant in baseline setdescription controller-client interface-client; do
    binary="$BUILD/mac2jb-ios-probe-stdout-$variant"
    entitlements="$audit_dir/$variant-entitlements.plist"
    symbols="$audit_dir/$variant-symbols.txt"
    undefined_symbols="$audit_dir/$variant-undefined-symbols.txt"
    strings="$audit_dir/$variant-strings.txt"

    [[ -x "$binary" ]] || { echo "Missing stdout-only probe variant: $binary" >&2; exit 1; }
    codesign --verify --strict "$binary"
    /usr/bin/nm "$binary" > "$symbols"
    /usr/bin/nm -u "$binary" > "$undefined_symbols"
    /usr/bin/strings -a "$binary" > "$strings"
    if rg -q 'MAC2JBWriteExclusiveReport|MAC2JB_PROBE_REPORT' "$symbols" "$strings"; then
      echo "The stdout-only $variant binary retained the persistent report writer." >&2
      exit 1
    fi
    if rg -q '_IOUSBDeviceController(SetDescription|SendCommand|GoOffAndOnBus|ForceOffBus)$|_IORegistryEntrySetCFPropert(y|ies)$' "$undefined_symbols"; then
      echo "The stdout-only $variant binary directly imports a USB or registry mutation API." >&2
      exit 1
    fi
    rg -q '^--output is forbidden in stdout-only mode$' "$strings"
    codesign -d --entitlements :- "$binary" > "$entitlements" 2>/dev/null || true
  done

  if rg -q '<key>' "$audit_dir/baseline-entitlements.plist"; then
    echo 'The stdout-only baseline unexpectedly carries an entitlement.' >&2
    exit 1
  fi
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.private.usbdevice.setdescription' "$audit_dir/setdescription-entitlements.plist")" == 'true' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.exception.iokit-user-client-class:0' "$audit_dir/controller-client-entitlements.plist")" == 'IOUSBDeviceControllerUserClient' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.exception.iokit-user-client-class:0' "$audit_dir/interface-client-entitlements.plist")" == 'IOUSBDeviceInterfaceUserClient' ]]
  trap - RETURN
  /bin/rm -rf "$audit_dir"
  echo 'PASS stdout-only read-only probe binary audit: no persistent report writer or direct mutation imports'
}

audit_diagnostic() {
  local source="$ROOT/ios/probes/main.swift"
  local shim="$ROOT/ios/probes/MAC2JBProbeShim.c"
  local binary="$BUILD/mac2jb-ios-probe-diagnostic"
  local audit_dir entitlements symbols undefined_symbols strings
  audit_dir="$(mktemp -d "${TMPDIR:-/tmp}/mac2jb-diagnostic-audit.XXXXXX")"
  entitlements="$audit_dir/entitlements.plist"
  symbols="$audit_dir/symbols.txt"
  undefined_symbols="$audit_dir/undefined-symbols.txt"
  strings="$audit_dir/strings.txt"
  trap "/bin/rm -rf '$audit_dir'" RETURN

  [[ -x "$binary" ]] || { echo "Missing diagnostic probe: $binary" >&2; exit 1; }
  codesign --verify --strict "$binary"
  if rg -n 'IOUSBDeviceController(SetDescription|SendCommand|GoOffAndOnBus|ForceOffBus)[[:space:]]*\(' "$source" "$shim"; then
    echo 'A USB mutation API is directly callable from the diagnostic sources.' >&2
    exit 1
  fi
  if rg -n 'IORegistryEntrySetCFPropert(y|ies)[[:space:]]*\(' "$source" "$shim"; then
    echo 'An IOKit registry mutation API is directly callable from the diagnostic sources.' >&2
    exit 1
  fi

  /usr/bin/nm "$binary" > "$symbols"
  /usr/bin/nm -u "$binary" > "$undefined_symbols"
  /usr/bin/strings -a "$binary" > "$strings"
  if rg -q 'MAC2JBWriteExclusiveReport|MAC2JB_PROBE_REPORT' "$symbols" "$strings"; then
    echo 'The diagnostic binary retained a reachable report-writer symbol or normal report marker.' >&2
    exit 1
  fi
  if rg -q '_IOUSBDeviceController(SetDescription|SendCommand|GoOffAndOnBus|ForceOffBus)$|_IORegistryEntrySetCFPropert(y|ies)$' "$undefined_symbols"; then
    echo 'The diagnostic binary directly imports a USB or registry mutation API.' >&2
    exit 1
  fi
  for mutation_symbol in \
    IOUSBDeviceControllerSetDescription \
    IOUSBDeviceControllerSendCommand \
    IOUSBDeviceControllerGoOffAndOnBus \
    IOUSBDeviceControllerForceOffBus \
    IORegistryEntrySetCFProperty \
    IORegistryEntrySetCFProperties
  do
    rg -q "^${mutation_symbol}$" "$strings"
  done
  rg -q '^MAC2JB_DIAG_PROCESS v1$' "$strings"

  codesign -d --entitlements :- "$binary" > "$entitlements" 2>/dev/null || true
  if rg -q '<key>' "$entitlements"; then
    echo 'The diagnostic binary unexpectedly carries an entitlement.' >&2
    exit 1
  fi
  trap - RETURN
  /bin/rm -rf "$audit_dir"
  echo 'PASS diagnostic-only probe audit'
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
  build-stdout-only) build_stdout_probe ;;
  build-diagnostic) build_diagnostic ;;
  audit) audit_probe ;;
  audit-stdout-only) audit_stdout_probe ;;
  audit-diagnostic) audit_diagnostic ;;
  compare) shift; compare_reports "$@" ;;
  run-local) shift; run_local "$@" ;;
  *) usage >&2; exit 2 ;;
esac
