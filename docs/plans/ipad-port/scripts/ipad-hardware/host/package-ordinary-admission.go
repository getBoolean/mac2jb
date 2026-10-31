// Package a separate, read-only ordinary-app admission diagnostic on the Mac.
//
// This copies the audited stdout-only U1 probe into two executables. The
// default package uses TrollStore's ordinary-app identity with get-task-allow
// false; --debug-ordinary uses a distinct app ID with get-task-allow true.
// In either package the child adds only set-description to the main profile;
// neither executable invokes a USB/registry mutation API. Packaging never
// contacts the iPad. Installation needs independent preflight, attestation,
// and a cleanup-ledger entry. Existing toolbox artifacts are not changed.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"
)

const (
	buildDir     = "build/ipad-hardware"
	input        = buildDir + "/mac2jb-ios-probe-stdout-unsigned"
	output       = buildDir + "/mac2jb-u1-ordinary-admission.tipa"
	appName      = "Mac2JBU1-OrdinaryAdmission.app"
	appID        = "dev.mac2jb.u1probe.ordinaryadmission"
	mainName     = "mac2jb-u1-ordinary-baseline"
	child        = "mac2jb-u1-ordinary-setdescription"
	markerOutput = buildDir + "/mac2jb-u1-springboard-marker.tipa"
	markerApp    = "Mac2JBU1-SpringBoardMarker.app"
	markerID     = "dev.mac2jb.u1probe.springboardmarker"
	markerName   = "mac2jb-u1-springboard-marker"
	debugOutput  = buildDir + "/mac2jb-u1-debug-ordinary.tipa"
	debugApp     = "Mac2JBU1-DebugOrdinary.app"
	debugID      = "dev.mac2jb.u1probe.debugordinary"
	debugMain    = "mac2jb-u1-debug-baseline"
	debugChild   = "mac2jb-u1-debug-setdescription"
	r2Executable = "mac2jb-u1-springboard-r2"
	r2Baseline   = buildDir + "/mac2jb-u1-springboard-r2-baseline.tipa"
	r2SetDesc    = buildDir + "/mac2jb-u1-springboard-r2-setdescription.tipa"
)

var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleDisplayName</key><string>MAC2JB U1 Ordinary Admission</string>
<key>CFBundleExecutable</key><string>mac2jb-u1-ordinary-baseline</string>
<key>CFBundleIdentifier</key><string>dev.mac2jb.u1probe.ordinaryadmission</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>MAC2JBU1OrdinaryAdmission</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
<key>CFBundleVersion</key><string>1</string>
<key>LSRequiresIPhoneOS</key><true/>
<key>MinimumOSVersion</key><string>17.0</string>
<key>UIDeviceFamily</key><array><integer>2</integer></array>
<key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
</dict></plist>
`

const markerInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleDisplayName</key><string>MAC2JB U1 SpringBoard Marker</string>
<key>CFBundleExecutable</key><string>mac2jb-u1-springboard-marker</string>
<key>CFBundleIdentifier</key><string>dev.mac2jb.u1probe.springboardmarker</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>MAC2JBU1SpringBoardMarker</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
<key>CFBundleVersion</key><string>1</string>
<key>LSRequiresIPhoneOS</key><true/>
<key>MinimumOSVersion</key><string>17.0</string>
<key>UIDeviceFamily</key><array><integer>2</integer></array>
<key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
</dict></plist>
`

const debugInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleDisplayName</key><string>MAC2JB U1 Debug Ordinary</string>
<key>CFBundleExecutable</key><string>mac2jb-u1-debug-baseline</string>
<key>CFBundleIdentifier</key><string>dev.mac2jb.u1probe.debugordinary</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>MAC2JBU1DebugOrdinary</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
<key>CFBundleVersion</key><string>1</string>
<key>LSRequiresIPhoneOS</key><true/>
<key>MinimumOSVersion</key><string>17.0</string>
<key>UIDeviceFamily</key><array><integer>2</integer></array>
<key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
</dict></plist>
`

func command(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		if len(data) > 512 {
			data = data[:512]
		}
		return fmt.Errorf("local %s failed: %w: %s", filepath.Base(name), err, data)
	}
	return nil
}

func entitlements(path string, expected map[string]any) error {
	cmd := exec.Command("/usr/bin/codesign", "-d", "--entitlements", ":-", path)
	var actual bytes.Buffer
	cmd.Stdout = &actual
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot read signed entitlements: %w", err)
	}
	temp, err := os.CreateTemp(buildDir, "u1-entitlements-*.plist")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(actual.Bytes()); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	jsonBytes, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", temp.Name()).Output()
	if err != nil {
		return fmt.Errorf("invalid signed entitlements: %w", err)
	}
	var got map[string]any
	if err = json.Unmarshal(jsonBytes, &got); err != nil {
		return err
	}
	if !reflect.DeepEqual(got, expected) {
		return errors.New("signed entitlements differ from the two fixed ordinary profiles")
	}
	return nil
}

func archive(root, destination, bundle, executable, childExecutable string) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	paths := []string{
		"Info.plist", executable, "Probes/" + childExecutable,
		"_CodeSignature/CodeResources",
	}
	for _, name := range paths {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			writer.Close()
			return err
		}
		mode := os.FileMode(0644)
		if name == executable || name == "Probes/"+childExecutable {
			mode = 0755
		}
		header := &zip.FileHeader{Name: "Payload/" + bundle + "/" + name, Method: zip.Deflate}
		header.SetMode(mode)
		header.Modified = fixedTime
		entry, err := writer.CreateHeader(header)
		if err != nil {
			writer.Close()
			return err
		}
		if _, err := entry.Write(body); err != nil {
			writer.Close()
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return file.Sync()
}

func archiveMarker(root, destination string) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	for _, name := range []string{"Info.plist", markerName, "_CodeSignature/CodeResources"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			writer.Close()
			return err
		}
		mode := os.FileMode(0644)
		if name == markerName {
			mode = 0755
		}
		header := &zip.FileHeader{Name: "Payload/" + markerApp + "/" + name, Method: zip.Deflate}
		header.SetMode(mode)
		header.Modified = fixedTime
		entry, err := writer.CreateHeader(header)
		if err != nil {
			writer.Close()
			return err
		}
		if _, err := entry.Write(body); err != nil {
			writer.Close()
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return file.Sync()
}

func archiveSingle(root, destination, bundle, executable string) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	for _, name := range []string{"Info.plist", executable, "_CodeSignature/CodeResources"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			writer.Close()
			return err
		}
		mode := os.FileMode(0644)
		if name == executable {
			mode = 0755
		}
		header := &zip.FileHeader{Name: "Payload/" + bundle + "/" + name, Method: zip.Deflate}
		header.SetMode(mode)
		header.Modified = fixedTime
		entry, err := writer.CreateHeader(header)
		if err != nil {
			writer.Close()
			return err
		}
		if _, err := entry.Write(body); err != nil {
			writer.Close()
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return file.Sync()
}

// runMarker only packages a new, distinct app; it never contacts the iPad.
func runMarker() error {
	if _, err := os.Stat(markerOutput); !os.IsNotExist(err) {
		return errors.New("marker output already exists or cannot be checked")
	}
	temp, err := os.MkdirTemp(buildDir, "u1-springboard-marker-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	app := filepath.Join(temp, markerApp)
	if err := os.Mkdir(app, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(app, "Info.plist"), []byte(markerInfoPlist), 0644); err != nil {
		return err
	}
	if err := command("/usr/bin/plutil", "-lint", filepath.Join(app, "Info.plist")); err != nil {
		return err
	}
	binary := filepath.Join(app, markerName)
	if err := command("/usr/bin/xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios17.0", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o", binary, "ios/probes/U1SpringBoardMarker.c"); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", markerID, "--entitlements", "ios/entitlements/probe-ordinary-app.plist", app); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
		return err
	}
	ordinary := map[string]any{
		"application-identifier":              "TROLLTROLL.*",
		"com.apple.developer.team-identifier": "TROLLTROLL",
		"get-task-allow":                      false,
		"keychain-access-groups":              []any{"TROLLTROLL.*", "com.apple.token"},
	}
	if err := entitlements(binary, ordinary); err != nil {
		return err
	}
	first := filepath.Join(temp, "marker.tipa")
	second := filepath.Join(temp, "marker-second.tipa")
	if err := archiveMarker(app, first); err != nil {
		return err
	}
	if err := archiveMarker(app, second); err != nil {
		return err
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		return err
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil || !bytes.Equal(firstBytes, secondBytes) {
		return errors.New("marker ZIP creation is not deterministic")
	}
	if err := os.Link(first, markerOutput); err != nil {
		return err
	}
	digest := sha256.Sum256(firstBytes)
	fmt.Printf("MARKER_PACKAGE sha256=%s bytes=%d\n", hex.EncodeToString(digest[:]), len(firstBytes))
	return nil
}

func run() error {
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		return errors.New("output already exists or cannot be checked")
	}
	if err := command("/bin/bash", "docs/plans/ipad-port/scripts/ipad-hardware/collect-inventory.sh", "audit-stdout-only"); err != nil {
		return err
	}
	data, err := os.ReadFile(input)
	if err != nil || len(data) < 100000 || len(data) > 2000000 {
		return errors.New("audited unsigned probe missing or wrong size")
	}
	temp, err := os.MkdirTemp(buildDir, "u1-ordinary-admission-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	app := filepath.Join(temp, appName)
	if err := os.MkdirAll(filepath.Join(app, "Probes"), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(app, "Info.plist"), []byte(infoPlist), 0644); err != nil {
		return err
	}
	if err := command("/usr/bin/plutil", "-lint", filepath.Join(app, "Info.plist")); err != nil {
		return err
	}
	for _, name := range []string{mainName, "Probes/" + child} {
		if err := os.WriteFile(filepath.Join(app, name), data, 0755); err != nil {
			return err
		}
	}
	childPath := filepath.Join(app, "Probes", child)
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", appID+".setdescription", "--entitlements", "ios/entitlements/probe-ordinary-setdescription.plist", childPath); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", appID, "--entitlements", "ios/entitlements/probe-ordinary-app.plist", app); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
		return err
	}
	ordinary := map[string]any{
		"application-identifier":              "TROLLTROLL.*",
		"com.apple.developer.team-identifier": "TROLLTROLL",
		"get-task-allow":                      false,
		"keychain-access-groups":              []any{"TROLLTROLL.*", "com.apple.token"},
	}
	if err := entitlements(filepath.Join(app, mainName), ordinary); err != nil {
		return err
	}
	childExpected := map[string]any{}
	for key, value := range ordinary {
		childExpected[key] = value
	}
	childExpected["com.apple.private.usbdevice.setdescription"] = true
	if err := entitlements(childPath, childExpected); err != nil {
		return err
	}
	staged := filepath.Join(temp, "admission.tipa")
	if err := archive(app, staged, appName, mainName, child); err != nil {
		return err
	}
	second := filepath.Join(temp, "admission-second.tipa")
	if err := archive(app, second, appName, mainName, child); err != nil {
		return err
	}
	firstBytes, err := os.ReadFile(staged)
	if err != nil {
		return err
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		return err
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		return errors.New("package ZIP creation is not deterministic")
	}
	if err := os.Link(staged, output); err != nil {
		return err
	}
	digest := sha256.Sum256(firstBytes)
	fmt.Printf("ADMISSION_PACKAGE sha256=%s bytes=%d\n", hex.EncodeToString(digest[:]), len(firstBytes))
	return nil
}

// runDebug keeps the audited probe code identical while changing only the
// ordinary app identity and get-task-allow value. It never contacts the iPad.
func runDebug() error {
	if _, err := os.Stat(debugOutput); !os.IsNotExist(err) {
		return errors.New("debug output already exists or cannot be checked")
	}
	if err := command("/bin/bash", "docs/plans/ipad-port/scripts/ipad-hardware/collect-inventory.sh", "audit-stdout-only"); err != nil {
		return err
	}
	data, err := os.ReadFile(input)
	if err != nil || len(data) < 100000 || len(data) > 2000000 {
		return errors.New("audited unsigned probe missing or wrong size")
	}
	temp, err := os.MkdirTemp(buildDir, "u1-debug-ordinary-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	app := filepath.Join(temp, debugApp)
	if err := os.MkdirAll(filepath.Join(app, "Probes"), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(app, "Info.plist"), []byte(debugInfoPlist), 0644); err != nil {
		return err
	}
	if err := command("/usr/bin/plutil", "-lint", filepath.Join(app, "Info.plist")); err != nil {
		return err
	}
	for _, name := range []string{debugMain, "Probes/" + debugChild} {
		if err := os.WriteFile(filepath.Join(app, name), data, 0755); err != nil {
			return err
		}
	}
	childPath := filepath.Join(app, "Probes", debugChild)
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", debugID+".setdescription", "--entitlements", "ios/entitlements/probe-debug-ordinary-setdescription.plist", childPath); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", debugID, "--entitlements", "ios/entitlements/probe-debug-ordinary-app.plist", app); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
		return err
	}
	ordinary := map[string]any{
		"application-identifier":              "TROLLTROLL.*",
		"com.apple.developer.team-identifier": "TROLLTROLL",
		"get-task-allow":                      true,
		"keychain-access-groups":              []any{"TROLLTROLL.*", "com.apple.token"},
	}
	if err := entitlements(filepath.Join(app, debugMain), ordinary); err != nil {
		return err
	}
	childExpected := map[string]any{}
	for key, value := range ordinary {
		childExpected[key] = value
	}
	childExpected["com.apple.private.usbdevice.setdescription"] = true
	if err := entitlements(childPath, childExpected); err != nil {
		return err
	}
	staged := filepath.Join(temp, "debug.tipa")
	second := filepath.Join(temp, "debug-second.tipa")
	if err := archive(app, staged, debugApp, debugMain, debugChild); err != nil {
		return err
	}
	if err := archive(app, second, debugApp, debugMain, debugChild); err != nil {
		return err
	}
	firstBytes, err := os.ReadFile(staged)
	if err != nil {
		return err
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil || !bytes.Equal(firstBytes, secondBytes) {
		return errors.New("debug ZIP creation is not deterministic")
	}
	if err := os.Link(staged, debugOutput); err != nil {
		return err
	}
	digest := sha256.Sum256(firstBytes)
	fmt.Printf("DEBUG_ORDINARY_PACKAGE sha256=%s bytes=%d\n", hex.EncodeToString(digest[:]), len(firstBytes))
	return nil
}

// runSpringboardR2 builds two distinct no-argument apps from one read-only
// collector binary. Their only effective entitlement difference is USB
// set-description; the collector never invokes a USB mutation symbol.
func runSpringboardR2() error {
	for _, output := range []string{r2Baseline, r2SetDesc} {
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			return errors.New("SpringBoard R2 output already exists or cannot be checked")
		}
	}
	temp, err := os.MkdirTemp(buildDir, "u1-springboard-r2-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	object := filepath.Join(temp, "shim.o")
	unsigned := filepath.Join(temp, "unsigned")
	if err := command("/usr/bin/xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios17.0",
		"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections",
		"-I", "ios/probes", "-c", "ios/probes/MAC2JBProbeShim.c", "-o", object); err != nil {
		return err
	}
	if err := command("/usr/bin/xcrun", "--sdk", "iphoneos", "swiftc", "-swift-version", "5", "-O",
		"-D", "MAC2JB_SPRINGBOARD_R2", "-target", "arm64-apple-ios17.0",
		"-module-cache-path", filepath.Join(buildDir, "swift-module-cache"), "-I", "ios/probes",
		"-framework", "Foundation", "-framework", "CryptoKit", "-framework", "IOKit",
		"-Xlinker", "-dead_strip", "ios/probes/ProbeOptions.swift", "ios/probes/ProbeResult.swift",
		"ios/probes/main.swift", object, "-o", unsigned); err != nil {
		return err
	}
	imports, err := exec.Command("/usr/bin/nm", "-u", unsigned).Output()
	if err != nil {
		return err
	}
	for _, forbidden := range []string{
		"_IOUSBDeviceControllerSetDescription", "_IOUSBDeviceControllerSendCommand",
		"_IOUSBDeviceControllerGoOffAndOnBus", "_IOUSBDeviceControllerForceOffBus",
		"_IORegistryEntrySetCFProperty", "_IORegistryEntrySetCFProperties",
	} {
		if bytes.Contains(imports, []byte(forbidden)) {
			return errors.New("SpringBoard R2 directly imports a USB/registry mutation API")
		}
	}
	code, err := os.ReadFile(unsigned)
	if err != nil || len(code) < 100000 || len(code) > 2000000 {
		return errors.New("SpringBoard R2 code missing or wrong size")
	}
	profiles := []struct {
		label, bundle, id, name, output, entitlement string
		setDescription                               bool
	}{
		{"baseline", "Mac2JBU1-R2Baseline.app", "dev.mac2jb.u1probe.r2baseline", "MAC2JBU1R2Baseline", r2Baseline, "ios/entitlements/probe-ordinary-app.plist", false},
		{"setdescription", "Mac2JBU1-R2SetDescription.app", "dev.mac2jb.u1probe.r2setdescription", "MAC2JBU1R2SetDescription", r2SetDesc, "ios/entitlements/probe-ordinary-setdescription.plist", true},
	}
	for _, profile := range profiles {
		app := filepath.Join(temp, profile.bundle)
		if err := os.Mkdir(app, 0755); err != nil {
			return err
		}
		info := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleDisplayName</key><string>MAC2JB U1 R2 %s</string>
<key>CFBundleExecutable</key><string>%s</string>
<key>CFBundleIdentifier</key><string>%s</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>%s</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
<key>CFBundleVersion</key><string>1</string>
<key>LSRequiresIPhoneOS</key><true/>
<key>MinimumOSVersion</key><string>17.0</string>
<key>UIDeviceFamily</key><array><integer>2</integer></array>
<key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
</dict></plist>
`, profile.label, r2Executable, profile.id, profile.name)
		if err := os.WriteFile(filepath.Join(app, "Info.plist"), []byte(info), 0644); err != nil {
			return err
		}
		if err := command("/usr/bin/plutil", "-lint", filepath.Join(app, "Info.plist")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(app, r2Executable), code, 0755); err != nil {
			return err
		}
		if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", profile.id,
			"--entitlements", profile.entitlement, app); err != nil {
			return err
		}
		if err := command("/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
			return err
		}
		expected := map[string]any{
			"application-identifier":              "TROLLTROLL.*",
			"com.apple.developer.team-identifier": "TROLLTROLL",
			"get-task-allow":                      false,
			"keychain-access-groups":              []any{"TROLLTROLL.*", "com.apple.token"},
		}
		if profile.setDescription {
			expected["com.apple.private.usbdevice.setdescription"] = true
		}
		if err := entitlements(filepath.Join(app, r2Executable), expected); err != nil {
			return err
		}
		first := filepath.Join(temp, profile.label+".tipa")
		second := filepath.Join(temp, profile.label+"-second.tipa")
		if err := archiveSingle(app, first, profile.bundle, r2Executable); err != nil {
			return err
		}
		if err := archiveSingle(app, second, profile.bundle, r2Executable); err != nil {
			return err
		}
		firstBytes, err := os.ReadFile(first)
		if err != nil {
			return err
		}
		secondBytes, err := os.ReadFile(second)
		if err != nil || !bytes.Equal(firstBytes, secondBytes) {
			return errors.New("SpringBoard R2 package is not deterministic")
		}
		if err := os.Link(first, profile.output); err != nil {
			return err
		}
		digest := sha256.Sum256(firstBytes)
		fmt.Printf("SPRINGBOARD_R2_PACKAGE profile=%s sha256=%s bytes=%d\n",
			profile.label, hex.EncodeToString(digest[:]), len(firstBytes))
	}
	return nil
}

func main() {
	var err error
	if len(os.Args) == 2 && os.Args[1] == "--springboard-marker" {
		err = runMarker()
	} else if len(os.Args) == 2 && os.Args[1] == "--debug-ordinary" {
		err = runDebug()
	} else if len(os.Args) == 2 && os.Args[1] == "--springboard-r2" {
		err = runSpringboardR2()
	} else if len(os.Args) == 1 {
		err = run()
	} else {
		err = errors.New("unknown package mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ADMISSION_PACKAGE rejected:", err)
		os.Exit(1)
	}
}
