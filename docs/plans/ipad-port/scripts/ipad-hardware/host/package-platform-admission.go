// Package a separate, read-only TrollStore admission diagnostic on the Mac.
//
// This copies the audited stdout-only U1 probe into two executables. The app
// entry point has platform-application only; the child adds only the existing
// set-description entitlement. Neither executable invokes a USB/registry
// mutation API. The package is not installed or sent to the iPad here. A later
// device install needs independent preflight, post-install attestation, and a
// cleanup-ledger entry. Existing toolbox artifacts are not changed.
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
	buildDir = "build/ipad-hardware"
	input    = buildDir + "/mac2jb-ios-probe-stdout-unsigned"
	output   = buildDir + "/mac2jb-u1-platform-admission.tipa"
	appName  = "Mac2JBU1-Admission.app"
	appID    = "dev.mac2jb.u1probe.admission"
	mainName = "mac2jb-u1-platform-only"
	child    = "mac2jb-u1-platform-setdescription"
)

var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleDisplayName</key><string>MAC2JB U1 Admission</string>
<key>CFBundleExecutable</key><string>mac2jb-u1-platform-only</string>
<key>CFBundleIdentifier</key><string>dev.mac2jb.u1probe.admission</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>MAC2JBU1Admission</string>
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
		return errors.New("signed entitlements differ from the two fixed profiles")
	}
	return nil
}

func archive(root, destination string) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	paths := []string{
		"Info.plist", mainName, "Probes/" + child,
		"_CodeSignature/CodeResources",
	}
	for _, name := range paths {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			writer.Close()
			return err
		}
		mode := os.FileMode(0644)
		if name == mainName || name == "Probes/"+child {
			mode = 0755
		}
		header := &zip.FileHeader{Name: "Payload/" + appName + "/" + name, Method: zip.Deflate}
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
	temp, err := os.MkdirTemp(buildDir, "u1-admission-*")
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
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", appID+".setdescription", "--entitlements", "ios/entitlements/probe-platform-setdescription.plist", childPath); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", appID, "--entitlements", "ios/entitlements/probe-platform-only.plist", app); err != nil {
		return err
	}
	if err := command("/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
		return err
	}
	if err := entitlements(filepath.Join(app, mainName), map[string]any{"platform-application": true}); err != nil {
		return err
	}
	if err := entitlements(childPath, map[string]any{"platform-application": true, "com.apple.private.usbdevice.setdescription": true}); err != nil {
		return err
	}
	staged := filepath.Join(temp, "admission.tipa")
	if err := archive(app, staged); err != nil {
		return err
	}
	second := filepath.Join(temp, "admission-second.tipa")
	if err := archive(app, second); err != nil {
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ADMISSION_PACKAGE rejected:", err)
		os.Exit(1)
	}
}
