// Classify Developer Mode on the one matching iPad over libimobiledevice Wi-Fi.
//
// This Mac-only program calls only idevice_id network discovery, ideviceinfo
// GetValue for the known product tuple, and idevicedevmodectl list. It never
// calls enable, arm, confirm, reveal, or any iPad shell command. Raw UDIDs,
// pair records, addresses, names, and tool diagnostics stay in process memory;
// only fixed categories are printed. A missing or ambiguous network device
// fails closed. Device pairing handshakes can create ordinary session logs.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	deviceID   = "/opt/homebrew/bin/idevice_id"
	deviceInfo = "/opt/homebrew/bin/ideviceinfo"
	devmode    = "/opt/homebrew/bin/idevicedevmodectl"
)

var udidLine = regexp.MustCompile(`^[0-9A-Fa-f-]{20,50}$`)

func call(path string, args ...string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = bytes.NewReader(nil)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil || ctx.Err() != nil || stdout.Len() > 4096 || stderr.Len() > 4096 {
		return nil, false
	}
	return stdout.Bytes(), true
}

func run() {
	result, ok := call(deviceID, "-n")
	if !ok {
		fmt.Println("DEVMODE network=unavailable tuple=unavailable status=unavailable")
		return
	}
	lines := strings.Split(strings.TrimSpace(string(result)), "\n")
	if len(result) == 0 || len(lines) == 0 || lines[0] == "" {
		fmt.Println("DEVMODE network=zero tuple=unavailable status=unavailable")
		return
	}
	if len(lines) != 1 || !udidLine.MatchString(lines[0]) {
		fmt.Println("DEVMODE network=ambiguous tuple=unavailable status=unavailable")
		return
	}
	udid := lines[0]
	product, okProduct := call(deviceInfo, "-n", "-s", "-u", udid, "-k", "ProductType")
	version, okVersion := call(deviceInfo, "-n", "-s", "-u", udid, "-k", "ProductVersion")
	model, okModel := call(deviceInfo, "-n", "-s", "-u", udid, "-k", "HardwareModel")
	if !okProduct || !okVersion || !okModel ||
		strings.TrimSpace(string(product)) != "iPad14,5" ||
		strings.TrimSpace(string(version)) != "17.0" ||
		strings.TrimSpace(string(model)) != "J620AP" {
		fmt.Println("DEVMODE network=one tuple=unverified status=unavailable")
		return
	}
	listing, ok := call(devmode, "-n", "-u", udid, "list")
	if !ok {
		fmt.Println("DEVMODE network=one tuple=matched status=unavailable")
		return
	}
	state := "unavailable"
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == udid {
			if fields[1] == "enabled" || fields[1] == "disabled" {
				state = fields[1]
			}
		}
	}
	fmt.Println("DEVMODE network=one tuple=matched status=" + state)
}

func main() {
	if len(os.Args) != 1 {
		fmt.Println("DEVMODE rejected")
		os.Exit(2)
	}
	run()
}
