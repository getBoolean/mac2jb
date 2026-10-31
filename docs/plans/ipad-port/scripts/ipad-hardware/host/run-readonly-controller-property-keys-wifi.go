// Run bounded read-only controller, device-tree, or battery-state probes over pinned Wi-Fi SSH.
//
// This Mac program verifies the exact repository payload, durable Mac SSH key,
// original host pin, and private Wi-Fi address. It sends the payload to the
// iPad's installed Python interpreter as root, with a bounded SSH session.
// It accepts only categorical output and filtered property names. It writes
// no iPad file and never changes USB, SSH, registry, or trust configuration.
// The --interpreter-entitlements mode runs as mobile to classify the installed
// Python process before considering it for a no-private-entitlement U1 probe.
// The --admission-smoke-launch mode verifies and launches a fixed marker-only
// C executable as mobile; that executable makes no USB or file changes.
// The --admission-platform-control-launch mode runs the same C code signed
// with only platform-application, isolating the signing/launch path.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	privateDir        = "/Users/boolean/.ssh/mac2jb-ipad"
	keyName           = "mac2jb-ipad-probe-ed25519"
	hostName          = "mac2jb-ipad-known-hosts"
	keySHA            = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA           = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	payloadPath       = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-controller-property-keys.py"
	payloadSHA        = "97b6cbf1f71195644a4dc35a7992fca9fc999b0924373f348481eb90ab4901ed"
	busPath           = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-controller-bus-state.py"
	busSHA            = "ad08e9ae85147610d88d11bfd1c31de890904b6d1edf7551a919364cc88584da"
	descPath          = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-controller-description-types.py"
	descSHA           = "00f254119c926c8649fbeb7dadf15e0fc048762b4cfd5c1fab38566300afc253"
	configPath        = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-device-tree-configuration-string.py"
	configSHA         = "07ddf5d2600df1deab4d4bf153abd9223b397bddf55130526f63cb91cb882f65"
	powerPath         = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-power-source-state.py"
	powerSHA          = "c0ab521efcdfa52b96ac8a1c4e6a8d3cd76a4aad145a32c7528a176fe1d7f677"
	interpPath        = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-interpreter-entitlements.py"
	interpSHA         = "9d491fb3b262414a909d69c80175c177f4623b5352425f93bcce38bfbbd0fca1"
	smokePath         = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-admission-smoke-launch.py"
	smokeSHA          = "6c4d0ef9ad6cdc7f4e3e426482277a97b803b482133f94ac69ea447ecbca6a14"
	controlPath       = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-admission-platform-control-launch.py"
	controlSHA        = "d58610de2b3922d006dd33e024f7b6d0f7047001a6a88d7f5bc97be3c3aca384"
	inventoryPath     = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-probe-app-inventory.py"
	inventorySHA      = "7588740c84615939d080e0adebf07fff787926c5f718afe5b6517254863dc757"
	ordinaryCrashPath = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-ordinary-crash-classifier.py"
	ordinaryCrashSHA  = "13e9cb9708cc338d08c692a40428c38fe88785d06e416e3b55d33f29b82cb829"
	debugCrashPath    = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-debug-ordinary-crash-classifier.py"
	debugCrashSHA     = "b6d3b5627d1caada76fedc54c50eaf705c67512c0081dbffc24741348a127f29"
	ordinaryUIPath    = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-launch-ordinary-via-uiopen.py"
	ordinaryUISHA     = "e90b3f74ba471968460076fcdb1116a74a365fd88da1317dd50b116430cab723"
	uiopenUsagePath   = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-uiopen-usage.py"
	uiopenUsageSHA    = "f5c676d49cdc6b9ddac1a5c8db9356cfee1f2aa242280f46e747818a4cc635f6"
)

var (
	header            = regexp.MustCompile(`^CONTROLLER_KEYS query=ok services=[0-4] matching-keys=([0-9]{1,2})$`)
	keyLine           = regexp.MustCompile(`^CONTROLLER_KEY [A-Za-z0-9 ._/-]{1,127}$`)
	busLine           = regexp.MustCompile(`^CONTROLLER_BUS query=ok state=(disconnected|attached|powered|default|addressed|configured|suspended|other|unknown) onbus=(yes|no|unknown) speed=(unknown|other|[0-9]{1,6}) config=(unknown|other|[0-9]{1,3})$`)
	descLine          = regexp.MustCompile(`^DESCRIPTION_TYPES query=ok default=(absent|unavailable|other|(dict|array|data|string):([0-9]{1,4}|large)) live=(absent|unavailable|other|(dict|array|data|string):([0-9]{1,4}|large))$`)
	powerLine         = regexp.MustCompile(`^POWER_SOURCE query=ok external=(yes|no|unknown) charging=(yes|no|unknown) full=(yes|no|unknown)$`)
	interpLine        = regexp.MustCompile(`^INTERPRETER_ENTITLEMENTS query=ok platform=(yes|no|unknown) setdescription=(yes|no|unknown) userclient=(yes|no|unknown) no-sandbox=(yes|no|unknown)$`)
	inventoryLine     = regexp.MustCompile(`^APP_INVENTORY query=ok store=(0|1|many) toolbox=(0|1|many) platform=(0|1|many) ordinary=(0|1|many)$`)
	ordinaryCrashLine = regexp.MustCompile(`^ORDINARY_CRASH query=ok truncated=(yes|no) named=([0-9]{1,2}) matching=([0-9]{1,2}) codesign=([0-9]{1,2}) amfi=([0-9]{1,2}) jetsam=([0-9]{1,2}) kill=([0-9]{1,2})$`)
	debugCrashLine    = regexp.MustCompile(`^DEBUG_ORDINARY_CRASH query=ok truncated=(yes|no) named=([0-9]{1,2}) matching=([0-9]{1,2}) codesign=([0-9]{1,2}) amfi=([0-9]{1,2}) jetsam=([0-9]{1,2}) kill=([0-9]{1,2})$`)
)

func checked(path, digest string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("unsafe local file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0600 {
			return nil, fmt.Errorf("unsafe private file")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != digest {
		return nil, fmt.Errorf("local digest mismatch")
	}
	return data, nil
}

func address() (string, error) {
	path := filepath.Join(privateDir, "wifi-ipv4")
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) ||
		stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() > 16 {
		return "", fmt.Errorf("unsafe private address")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 7 || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", fmt.Errorf("invalid private address")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", fmt.Errorf("nonprivate or noncanonical address")
	}
	return value, nil
}

func run(mode string) error {
	key := filepath.Join(privateDir, keyName)
	host := filepath.Join(privateDir, hostName)
	if _, err := checked(key, keySHA, true); err != nil {
		return err
	}
	if _, err := checked(host, hostSHA, true); err != nil {
		return err
	}
	path, digest := payloadPath, payloadSHA
	if mode == "bus" {
		path, digest = busPath, busSHA
	} else if mode == "descriptions" {
		path, digest = descPath, descSHA
	} else if mode == "configuration-string" {
		path, digest = configPath, configSHA
	} else if mode == "power" {
		path, digest = powerPath, powerSHA
	} else if mode == "interpreter-entitlements" {
		path, digest = interpPath, interpSHA
	} else if mode == "admission-smoke-launch" {
		path, digest = smokePath, smokeSHA
	} else if mode == "admission-platform-control-launch" {
		path, digest = controlPath, controlSHA
	} else if mode == "probe-app-inventory" {
		path, digest = inventoryPath, inventorySHA
	} else if mode == "ordinary-crash" {
		path, digest = ordinaryCrashPath, ordinaryCrashSHA
	} else if mode == "debug-ordinary-crash" {
		path, digest = debugCrashPath, debugCrashSHA
	} else if mode == "ordinary-uiopen" {
		path, digest = ordinaryUIPath, ordinaryUISHA
	} else if mode == "uiopen-usage" {
		path, digest = uiopenUsagePath, uiopenUsageSHA
	}
	payload, err := checked(path, digest, false)
	if err != nil {
		return err
	}
	ip, err := address()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	account := "root"
	if mode == "interpreter-entitlements" || mode == "admission-smoke-launch" || mode == "admission-platform-control-launch" || mode == "ordinary-uiopen" || mode == "uiopen-usage" {
		account = "mobile"
	}
	args := []string{"-F", "/dev/null", "-i", key,
		"-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + host,
		"-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
		"-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
		"-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "PermitLocalCommand=no",
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=5",
		"-o", "ConnectionAttempts=1", "-o", "LogLevel=ERROR",
		"-o", "HostKeyAlias=[127.0.0.1]:2222", "-o", "AddressFamily=inet",
		"-T", "-p", "22", account + "@" + ip, "/var/jb/usr/bin/python3 -I -S -B -"}
	command := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	command.Stdin = bytes.NewReader(payload)
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil || len(output) > 8192 || !bytes.HasSuffix(output, []byte{'\n'}) {
		return fmt.Errorf("bounded device query failed")
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if mode == "uiopen-usage" {
		if len(lines) != 5 || len(output) > 160 ||
			!regexp.MustCompile(`^UIOPEN_USAGE status=(-?[0-9]{1,3}|timeout)$`).MatchString(lines[0]) {
			return fmt.Errorf("invalid uiopen usage status")
		}
		for index, label := range []string{"usage", "url", "bundle", "path"} {
			if lines[index+1] != "UIOPEN_USAGE "+label+"=yes" && lines[index+1] != "UIOPEN_USAGE "+label+"=no" {
				return fmt.Errorf("invalid uiopen usage field")
			}
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	}
	if mode == "ordinary-uiopen" {
		if len(lines) != 1 || len(output) > 64 ||
			(lines[0] != "ORDINARY_UIOPEN status=accepted" &&
				lines[0] != "ORDINARY_UIOPEN status=rejected" &&
				lines[0] != "ORDINARY_UIOPEN status=timeout") {
			return fmt.Errorf("invalid ordinary launch result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "ordinary-crash" {
		if len(lines) != 1 || len(output) > 160 ||
			(!ordinaryCrashLine.MatchString(lines[0]) && lines[0] != "ORDINARY_CRASH query=too-many-entries") {
			return fmt.Errorf("invalid ordinary crash result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "debug-ordinary-crash" {
		if len(lines) != 1 || len(output) > 160 ||
			(!debugCrashLine.MatchString(lines[0]) && lines[0] != "DEBUG_ORDINARY_CRASH query=too-many-entries") {
			return fmt.Errorf("invalid debug ordinary crash result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "probe-app-inventory" {
		if len(lines) != 1 || len(output) > 128 ||
			(!inventoryLine.MatchString(lines[0]) && lines[0] != "APP_INVENTORY query=too-many") {
			return fmt.Errorf("invalid app inventory result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "admission-smoke-launch" || mode == "admission-platform-control-launch" {
		if len(lines) != 1 || len(output) > 96 {
			return fmt.Errorf("invalid admission smoke result length")
		}
		allowed := map[string]bool{
			"SMOKE_RUN rejected": true, "SMOKE_RUN timeout": true,
			"SMOKE_RUN launch-error": true, "SMOKE_RUN reached-main": true,
			"SMOKE_RUN signal-9": true, "SMOKE_RUN other": true,
		}
		if !allowed[lines[0]] {
			return fmt.Errorf("invalid admission smoke result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "interpreter-entitlements" {
		if len(lines) != 1 || len(output) > 192 {
			return fmt.Errorf("invalid interpreter entitlement result length")
		}
		if !interpLine.MatchString(lines[0]) && lines[0] != "INTERPRETER_ENTITLEMENTS query=unavailable" && lines[0] != "INTERPRETER_ENTITLEMENTS query=task-unavailable" {
			return fmt.Errorf("invalid interpreter entitlement result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "power" {
		if len(lines) != 1 || len(output) > 128 {
			return fmt.Errorf("invalid power result length")
		}
		allowed := map[string]bool{
			"POWER_SOURCE query=matching-unavailable":   true,
			"POWER_SOURCE query=matching-failed":        true,
			"POWER_SOURCE query=no-service":             true,
			"POWER_SOURCE query=multiple-services":      true,
			"POWER_SOURCE query=properties-unavailable": true,
		}
		if !allowed[lines[0]] && !powerLine.MatchString(lines[0]) {
			return fmt.Errorf("invalid power result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "configuration-string" {
		if len(lines) != 1 || len(output) > 128 {
			return fmt.Errorf("invalid configuration-string result length")
		}
		allowed := map[string]bool{
			"CONFIG_STRING query=root-unavailable":         true,
			"CONFIG_STRING query=key-unavailable":          true,
			"CONFIG_STRING query=ok result=absent":         true,
			"CONFIG_STRING query=ok result=present-string": true,
			"CONFIG_STRING query=ok result=present-other":  true,
		}
		if !allowed[lines[0]] {
			return fmt.Errorf("invalid configuration-string result")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "descriptions" {
		if len(lines) != 1 || len(output) > 512 {
			return fmt.Errorf("invalid description-type result length")
		}
		allowed := map[string]bool{
			"DESCRIPTION_TYPES query=matching-unavailable":   true,
			"DESCRIPTION_TYPES query=matching-failed":        true,
			"DESCRIPTION_TYPES query=no-service":             true,
			"DESCRIPTION_TYPES query=multiple-services":      true,
			"DESCRIPTION_TYPES query=properties-unavailable": true,
		}
		if !allowed[lines[0]] && !descLine.MatchString(lines[0]) {
			return fmt.Errorf("invalid description-type grammar")
		}
		fmt.Println(lines[0])
		return nil
	}
	if mode == "bus" {
		if len(lines) != 1 || len(output) > 512 {
			return fmt.Errorf("invalid bus-state result length")
		}
		allowed := map[string]bool{
			"CONTROLLER_BUS query=matching-unavailable":      true,
			"CONTROLLER_BUS query=matching-failed":           true,
			"CONTROLLER_BUS query=no-service":                true,
			"CONTROLLER_BUS query=multiple-services":         true,
			"CONTROLLER_BUS query=properties-unavailable":    true,
			"CONTROLLER_BUS query=current-state-unavailable": true,
		}
		if !allowed[lines[0]] && !busLine.MatchString(lines[0]) {
			return fmt.Errorf("invalid bus-state grammar")
		}
		fmt.Println(lines[0])
		return nil
	}
	if len(lines) < 1 || len(lines) > 49 {
		return fmt.Errorf("invalid result length")
	}
	if strings.HasPrefix(lines[0], "CONTROLLER_KEYS query=") && !strings.HasPrefix(lines[0], "CONTROLLER_KEYS query=ok") {
		if len(lines) != 1 {
			return fmt.Errorf("invalid failure grammar")
		}
		allowed := map[string]bool{
			"CONTROLLER_KEYS query=matching-unavailable":   true,
			"CONTROLLER_KEYS query=matching-failed":        true,
			"CONTROLLER_KEYS query=too-many-services":      true,
			"CONTROLLER_KEYS query=properties-unavailable": true,
			"CONTROLLER_KEYS query=too-many-properties":    true,
			"CONTROLLER_KEYS query=too-many-matching-keys": true,
		}
		if !allowed[lines[0]] {
			return fmt.Errorf("invalid failure category")
		}
		fmt.Println(lines[0])
		return nil
	}
	match := header.FindStringSubmatch(lines[0])
	if match == nil {
		return fmt.Errorf("invalid header")
	}
	count, err := strconv.Atoi(match[1])
	if err != nil || count != len(lines)-1 {
		return fmt.Errorf("property count mismatch")
	}
	for _, line := range lines[1:] {
		if !keyLine.MatchString(line) {
			return fmt.Errorf("invalid property name")
		}
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return nil
}

func main() {
	mode := "keys"
	if len(os.Args) == 2 && os.Args[1] == "--bus" {
		mode = "bus"
	} else if len(os.Args) == 2 && os.Args[1] == "--descriptions" {
		mode = "descriptions"
	} else if len(os.Args) == 2 && os.Args[1] == "--configuration-string" {
		mode = "configuration-string"
	} else if len(os.Args) == 2 && os.Args[1] == "--power" {
		mode = "power"
	} else if len(os.Args) == 2 && os.Args[1] == "--interpreter-entitlements" {
		mode = "interpreter-entitlements"
	} else if len(os.Args) == 2 && os.Args[1] == "--admission-smoke-launch" {
		mode = "admission-smoke-launch"
	} else if len(os.Args) == 2 && os.Args[1] == "--admission-platform-control-launch" {
		mode = "admission-platform-control-launch"
	} else if len(os.Args) == 2 && os.Args[1] == "--probe-app-inventory" {
		mode = "probe-app-inventory"
	} else if len(os.Args) == 2 && os.Args[1] == "--ordinary-crash" {
		mode = "ordinary-crash"
	} else if len(os.Args) == 2 && os.Args[1] == "--debug-ordinary-crash" {
		mode = "debug-ordinary-crash"
	} else if len(os.Args) == 2 && os.Args[1] == "--ordinary-uiopen" {
		mode = "ordinary-uiopen"
	} else if len(os.Args) == 2 && os.Args[1] == "--uiopen-usage" {
		mode = "uiopen-usage"
	} else if len(os.Args) != 1 {
		fmt.Println("CONTROLLER_QUERY rejected")
		os.Exit(2)
	}
	if err := run(mode); err != nil {
		fmt.Println("CONTROLLER_QUERY rejected")
		os.Exit(1)
	}
}
