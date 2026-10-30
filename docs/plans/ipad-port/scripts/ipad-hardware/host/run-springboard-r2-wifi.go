// Preflight, stage, or install one of two fixed SpringBoard R2 apps over pinned Wi-Fi.
//
// This Mac runner checks the durable SSH key, host pin, private address,
// original ClientTruth backup, exact device helper, and exact local IPA bytes.
// Preflight reads only. Stage creates one fixed Media archive exclusively and
// verifies full readback. Install invokes TrollStore once for the exact staged
// app after a fresh profile/app check. It never launches probe code. All
// persistent target paths and cleanup conditions are in the device ledger.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	privateDir  = "/Users/boolean/.ssh/mac2jb-ipad"
	keyName     = "mac2jb-ipad-probe-ed25519"
	hostName    = "mac2jb-ipad-known-hosts"
	keySHA      = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA     = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	backupDir   = privateDir + "/backups/clienttruth-before-toolbox-2026-10-30"
	payloadPath = "scripts/ipad-hardware/device/u1-springboard-r2-stage-install.py"
	payloadSHA  = "b84aa3ce623bfdf67a228b376dbcf782b77322e68d04f9b3cdfb593ad11e4630"
)

type profile struct {
	name, path, digest string
	size               int
}

var profiles = map[string]profile{
	"baseline":       {"baseline", "build/ipad-hardware/mac2jb-u1-springboard-r2-baseline.tipa", "565ad2fd8b4d90130fd29e562ad446911a5364be67f7c8e1b3547b43b8f06c1a", 109249},
	"setdescription": {"setdescription", "build/ipad-hardware/mac2jb-u1-springboard-r2-setdescription.tipa", "0424a37259f8c873d474dcd1965ccdcc386f0d39814f408869432f2aa235d65d", 109335},
}

var stateLine = regexp.MustCompile(`^SPRINGBOARD_R2_PREFLIGHT profile=(unchanged|changed) store=one baseline=(zero|one) setdescription=(zero|one) stage-baseline=(absent|verified|other) stage-setdescription=(absent|verified|other)$`)
var installLine = regexp.MustCompile(`^SPRINGBOARD_R2_INSTALL profile=(baseline|setdescription) helper=0 clienttruth=unchanged app=one other=(zero|one) stage=verified$`)

func checked(path, digest string, mode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) ||
		stat.Nlink != 1 || (mode != 0 && info.Mode().Perm() != mode) {
		return nil, errors.New("unsafe local input")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if digest != "" {
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != digest {
			return nil, errors.New("local digest mismatch")
		}
	}
	return data, nil
}

func address() (string, error) {
	data, err := checked(filepath.Join(privateDir, "wifi-ipv4"), "", 0600)
	if err != nil || len(data) < 8 || len(data) > 16 ||
		!bytes.HasSuffix(data, []byte{'\n'}) || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", errors.New("invalid private address file")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", errors.New("invalid private address")
	}
	return value, nil
}

func originalDigest() (string, error) {
	info, err := os.Lstat(backupDir)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		return "", errors.New("unsafe backup directory")
	}
	meta, err := checked(filepath.Join(backupDir, "metadata.json"), "", 0600)
	if err != nil || len(meta) > 4096 {
		return "", errors.New("unsafe backup metadata")
	}
	var record struct {
		Verified bool `json:"verified"`
		Remote   struct {
			SHA256 string `json:"sha256"`
		} `json:"remote"`
	}
	if err := json.Unmarshal(meta, &record); err != nil || !record.Verified ||
		len(record.Remote.SHA256) != 64 {
		return "", errors.New("unverified backup metadata")
	}
	for _, c := range record.Remote.SHA256 {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", errors.New("invalid backup digest")
		}
	}
	if _, err := checked(filepath.Join(backupDir, "ClientTruth.plist"), record.Remote.SHA256, 0600); err != nil {
		return "", errors.New("original backup bytes mismatch")
	}
	if _, err := checked(filepath.Join(backupDir, "acl.txt"), "", 0600); err != nil {
		return "", errors.New("backup ACL missing")
	}
	return record.Remote.SHA256, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func ssh(account, ip, key, host, remote string, stdin []byte, limit time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
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
		"-T", "-p", "22", account + "@" + ip, remote}
	command := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	command.Stdin = bytes.NewReader(stdin)
	command.Stderr = io.Discard
	out, err := command.Output()
	if err != nil || ctx.Err() != nil || len(out) > 512 {
		return nil, errors.New("bounded pinned SSH command failed")
	}
	return out, nil
}

func preflight(ip, key, host, original string, source []byte) (string, error) {
	output, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - preflight "+original, source, 20*time.Second)
	if err != nil || len(output) > 256 || bytes.Count(output, []byte{'\n'}) != 1 || !bytes.HasSuffix(output, []byte{'\n'}) {
		return "", errors.New("R2 preflight failed")
	}
	line := strings.TrimSuffix(string(output), "\n")
	if !stateLine.MatchString(line) {
		return "", errors.New("R2 preflight result invalid")
	}
	return line, nil
}

func category(line, key string) string {
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, key+"=") {
			return strings.TrimPrefix(field, key+"=")
		}
	}
	return ""
}

func run(action, label string) error {
	key := filepath.Join(privateDir, keyName)
	host := filepath.Join(privateDir, hostName)
	if _, err := checked(key, keySHA, 0600); err != nil {
		return err
	}
	if _, err := checked(host, hostSHA, 0600); err != nil {
		return err
	}
	source, err := checked(payloadPath, payloadSHA, 0)
	if err != nil || len(source) > 16384 {
		return errors.New("device helper changed or too large")
	}
	original, err := originalDigest()
	if err != nil {
		return err
	}
	ip, err := address()
	if err != nil {
		return err
	}
	before, err := preflight(ip, key, host, original, source)
	if err != nil {
		return err
	}
	fmt.Println(before)
	if action == "preflight" {
		return nil
	}
	selected := profiles[label]
	other := "setdescription"
	if label == "setdescription" {
		other = "baseline"
	}
	if category(before, "profile") != "unchanged" || category(before, label) != "zero" ||
		category(before, "stage-"+label) != map[string]string{"stage": "absent", "install": "verified"}[action] {
		return errors.New("R2 action preconditions not met")
	}
	priorOther := category(before, other)
	if action == "stage" {
		archive, err := checked(selected.path, selected.digest, 0)
		if err != nil || len(archive) != selected.size {
			return errors.New("R2 local IPA changed")
		}
		remote := "/var/jb/usr/bin/python3 -I -S -B -c " + shellQuote(string(source)) + " stage " + label + " " + original
		output, err := ssh("root", ip, key, host, remote, archive, 30*time.Second)
		if err != nil || string(output) != "SPRINGBOARD_R2_STAGE profile="+label+" verified\n" {
			return errors.New("R2 stage uncertain; inspect before retry")
		}
		fmt.Print(string(output))
	} else {
		remote := "/var/jb/usr/bin/python3 -I -S -B - install " + label + " " + original
		output, err := ssh("root", ip, key, host, remote, source, 110*time.Second)
		if err != nil || len(output) > 256 || !bytes.HasSuffix(output, []byte{'\n'}) ||
			!installLine.Match(bytes.TrimSuffix(output, []byte{'\n'})) ||
			category(strings.TrimSpace(string(output)), "profile") != label ||
			category(strings.TrimSpace(string(output)), "other") != priorOther {
			return errors.New("R2 install uncertain; inspect before retry")
		}
		fmt.Print(string(output))
	}
	after, err := preflight(ip, key, host, original, source)
	if err != nil || category(after, "profile") != "unchanged" || category(after, other) != priorOther ||
		category(after, label) != map[string]string{"stage": "zero", "install": "one"}[action] ||
		category(after, "stage-"+label) != "verified" {
		return errors.New("R2 post-action state uncertain")
	}
	fmt.Println(after)
	return nil
}

func main() {
	action, label := "preflight", ""
	if len(os.Args) == 3 && (os.Args[1] == "--stage" || os.Args[1] == "--install") {
		action = strings.TrimPrefix(os.Args[1], "--")
		label = os.Args[2]
		if _, ok := profiles[label]; !ok {
			fmt.Println("SPRINGBOARD_R2_FLOW rejected")
			os.Exit(2)
		}
	} else if len(os.Args) != 1 {
		fmt.Println("SPRINGBOARD_R2_FLOW rejected")
		os.Exit(2)
	}
	if err := run(action, label); err != nil {
		fmt.Println("SPRINGBOARD_R2_FLOW rejected:", err)
		os.Exit(1)
	}
}
