// Check the ordinary-app admission install boundary over pinned iPad Wi-Fi SSH.
//
// This Mac program verifies the durable SSH identity, host pin, private Wi-Fi
// address, original ClientTruth backup, and exact repository device payload.
// Default mode sends only the read-only preflight to root Python and prints
// one fixed status line. Optional --stage rechecks that preflight and then
// exclusively creates one hash-verified archive in iPad Media. Optional
// --install rechecks the live profile and staged-app preconditions, then calls
// the exact TrollStore install helper once. That action can create app state
// and must be attested before launching any probe. An interrupted stage or
// install needs inspection before retry; device paths are in the ledger.
// The two --startup-* modes revalidate installed-code attestation and invoke
// only the exact hash-pinned executable with no arguments. The audited parser
// exits before any IOKit work or report write.
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
	"strconv"
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
	payloadPath = "scripts/ipad-hardware/device/u1-readonly-ordinary-admission-preflight.py"
	payloadSHA  = "1736607d3c5ce9490ef2a21721e8150583f3f3b0108ce8f55b68d7d5dc574eb5"
	backupDir   = privateDir + "/backups/clienttruth-before-toolbox-2026-10-30"
	archivePath = "build/ipad-hardware/mac2jb-u1-ordinary-admission.tipa"
	archiveSHA  = "7dd7817c863b7add70a8d13f3764b05db8d39837283706ceb99cef635cdec961"
	stagePath   = "scripts/ipad-hardware/device/u1-stage-ordinary-admission.py"
	stageSHA    = "61181781450bd356046292009f701c99816d071d29ab065e79434c0a9e2c0ed7"
	installPath = "scripts/ipad-hardware/device/u1-install-ordinary-admission.py"
	installSHA  = "e4dd38a36773449d79c265cc6e74cd35a12d9d096b5a6e9b38a24ce513bd6536"
	startupPath = "scripts/ipad-hardware/device/u1-readonly-ordinary-startup-check.py"
	startupSHA  = "ff102b3cf16b80c71fb649c0116f70d247dacf088c3c549837a65c9e41a75a0e"
	attestPath  = "scripts/ipad-hardware/validate-installed-ordinary-admission.py"
	attestSHA   = "dd6cf2507e224f3b12b17af6d3cf985a5d9b0a052d53f78ee90caaa9dee13906"
)

var resultLine = regexp.MustCompile(`^ORDINARY_PREFLIGHT profile=(unchanged|changed) app=(absent|present) toolbox=(absent|present) platform=(absent|present) helper=present stage=(absent|present)$`)
var countLine = regexp.MustCompile(`^ORDINARY_COUNTS store=(0|1|many) toolbox=(0|1|many) platform=(0|1|many) ordinary=(0|1|many)\n$`)
var installReceipt = regexp.MustCompile(`^ORDINARY_INSTALL helper=0\nORDINARY_INSTALL profile=unchanged\nORDINARY_INSTALL app=one\nORDINARY_INSTALL toolbox=(zero|one)\nORDINARY_INSTALL platform=(zero|one)\n$`)

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

func run(mode string) error {
	key := filepath.Join(privateDir, keyName)
	host := filepath.Join(privateDir, hostName)
	if _, err := checked(key, keySHA, 0600); err != nil {
		return err
	}
	if _, err := checked(host, hostSHA, 0600); err != nil {
		return err
	}
	payload, err := checked(payloadPath, payloadSHA, 0)
	if err != nil || len(payload) > 8192 {
		return errors.New("unexpected device payload")
	}
	original, err := originalDigest()
	if err != nil {
		return err
	}
	ip, err := address()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		"-T", "-p", "22", "root@" + ip,
		"/var/jb/usr/bin/python3 -I -S -B - " + original}
	command := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	command.Stdin = bytes.NewReader(payload)
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 && exit.ExitCode() <= 255 {
			if exit.ExitCode() == 68 && len(output) <= 128 && countLine.Match(output) {
				fmt.Print(string(output))
			}
			return fmt.Errorf("device preflight exit=%d", exit.ExitCode())
		}
		return errors.New("device preflight transport failed")
	}
	if len(output) > 256 || !bytes.HasSuffix(output, []byte{'\n'}) {
		return errors.New("device preflight failed")
	}
	line := strings.TrimSuffix(string(output), "\n")
	if !resultLine.MatchString(line) {
		return errors.New("invalid preflight result")
	}
	fmt.Println(line)
	if mode == "preflight" {
		return nil
	}
	if strings.HasPrefix(mode, "startup-") {
		if !strings.HasPrefix(line, "ORDINARY_PREFLIGHT profile=unchanged app=present ") ||
			!strings.HasSuffix(line, "helper=present stage=present") {
			return errors.New("startup preconditions not met")
		}
		if _, err := checked(attestPath, attestSHA, 0); err != nil {
			return errors.New("attestation source changed")
		}
		verifyContext, stopVerify := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopVerify()
		verify := exec.CommandContext(verifyContext, "/opt/homebrew/bin/python3", "-I", "-S", "-B", attestPath, "--check")
		verify.Stderr = io.Discard
		verified, err := verify.Output()
		if err != nil || string(verified) != "ORDINARY_ATTEST code=matched entitlements=matched layout=exact\n" {
			return errors.New("installed code or entitlement attestation failed")
		}
		source, err := checked(startupPath, startupSHA, 0)
		if err != nil || len(source) > 8192 {
			return errors.New("unexpected startup payload")
		}
		variant := strings.TrimPrefix(mode, "startup-")
		startupContext, stopStartup := context.WithTimeout(context.Background(), 12*time.Second)
		defer stopStartup()
		args[len(args)-2] = "mobile@" + ip
		args[len(args)-1] = "/var/jb/usr/bin/python3 -I -S -B - " + variant
		startup := exec.CommandContext(startupContext, "/usr/bin/ssh", args...)
		startup.Stdin = bytes.NewReader(source)
		startup.Stderr = io.Discard
		statusOutput, err := startup.Output()
		if err != nil || len(statusOutput) > 128 || !bytes.HasSuffix(statusOutput, []byte{'\n'}) ||
			bytes.Count(statusOutput, []byte{'\n'}) != 1 {
			return errors.New("startup status unavailable")
		}
		statusLine := strings.TrimSuffix(string(statusOutput), "\n")
		prefix := "ORDINARY_STARTUP variant=" + variant + " status="
		if !strings.HasPrefix(statusLine, prefix) {
			return errors.New("startup status grammar mismatch")
		}
		status := strings.TrimPrefix(statusLine, prefix)
		if status != "timeout" {
			value, err := strconv.Atoi(status)
			if err != nil || value < -255 || value > 255 {
				return errors.New("startup status out of range")
			}
		}
		fmt.Println(statusLine)
		return nil
	}
	if mode == "install" {
		if !strings.HasPrefix(line, "ORDINARY_PREFLIGHT profile=unchanged app=absent ") ||
			!strings.HasSuffix(line, "helper=present stage=present") {
			return errors.New("install preconditions not met")
		}
		installer, err := checked(installPath, installSHA, 0)
		if err != nil || len(installer) > 8192 {
			return errors.New("unexpected installer payload")
		}
		installContext, stopInstall := context.WithTimeout(context.Background(), 110*time.Second)
		defer stopInstall()
		args[len(args)-1] = "/var/jb/usr/bin/python3 -I -S -B - " + original
		installCommand := exec.CommandContext(installContext, "/usr/bin/ssh", args...)
		installCommand.Stdin = bytes.NewReader(installer)
		installCommand.Stderr = io.Discard
		installOutput, err := installCommand.Output()
		if err != nil || len(installOutput) > 256 || !installReceipt.Match(installOutput) {
			return errors.New("install result uncertain; inspect app and profile before retry")
		}
		fmt.Print(string(installOutput))
		return nil
	}
	if !strings.HasPrefix(line, "ORDINARY_PREFLIGHT profile=unchanged app=absent ") ||
		!strings.HasSuffix(line, "helper=present stage=absent") {
		return errors.New("stage preconditions not met")
	}
	archive, err := checked(archivePath, archiveSHA, 0)
	if err != nil || len(archive) != 232249 {
		return errors.New("unexpected admission archive")
	}
	stageSource, err := checked(stagePath, stageSHA, 0)
	if err != nil || len(stageSource) > 8192 {
		return errors.New("unexpected stage payload")
	}
	stageContext, stopStage := context.WithTimeout(context.Background(), 25*time.Second)
	defer stopStage()
	args[len(args)-1] = "/var/jb/usr/bin/python3 -I -S -B -c " + shellQuote(string(stageSource))
	staging := exec.CommandContext(stageContext, "/usr/bin/ssh", args...)
	staging.Stdin = bytes.NewReader(archive)
	staging.Stderr = io.Discard
	stageOutput, err := staging.Output()
	if err != nil || string(stageOutput) != "ORDINARY_STAGE verified\n" {
		return errors.New("stage result uncertain; inspect fixed Media path before retry")
	}
	fmt.Print(string(stageOutput))
	return nil
}

func main() {
	mode := "preflight"
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--stage":
			mode = "stage"
		case "--install":
			mode = "install"
		case "--startup-ordinary-baseline":
			mode = "startup-ordinary-baseline"
		case "--startup-ordinary-setdescription":
			mode = "startup-ordinary-setdescription"
		default:
			fmt.Println("ORDINARY_FLOW rejected")
			os.Exit(2)
		}
	} else if len(os.Args) > 2 {
		fmt.Println("ORDINARY_FLOW rejected")
		os.Exit(2)
	}
	if err := run(mode); err != nil {
		fmt.Println("ORDINARY_FLOW rejected:", err)
		os.Exit(1)
	}
}
