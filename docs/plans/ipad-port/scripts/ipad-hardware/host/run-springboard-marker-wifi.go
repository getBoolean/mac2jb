// Stage and install one exact U1 SpringBoard launch-marker app over pinned Wi-Fi.
//
// Default mode is read-only. --stage exclusively creates one fixed Media IPA
// after a clean preflight. --install invokes the fixed TrollStore helper once
// after a verified stage and unchanged backed-up ClientTruth profile. All
// source, package, SSH identity, host pin, and private backup bytes are checked.
// The marker code itself is not launched by this runner. Device changes and
// exact cleanup identities are recorded in docs/ipad/device-cleanup-ledger.md.
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
	privateDir    = "/Users/boolean/.ssh/mac2jb-ipad"
	keyName       = "mac2jb-ipad-probe-ed25519"
	hostName      = "mac2jb-ipad-known-hosts"
	keySHA        = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA       = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	backupDir     = privateDir + "/backups/clienttruth-before-toolbox-2026-10-30"
	packagePath   = "build/ipad-hardware/mac2jb-u1-springboard-marker.tipa"
	packageSHA    = "2f76c3dca4ea0b19fa352fc274f1bfd5b65a9fc74d39fcd70247e65852965c72"
	preflightPath = "scripts/ipad-hardware/device/u1-readonly-springboard-marker-preflight.py"
	preflightSHA  = "79bf54f71f8d2f999765efe5dcc99ef1178f57ade9825b1ea01b8276ab77c275"
	stagePath     = "scripts/ipad-hardware/device/u1-stage-springboard-marker.py"
	stageSHA      = "d1b3cf734eaf6d605e79085aa0d32e3eccb72c90584ea3e156ae2c0d753e53bb"
	installPath   = "scripts/ipad-hardware/device/u1-install-springboard-marker.py"
	installSHA    = "a33b09e33478efa9142c3d530701deea55cee64d9a5282be842af3561dd5c6fb"
	receiptPath   = "scripts/ipad-hardware/device/u1-readonly-springboard-marker-receipt.py"
	receiptSHA    = "e8cb193cf80126e7b42215400235c3ff41df75d0a49d5cca92db24906ee3711f"
	launchPath    = "scripts/ipad-hardware/device/u1-launch-springboard-marker.py"
	launchSHA     = "2b112dff2c705c238177fcdf36889c3011ef124b0e7a87667eff57116c238a37"
	directPath    = "scripts/ipad-hardware/device/u1-direct-launch-springboard-marker.py"
	directSHA     = "40f9c9375148eb0baad5c980e5a6f4fa33478b4e6fe42bc6ad4f0430b8cf9f08"
	validatorPath = "scripts/ipad-hardware/validate-installed-springboard-marker.py"
	validatorSHA  = "aa969d2f2c462959077140dd17963670916d503eea68346cdb4b1aa7f6149e80"
	manifestPath  = "build/ipad-hardware/installed-springboard-marker-attestation.json"
)

var preflightLine = regexp.MustCompile(`^MARKER_PREFLIGHT profile=(unchanged|changed) store=(zero|one|many|other) ordinary=(zero|one|many|other) marker=(zero|one|many|other) stage=(absent|verified|other)$`)
var receiptLine = regexp.MustCompile(`^MARKER_RECEIPT container=(absent|one|many|too-many) receipt=(absent|verified|other|unknown)$`)

func checked(path, expected string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 ||
		(private && info.Mode().Perm() != 0600) {
		return nil, errors.New("unsafe local input")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if expected != "" {
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != expected {
			return nil, errors.New("local digest mismatch")
		}
	}
	return data, nil
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
	metadata, err := checked(filepath.Join(backupDir, "metadata.json"), "", true)
	if err != nil || len(metadata) > 4096 {
		return "", errors.New("unsafe backup metadata")
	}
	var record struct {
		Verified bool `json:"verified"`
		Remote   struct {
			SHA256 string `json:"sha256"`
		} `json:"remote"`
	}
	if err := json.Unmarshal(metadata, &record); err != nil || !record.Verified || len(record.Remote.SHA256) != 64 {
		return "", errors.New("unverified backup")
	}
	for _, char := range record.Remote.SHA256 {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return "", errors.New("invalid backup digest")
		}
	}
	if _, err := checked(filepath.Join(backupDir, "ClientTruth.plist"), record.Remote.SHA256, true); err != nil {
		return "", errors.New("backup bytes changed")
	}
	if _, err := checked(filepath.Join(backupDir, "acl.txt"), "", true); err != nil {
		return "", errors.New("backup ACL missing")
	}
	return record.Remote.SHA256, nil
}

func address() (string, error) {
	data, err := checked(filepath.Join(privateDir, "wifi-ipv4"), "", true)
	if err != nil || len(data) < 8 || len(data) > 16 || bytes.Count(data, []byte{'\n'}) != 1 || !bytes.HasSuffix(data, []byte{'\n'}) {
		return "", errors.New("invalid private address")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", errors.New("noncanonical private address")
	}
	return value, nil
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func ssh(account, ip, key, host, remote string, stdin []byte, deadline time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	args := []string{"-F", "/dev/null", "-i", key,
		"-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=publickey", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
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
	output, err := command.Output()
	if err != nil || len(output) > 256 {
		return nil, errors.New("bounded device command failed")
	}
	return output, nil
}

func preflight(ip, key, host, original string, payload []byte) (string, error) {
	output, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - "+original, payload, 20*time.Second)
	if err != nil || !bytes.HasSuffix(output, []byte{'\n'}) || bytes.Count(output, []byte{'\n'}) != 1 {
		return "", errors.New("marker preflight failed")
	}
	line := strings.TrimSuffix(string(output), "\n")
	if !preflightLine.MatchString(line) {
		return "", errors.New("invalid marker preflight")
	}
	return line, nil
}

func receipt(ip, key, host string) (string, error) {
	source, err := checked(receiptPath, receiptSHA, false)
	if err != nil || len(source) > 8192 {
		return "", errors.New("unexpected receipt source")
	}
	output, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B -", source, 20*time.Second)
	if err != nil || len(output) > 128 || bytes.Count(output, []byte{'\n'}) != 1 || !bytes.HasSuffix(output, []byte{'\n'}) {
		return "", errors.New("receipt query failed")
	}
	line := strings.TrimSuffix(string(output), "\n")
	if !receiptLine.MatchString(line) {
		return "", errors.New("invalid receipt result")
	}
	return line, nil
}

func attestedBinaryHash() (string, error) {
	if _, err := checked(validatorPath, validatorSHA, false); err != nil {
		return "", errors.New("attestation source changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/opt/homebrew/bin/python3", "-I", "-S", "-B", validatorPath, "--check")
	command.Stderr = io.Discard
	result, err := command.Output()
	if err != nil || string(result) != "MARKER_ATTEST code=matched entitlements=matched layout=exact\n" {
		return "", errors.New("installed marker attestation failed")
	}
	data, err := checked(manifestPath, "", true)
	if err != nil || len(data) > 4096 {
		return "", errors.New("unsafe marker manifest")
	}
	var record struct {
		Status    string `json:"status"`
		BinarySHA string `json:"binarySha256"`
	}
	if err := json.Unmarshal(data, &record); err != nil || record.Status != "installed-code-and-entitlements-matched" || len(record.BinarySHA) != 64 {
		return "", errors.New("invalid marker manifest")
	}
	for _, char := range record.BinarySHA {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return "", errors.New("invalid marker binary digest")
		}
	}
	return record.BinarySHA, nil
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
	original, err := originalDigest()
	if err != nil {
		return err
	}
	ip, err := address()
	if err != nil {
		return err
	}
	payload, err := checked(preflightPath, preflightSHA, false)
	if err != nil || len(payload) > 8192 {
		return errors.New("unexpected preflight source")
	}
	before, err := preflight(ip, key, host, original, payload)
	if err != nil {
		return err
	}
	fmt.Println(before)
	if mode == "preflight" {
		return nil
	}
	if mode == "receipt" {
		line, err := receipt(ip, key, host)
		if err != nil {
			return err
		}
		fmt.Println(line)
		return nil
	}
	if mode == "launch" {
		if before != "MARKER_PREFLIGHT profile=unchanged store=one ordinary=one marker=one stage=verified" {
			return errors.New("launch preconditions not met")
		}
		binarySHA, err := attestedBinaryHash()
		if err != nil {
			return err
		}
		prior, err := receipt(ip, key, host)
		if err != nil || prior != "MARKER_RECEIPT container=one receipt=absent" {
			return errors.New("clean receipt precondition not met")
		}
		fmt.Println(prior)
		source, err := checked(launchPath, launchSHA, false)
		if err != nil || len(source) > 8192 {
			return errors.New("unexpected launch source")
		}
		output, err := ssh("mobile", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - "+binarySHA, source, 20*time.Second)
		if err != nil || string(output) != "MARKER_LAUNCH status=accepted\n" {
			return errors.New("launch request not accepted")
		}
		fmt.Print(string(output))
		for attempt := 0; attempt < 3; attempt++ {
			line, err := receipt(ip, key, host)
			if err != nil {
				return err
			}
			if line == "MARKER_RECEIPT container=one receipt=verified" {
				fmt.Println(line)
				return nil
			}
			if attempt == 2 {
				fmt.Println(line)
				return nil
			}
			time.Sleep(time.Second)
		}
		return errors.New("receipt polling invariant")
	}
	if mode == "direct" {
		if before != "MARKER_PREFLIGHT profile=unchanged store=one ordinary=one marker=one stage=verified" {
			return errors.New("direct-launch preconditions not met")
		}
		binarySHA, err := attestedBinaryHash()
		if err != nil {
			return err
		}
		source, err := checked(directPath, directSHA, false)
		if err != nil || len(source) > 8192 {
			return errors.New("unexpected direct-launch source")
		}
		output, err := ssh("mobile", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - "+binarySHA, source, 12*time.Second)
		if err != nil || (string(output) != "MARKER_DIRECT status=0\n" &&
			string(output) != "MARKER_DIRECT status=66\n" &&
			string(output) != "MARKER_DIRECT status=-9\n" &&
			string(output) != "MARKER_DIRECT status=other\n" &&
			string(output) != "MARKER_DIRECT status=timeout\n") {
			return errors.New("direct-launch result unavailable")
		}
		fmt.Print(string(output))
		return nil
	}
	if mode == "stage" {
		if before != "MARKER_PREFLIGHT profile=unchanged store=one ordinary=one marker=zero stage=absent" {
			return errors.New("stage preconditions not met")
		}
		archive, err := checked(packagePath, packageSHA, true)
		if err != nil || len(archive) != 4074 {
			return errors.New("unexpected marker package")
		}
		source, err := checked(stagePath, stageSHA, false)
		if err != nil || len(source) > 8192 {
			return errors.New("unexpected stage source")
		}
		output, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B -c "+quote(string(source)), archive, 25*time.Second)
		if err != nil || string(output) != "MARKER_STAGE verified\n" {
			return errors.New("stage uncertain; inspect before retry")
		}
		fmt.Print(string(output))
		after, err := preflight(ip, key, host, original, payload)
		if err != nil || after != "MARKER_PREFLIGHT profile=unchanged store=one ordinary=one marker=zero stage=verified" {
			return errors.New("post-stage state uncertain")
		}
		fmt.Println(after)
		return nil
	}
	if before != "MARKER_PREFLIGHT profile=unchanged store=one ordinary=one marker=zero stage=verified" {
		return errors.New("install preconditions not met")
	}
	source, err := checked(installPath, installSHA, false)
	if err != nil || len(source) > 8192 {
		return errors.New("unexpected install source")
	}
	output, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - "+original, source, 110*time.Second)
	if err != nil || string(output) != "MARKER_INSTALL helper=0 profile=unchanged app=one\n" {
		return errors.New("install uncertain; inspect before retry")
	}
	fmt.Print(string(output))
	after, err := preflight(ip, key, host, original, payload)
	if err != nil || after != "MARKER_PREFLIGHT profile=unchanged store=one ordinary=one marker=one stage=verified" {
		return errors.New("post-install state uncertain")
	}
	fmt.Println(after)
	return nil
}

func main() {
	mode := "preflight"
	if len(os.Args) == 2 && os.Args[1] == "--stage" {
		mode = "stage"
	} else if len(os.Args) == 2 && os.Args[1] == "--install" {
		mode = "install"
	} else if len(os.Args) == 2 && os.Args[1] == "--receipt" {
		mode = "receipt"
	} else if len(os.Args) == 2 && os.Args[1] == "--launch" {
		mode = "launch"
	} else if len(os.Args) == 2 && os.Args[1] == "--direct" {
		mode = "direct"
	} else if len(os.Args) != 1 {
		fmt.Println("MARKER_FLOW rejected")
		os.Exit(2)
	}
	if err := run(mode); err != nil {
		fmt.Println("MARKER_FLOW rejected")
		os.Exit(1)
	}
}
