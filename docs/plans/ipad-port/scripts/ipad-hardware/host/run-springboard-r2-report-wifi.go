// Launch and privately collect one attested SpringBoard R2 report over pinned Wi-Fi.
//
// This Mac runner checks exact SSH identity/host bytes, original ClientTruth
// backup, installed-code attestation, on-device profile/app state, and report
// absence before requesting one explicit bundle-ID launch. It captures only
// the exact app-owned report into an ignored mode-0600 local file. A clearN
// action validates the retained round N file, then deletes only its matching
// app-owned receipt so the next exclusive round can run. It never prints raw
// report bytes or changes USB, SSH, trust, or system settings.
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
	"strings"
	"syscall"
	"time"
)

const (
	privateDir          = "/Users/boolean/.ssh/mac2jb-ipad"
	keySHA              = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA             = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	statePath           = "scripts/ipad-hardware/device/u1-springboard-r2-stage-install.py"
	stateSHA            = "b84aa3ce623bfdf67a228b376dbcf782b77322e68d04f9b3cdfb593ad11e4630"
	reportPath          = "scripts/ipad-hardware/device/u1-springboard-r2-report.py"
	reportSHA           = "577c7bf640b8217d186cc7e7b5ae89775fedbb335572ab6b9b24d27947e6ae6b"
	launchPath          = "scripts/ipad-hardware/device/u1-launch-springboard-r2.py"
	launchSHA           = "95502c2ef4d5187da55de085d0b64758d6cbf499f02a9009ca062c1e7a428205"
	validatorPath       = "scripts/ipad-hardware/validate-installed-springboard-r2.py"
	validatorSHA        = "765399d551ca2ace9a6fdf4c5011475d94a22a26d5e2f6324d1ec026de604496"
	clearPath           = "scripts/ipad-hardware/device/u1-clear-springboard-r2-report.py"
	clearSHA            = "43c07693c77207a0199144ddd3a972d1a30373c72cde985b492d33de58f9da24"
	reportValidatorPath = "scripts/ipad-hardware/validate-springboard-r2-report.py"
	reportValidatorSHA  = "00a6ca00cde30be22d3a6257fafdeb4e11c9f3e3e8d6a65e17dc51cd3d25cc3d"
)

func checked(path, digest string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 || (private && info.Mode().Perm() != 0600) {
		return nil, errors.New("unsafe local input")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if digest != "" {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return nil, errors.New("local digest mismatch")
		}
	}
	return data, nil
}
func address() (string, error) {
	data, err := checked(filepath.Join(privateDir, "wifi-ipv4"), "", true)
	if err != nil || len(data) < 8 || len(data) > 16 || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", errors.New("invalid private address file")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", errors.New("invalid private address")
	}
	return value, nil
}
func original() (string, error) {
	dir := filepath.Join(privateDir, "backups/clienttruth-before-toolbox-2026-10-30")
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		return "", errors.New("unsafe backup directory")
	}
	data, err := checked(filepath.Join(dir, "metadata.json"), "", true)
	if err != nil || len(data) > 4096 {
		return "", errors.New("unsafe backup metadata")
	}
	var record struct {
		Verified bool `json:"verified"`
		Remote   struct {
			SHA string `json:"sha256"`
		} `json:"remote"`
	}
	if json.Unmarshal(data, &record) != nil || !record.Verified || len(record.Remote.SHA) != 64 {
		return "", errors.New("invalid backup metadata")
	}
	if _, err := checked(filepath.Join(dir, "ClientTruth.plist"), record.Remote.SHA, true); err != nil {
		return "", errors.New("backup bytes changed")
	}
	if _, err := checked(filepath.Join(dir, "acl.txt"), "", true); err != nil {
		return "", errors.New("backup ACL missing")
	}
	return record.Remote.SHA, nil
}
func ssh(account, ip, key, host, remote string, input []byte, limit int, deadline time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	args := []string{"-F", "/dev/null", "-i", key, "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + host, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "-o", "LogLevel=ERROR", "-o", "HostKeyAlias=[127.0.0.1]:2222", "-o", "AddressFamily=inet", "-T", "-p", "22", account + "@" + ip, remote}
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil || len(out) > limit {
		return nil, errors.New("bounded pinned SSH command failed")
	}
	return out, nil
}
func attest(label string) (string, error) {
	if _, err := checked(validatorPath, validatorSHA, false); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/opt/homebrew/bin/python3", "-I", "-S", "-B", validatorPath, label, "--check")
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil || string(out) != "SPRINGBOARD_R2_ATTEST profile="+label+" code=matched entitlements=matched layout=exact\n" {
		return "", errors.New("installed attestation failed")
	}
	manifest := filepath.Join("build/ipad-hardware", "installed-springboard-r2-"+label+"-attestation.json")
	data, err := checked(manifest, "", true)
	if err != nil || len(data) > 4096 {
		return "", errors.New("unsafe attestation manifest")
	}
	var record struct {
		Status string `json:"status"`
		Binary string `json:"binarySha256"`
	}
	if json.Unmarshal(data, &record) != nil || record.Status != "installed-code-and-entitlements-matched" || len(record.Binary) != 64 {
		return "", errors.New("invalid attestation manifest")
	}
	for _, c := range record.Binary {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", errors.New("invalid binary hash")
		}
	}
	return record.Binary, nil
}
func run(label, action string) error {
	clearRound := ""
	round := ""
	switch action {
	case "clear1":
		clearRound = "1"
	case "clear2":
		clearRound = "2"
	case "clear3":
		clearRound = "3"
	case "clear4":
		clearRound = "4"
	case "clear5":
		clearRound = "5"
	case "clear6":
		clearRound = "6"
	case "clear7":
		clearRound = "7"
	case "round1":
		round = "1"
	case "round2":
		round = "2"
	case "round3":
		round = "3"
	case "round4":
		round = "4"
	case "round5":
		round = "5"
	case "round6":
		round = "6"
	case "round7":
		round = "7"
	case "round8":
		round = "8"
	case "state":
		// Read-only preflight and exact app-container report classification.
	default:
		return errors.New("unsupported action")
	}
	key := filepath.Join(privateDir, "mac2jb-ipad-probe-ed25519")
	host := filepath.Join(privateDir, "mac2jb-ipad-known-hosts")
	if _, err := checked(key, keySHA, true); err != nil {
		return err
	}
	if _, err := checked(host, hostSHA, true); err != nil {
		return err
	}
	ip, err := address()
	if err != nil {
		return err
	}
	sha, err := original()
	if err != nil {
		return err
	}
	state, err := checked(statePath, stateSHA, false)
	if err != nil || len(state) > 16384 {
		return errors.New("state source changed")
	}
	report, err := checked(reportPath, reportSHA, false)
	if err != nil || len(report) > 8192 {
		return errors.New("report source changed")
	}
	launch, err := checked(launchPath, launchSHA, false)
	if err != nil || len(launch) > 8192 {
		return errors.New("launch source changed")
	}
	binary, err := attest(label)
	if err != nil {
		return err
	}
	preflight := func() error {
		out, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - preflight "+sha, state, 512, 20*time.Second)
		if err != nil || !strings.HasPrefix(string(out), "SPRINGBOARD_R2_PREFLIGHT profile=unchanged store=one baseline=one setdescription=one ") || !strings.HasSuffix(string(out), "stage-baseline=verified stage-setdescription=verified\n") {
			return errors.New("R2 profile/app preflight failed")
		}
		return nil
	}
	if err := preflight(); err != nil {
		return err
	}
	stateRemote := "/var/jb/usr/bin/python3 -I -S -B - state " + label
	out, err := ssh("root", ip, key, host, stateRemote, report, 128, 20*time.Second)
	if action == "state" {
		if err != nil || (string(out) != "SPRINGBOARD_R2_REPORT profile="+label+" state=present\n" &&
			string(out) != "SPRINGBOARD_R2_REPORT profile="+label+" state=absent\n") {
			return errors.New("app report state uncertain")
		}
		fmt.Print(string(out))
		return nil
	}
	if clearRound != "" {
		if err != nil || string(out) != "SPRINGBOARD_R2_REPORT profile="+label+" state=present\n" {
			return errors.New("captured report not present")
		}
		if _, err := checked(reportValidatorPath, reportValidatorSHA, false); err != nil {
			return errors.New("report validator changed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, "/opt/homebrew/bin/python3", "-I", "-S", "-B", reportValidatorPath, label, clearRound)
		cmd.Stderr = io.Discard
		validated, validationErr := cmd.Output()
		cancel()
		if validationErr != nil || !bytes.HasPrefix(validated, []byte("SPRINGBOARD_R2_REPORT_VALID profile="+label+" round="+clearRound+" ")) {
			return errors.New("private report validation failed")
		}
		local, err := checked(filepath.Join("build/ipad-hardware", "springboard-r2-"+label+"-round-"+clearRound+".json"), "", true)
		if err != nil || len(local) == 0 || len(local) > 1_048_576 {
			return errors.New("private captured report unavailable")
		}
		digest := sha256.Sum256(local)
		clear, err := checked(clearPath, clearSHA, false)
		if err != nil || len(clear) > 8192 {
			return errors.New("clear source changed")
		}
		remote := fmt.Sprintf("/var/jb/usr/bin/python3 -I -S -B - %s %x", label, digest)
		out, err := ssh("root", ip, key, host, remote, clear, 128, 20*time.Second)
		if err != nil || string(out) != "SPRINGBOARD_R2_CLEAR profile="+label+" verified\n" {
			return errors.New("report clearance uncertain")
		}
		out, err = ssh("root", ip, key, host, stateRemote, report, 128, 20*time.Second)
		if err != nil || string(out) != "SPRINGBOARD_R2_REPORT profile="+label+" state=absent\n" {
			return errors.New("post-clear report state uncertain")
		}
		if err := preflight(); err != nil {
			return errors.New("post-clear profile/app check failed")
		}
		fmt.Printf("SPRINGBOARD_R2_CLEAR profile=%s verified\n", label)
		return nil
	}
	output := filepath.Join("build/ipad-hardware", "springboard-r2-"+label+"-round-"+round+".json")
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return errors.New("private output already exists or cannot be checked")
	}
	if err != nil || string(out) != "SPRINGBOARD_R2_REPORT profile="+label+" state=absent\n" {
		return errors.New("clean app report precondition failed")
	}
	out, err = ssh("mobile", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - "+label+" "+binary, launch, 128, 20*time.Second)
	if err != nil || string(out) != "SPRINGBOARD_R2_LAUNCH profile="+label+" status=accepted\n" {
		return errors.New("launch request uncertain")
	}
	fmt.Printf("SPRINGBOARD_R2_LAUNCH profile=%s status=accepted\n", label)
	var available bool
	for attempt := 0; attempt < 8; attempt++ {
		out, err = ssh("root", ip, key, host, stateRemote, report, 128, 20*time.Second)
		if err != nil {
			return errors.New("report state uncertain")
		}
		if string(out) == "SPRINGBOARD_R2_REPORT profile="+label+" state=present\n" {
			available = true
			break
		}
		if string(out) != "SPRINGBOARD_R2_REPORT profile="+label+" state=absent\n" {
			return errors.New("unsafe app report state")
		}
		time.Sleep(time.Second)
	}
	if !available {
		return errors.New("app report absent after launch")
	}
	raw, err := ssh("root", ip, key, host, "/var/jb/usr/bin/python3 -I -S -B - capture "+label, report, 1_048_576, 25*time.Second)
	if err != nil || len(raw) == 0 {
		return errors.New("private report capture failed")
	}
	fd, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("private output already exists")
	}
	count, writeErr := fd.Write(raw)
	syncErr := fd.Sync()
	closeErr := fd.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || count != len(raw) {
		return errors.New("private output write failed")
	}
	sum := sha256.Sum256(raw)
	fmt.Printf("SPRINGBOARD_R2_CAPTURE profile=%s bytes=%d sha256=%x\n", label, len(raw), sum)
	if err := preflight(); err != nil {
		return errors.New("post-capture profile/app check failed")
	}
	return nil
}
func main() {
	if len(os.Args) != 3 || (os.Args[1] != "baseline" && os.Args[1] != "setdescription") {
		fmt.Println("SPRINGBOARD_R2_FLOW rejected")
		os.Exit(2)
	}
	if run(os.Args[1], os.Args[2]) != nil {
		fmt.Println("SPRINGBOARD_R2_FLOW rejected")
		os.Exit(1)
	}
}
