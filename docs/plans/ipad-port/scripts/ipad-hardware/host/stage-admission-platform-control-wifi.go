// Stage one fixed platform-entitled marker-only iPad control over pinned Wi-Fi SSH.
//
// This Mac program verifies the exact 50,304-byte ad-hoc-signed C binary,
// device staging payload, private Mac key and host pin, and private Wi-Fi
// address. The iPad payload exclusively creates one root-owned Media file,
// verifies it, and makes it executable. It does not launch the file or touch
// USB, SSH configuration, system files, app registration, or trust caches.
// An interrupted stage may leave the fixed path listed in the cleanup ledger.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	privateDir = "/Users/boolean/.ssh/mac2jb-ipad"
	keyName    = "mac2jb-ipad-probe-ed25519"
	hostName   = "mac2jb-ipad-known-hosts"
	keySHA     = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA    = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	stagePath  = "scripts/ipad-hardware/device/u1-stage-admission-platform-control.py"
	stageSHA   = "4fb99bdccc480c9ff5f4c739d77024cdf103c76d1a0e6e93f7adbb781bf476a6"
	binPath    = "build/ipad-hardware/u1-admission-smoke-platform"
	binSHA     = "5d90f4db7b618ceabe29f59fb8d1a10578b9b37c8fc7d178d9db4b740dc29398"
	binSize    = 50304
)

func checked(path, digest string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("unsafe local file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0600 {
			return nil, errors.New("unsafe private file")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != digest {
		return nil, errors.New("local digest mismatch")
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
		return "", errors.New("unsafe private address")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 7 || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", errors.New("invalid private address")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", errors.New("nonprivate or noncanonical address")
	}
	return value, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func run() error {
	if len(os.Args) != 1 {
		return errors.New("no arguments accepted")
	}
	key := filepath.Join(privateDir, keyName)
	host := filepath.Join(privateDir, hostName)
	if _, err := checked(key, keySHA, true); err != nil {
		return err
	}
	if _, err := checked(host, hostSHA, true); err != nil {
		return err
	}
	stage, err := checked(stagePath, stageSHA, false)
	if err != nil {
		return err
	}
	binary, err := checked(binPath, binSHA, false)
	if err != nil || len(binary) != binSize {
		return errors.New("staged binary mismatch")
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
		"/var/jb/usr/bin/python3 -I -S -B -c " + shellQuote(string(stage))}
	command := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	command.Stdin = bytes.NewReader(binary)
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil || !bytes.Equal(output, []byte("PLATFORM_CONTROL_STAGE verified\n")) {
		return errors.New("bounded exclusive iPad stage failed; inspect fixed cleanup-ledger path")
	}
	fmt.Print("PLATFORM_CONTROL_STAGE verified\n")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PLATFORM_CONTROL_STAGE rejected:", err)
		os.Exit(1)
	}
}
