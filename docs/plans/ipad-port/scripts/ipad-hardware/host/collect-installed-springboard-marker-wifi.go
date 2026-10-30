// Stream the installed SpringBoard marker app privately over pinned Wi-Fi.
//
// This Mac program verifies the durable key, host pin, private address, and
// exact repository device archive script. It runs that read-only script as
// mobile, bounds the tar stream and SSH deadline, and exclusively saves one
// mode-0600 local archive. The archive may contain device paths and signatures;
// it stays in ignored build storage and is never printed. No iPad file is
// created, removed, modified, or executed by this collector.
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
	privateDir  = "/Users/boolean/.ssh/mac2jb-ipad"
	keyName     = "mac2jb-ipad-probe-ed25519"
	hostName    = "mac2jb-ipad-known-hosts"
	keySHA      = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA     = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	payloadPath = "scripts/ipad-hardware/device/u1-readonly-installed-springboard-marker-archive.sh"
	payloadSHA  = "378e180d68da91a40bd85b4447d901f2a72bf8615fbc9628757a69dff5070a75"
	outputPath  = "build/ipad-hardware/installed-springboard-marker-archive.tar"
	maxBytes    = 16 * 1024 * 1024
)

// The iPad has a rootless shell layout; /bin/sh is not assumed to exist.
// This is the fixed read-only env/shell selection used by the accepted
// installed-toolbox collector, with no dynamic interpolation.
const remoteShell = `exec 2>&-; set +euxv; env_path=; for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do if [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then env_path=$candidate; break; fi; done; shell_path=; for candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash /var/jb/bin/bash /var/jb/usr/bin/bash; do if [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then shell_path=$candidate; break; fi; done; if [ -z "$env_path" ]; then exit 127; fi; if [ -z "$shell_path" ]; then exit 126; fi; "$env_path" -i PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin' LC_ALL=C "$shell_path" -s`

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
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != digest {
		return nil, errors.New("local input digest mismatch")
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
	if err != nil || len(data) < 8 || !bytes.HasSuffix(data, []byte{'\n'}) ||
		bytes.Count(data, []byte{'\n'}) != 1 {
		return "", errors.New("invalid private address")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", errors.New("invalid private address")
	}
	return value, nil
}

func run() error {
	parent, err := os.Lstat(filepath.Dir(outputPath))
	if err != nil || !parent.IsDir() {
		return errors.New("private archive parent unavailable")
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		return errors.New("private archive already exists or cannot be checked")
	}
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
		return errors.New("unexpected device archive script")
	}
	ip, err := address()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		"-T", "-p", "22", "mobile@" + ip, remoteShell}
	command := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	command.Stdin = bytes.NewReader(payload)
	command.Stderr = io.Discard
	pipe, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return errors.New("ssh-start-failed")
	}
	data, readErr := io.ReadAll(io.LimitReader(pipe, maxBytes+1))
	if readErr != nil || len(data) > maxBytes {
		command.Process.Kill()
		command.Wait()
		return errors.New("device archive exceeded bound or read failed")
	}
	if err := command.Wait(); err != nil {
		var exited *exec.ExitError
		if errors.As(err, &exited) && exited.ExitCode() >= 0 && exited.ExitCode() <= 255 {
			return fmt.Errorf("remote-exit-%d", exited.ExitCode())
		}
		return errors.New("remote-command-failed")
	}
	if ctx.Err() != nil {
		return errors.New("remote-timeout")
	}
	if len(data) < 1024 || len(data)%512 != 0 {
		return errors.New("archive-size-invalid")
	}
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		file.Close()
		if !good {
			os.Remove(outputPath)
		}
	}()
	count, err := file.Write(data)
	if err != nil || count != len(data) {
		return errors.New("private archive write incomplete")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	good = true
	digest := sha256.Sum256(data)
	fmt.Printf("MARKER_ARCHIVE captured bytes=%d sha256=%s\n", len(data), hex.EncodeToString(digest[:]))
	return nil
}

func main() {
	if err := run(); err != nil {
		category := "local-preflight"
		switch err.Error() {
		case "ssh-start-failed", "remote-command-failed", "remote-timeout", "archive-size-invalid", "device archive exceeded bound or read failed":
			category = err.Error()
		}
		if strings.HasPrefix(err.Error(), "remote-exit-") {
			category = err.Error()
		}
		fmt.Println("MARKER_ARCHIVE rejected category=" + category)
		os.Exit(1)
	}
}
