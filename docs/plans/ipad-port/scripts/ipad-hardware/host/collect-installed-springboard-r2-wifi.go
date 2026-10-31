// Privately stream one installed SpringBoard R2 app over pinned Wi-Fi SSH.
//
// The fixed read-only tar payload searches one exact bundle name and emits a
// bounded archive; this Mac runner verifies the key, host pin, source digest,
// and address, then saves only an ignored mode-0600 local file. It never
// launches app code or changes an iPad file.
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
	maxBytes   = 16 * 1024 * 1024
)

type profile struct{ payload, sha, output string }

var profiles = map[string]profile{
	"baseline":       {"docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-installed-springboard-r2-baseline-archive.sh", "77aa8d9d5c7958756cf5a0e2d4e5cc91984bc490ec94578e17ded9d80eed48af", "build/ipad-hardware/installed-springboard-r2-baseline-archive.tar"},
	"setdescription": {"docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-installed-springboard-r2-setdescription-archive.sh", "eea2f20290047edb33d9fb81feff5fb46a161c25ea84b8f27ac948e655ea4a57", "build/ipad-hardware/installed-springboard-r2-setdescription-archive.tar"},
}

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

func run(label string) error {
	selected := profiles[label]
	parent, err := os.Lstat(filepath.Dir(selected.output))
	if err != nil || !parent.IsDir() {
		return errors.New("private archive parent unavailable")
	}
	if _, err := os.Lstat(selected.output); !os.IsNotExist(err) {
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
	payload, err := checked(selected.payload, selected.sha, 0)
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
		return errors.New("remote-command-failed")
	}
	if ctx.Err() != nil {
		return errors.New("remote-timeout")
	}
	if len(data) < 1024 || len(data)%512 != 0 {
		return errors.New("archive-size-invalid")
	}
	file, err := os.OpenFile(selected.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		file.Close()
		if !good {
			os.Remove(selected.output)
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
	fmt.Printf("SPRINGBOARD_R2_ARCHIVE profile=%s bytes=%d sha256=%s\n", label, len(data), hex.EncodeToString(digest[:]))
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("SPRINGBOARD_R2_ARCHIVE rejected")
		os.Exit(2)
	}
	if _, ok := profiles[os.Args[1]]; !ok {
		fmt.Println("SPRINGBOARD_R2_ARCHIVE rejected")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Println("SPRINGBOARD_R2_ARCHIVE rejected category=collection-failed")
		os.Exit(1)
	}
}
