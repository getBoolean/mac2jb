// Collect the stock USB source or live/default controller descriptions from the target iPad.
//
// This Mac tool checks its fixed device payload, the existing pinned Wi-Fi SSH
// identity, and the four accepted U1 platform reports for stock-source mode.
// --descriptions streams two existing controller properties instead. Both
// modes save bounded bytes exclusively under ignored private build storage.
// Neither mode changes iPad state or sends a USB command.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	privateDir      = "/Users/boolean/.ssh/mac2jb-ipad"
	keyName         = "mac2jb-ipad-probe-ed25519"
	hostName        = "mac2jb-ipad-known-hosts"
	keySHA          = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
	hostSHA         = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
	payloadPath     = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-stock-configuration.py"
	payloadSHA      = "93ac89b9c9f5db53f229fec0122f4c411f8ac893e15042627ed4b836b625fdfa"
	descPayloadPath = "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-controller-description-copy.py"
	descPayloadSHA  = "b2470a242e1984b746bddf92cd15a1570766bdf6dd6fcbeadc3efb0c3b5f650a"
	stockPath       = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
	maxBytes        = 2 * 1024 * 1024
)

var reportPaths = []string{
	"build/ipad-hardware/admission-probe-capture-host-a-operator-observed-vbus-charging-observed-a-admission-1-wifi-control/platform-only-round-1.json",
	"build/ipad-hardware/admission-probe-capture-host-b-operator-observed-vbus-charging-observed-b-admission-1-wifi-control/platform-only-round-1.json",
	"build/ipad-hardware/admission-probe-switch-a-operator-not-observed-observed-a-admission-1-wifi-control/platform-only-round-1.json",
	"build/ipad-hardware/admission-probe-switch-b-operator-not-observed-observed-b-admission-1-wifi-control/platform-only-round-1.json",
}

type report struct {
	Configuration struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"configuration"`
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxBytes {
		return 0, errors.New("oversized remote output")
	}
	return b.Buffer.Write(data)
}

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
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() > 16 {
		return "", errors.New("unsafe private address")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 7 || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", errors.New("invalid private address")
	}
	value := strings.TrimSuffix(string(data), "\n")
	ip := net.ParseIP(value).To4()
	if ip == nil || !ip.IsPrivate() || ip.String() != value {
		return "", errors.New("invalid private address")
	}
	return value, nil
}

func expectedDigest() (string, error) {
	var expected string
	for _, path := range reportPaths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 2*maxBytes {
			return "", errors.New("unsafe report")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		var item report
		if err := json.Unmarshal(data, &item); err != nil {
			return "", errors.New("invalid report")
		}
		digest := item.Configuration.SHA256
		if item.Configuration.Path != stockPath || len(digest) != 64 {
			return "", errors.New("invalid configuration source")
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
			return "", errors.New("invalid configuration digest")
		}
		if expected != "" && expected != digest {
			return "", errors.New("inconsistent configuration digest")
		}
		expected = digest
	}
	return expected, nil
}

func run() error {
	descriptions := len(os.Args) == 2 && os.Args[1] == "--descriptions"
	verifyDescriptions := len(os.Args) == 2 && os.Args[1] == "--verify-descriptions"
	if len(os.Args) != 1 && !descriptions && !verifyDescriptions {
		return errors.New("invalid arguments")
	}
	key := filepath.Join(privateDir, keyName)
	host := filepath.Join(privateDir, hostName)
	if _, err := checked(key, keySHA, true); err != nil {
		return err
	}
	if _, err := checked(host, hostSHA, true); err != nil {
		return err
	}
	chosenPath, chosenSHA := payloadPath, payloadSHA
	if descriptions || verifyDescriptions {
		chosenPath, chosenSHA = descPayloadPath, descPayloadSHA
	}
	payload, err := checked(chosenPath, chosenSHA, false)
	if err != nil {
		return err
	}
	var expected string
	if !descriptions && !verifyDescriptions {
		expected, err = expectedDigest()
		if err != nil {
			return err
		}
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
		"-T", "-p", "22", "root@" + ip, "/var/jb/usr/bin/python3 -I -S -B -"}
	command := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	command.Stdin = bytes.NewReader(payload)
	command.Stderr = io.Discard
	var output boundedOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return errors.New("bounded device read failed")
	}
	data := output.Bytes()
	if descriptions || verifyDescriptions {
		magic := []byte("MAC2JB-U1-DESC\x00")
		if len(data) < len(magic)+8 || !bytes.Equal(data[:len(magic)], magic) {
			return errors.New("invalid description frame")
		}
		base := len(magic)
		first := int(binary.BigEndian.Uint32(data[base : base+4]))
		second := int(binary.BigEndian.Uint32(data[base+4 : base+8]))
		if first < 8 || first > 512*1024 || second < 8 || second > 512*1024 ||
			len(data) != base+8+first+second {
			return errors.New("invalid description lengths")
		}
		defaultData := data[base+8 : base+8+first]
		liveData := data[base+8+first:]
		if !bytes.HasPrefix(defaultData, []byte("bplist00")) || !bytes.HasPrefix(liveData, []byte("bplist00")) {
			return errors.New("invalid description encoding")
		}
		dir := "build/ipad-hardware/controller-descriptions"
		if verifyDescriptions {
			oldDefault, err := readPrivate(filepath.Join(dir, "default.bplist"))
			if err != nil {
				return err
			}
			oldLive, err := readPrivate(filepath.Join(dir, "live.bplist"))
			if err != nil {
				return err
			}
			if !bytes.Equal(defaultData, oldDefault) || !bytes.Equal(liveData, oldLive) {
				return errors.New("description snapshot changed")
			}
			fmt.Println("CONTROLLER_DESCRIPTIONS default=stable live=stable private-copy=verified")
			return nil
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return errors.New("private description directory already exists or cannot be created")
		}
		completed := false
		defer func() {
			if !completed {
				os.Remove(filepath.Join(dir, "default.bplist"))
				os.Remove(filepath.Join(dir, "live.bplist"))
				os.Remove(dir)
			}
		}()
		if err := writePrivate(filepath.Join(dir, "default.bplist"), defaultData); err != nil {
			return err
		}
		if err := writePrivate(filepath.Join(dir, "live.bplist"), liveData); err != nil {
			return err
		}
		completed = true
		fmt.Println("CONTROLLER_DESCRIPTIONS default=saved live=saved private-copy=verified")
		return nil
	}
	if len(data) < 1 || len(data) > maxBytes {
		return errors.New("invalid device file size")
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != expected {
		return errors.New("device file differs from accepted reports")
	}
	dir := "build/ipad-hardware/stock-configuration"
	if err := os.Mkdir(dir, 0700); err != nil {
		return errors.New("private output directory already exists or cannot be created")
	}
	file, err := os.OpenFile(filepath.Join(dir, "USBDeviceConfiguration.plist"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Println("STOCK_CONFIGURATION source=verified four-rows=matching private-copy=saved")
	return nil
}

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func readPrivate(path string) ([]byte, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parentStat.Uid != uint32(os.Getuid()) || parent.Mode().Perm() != 0700 {
		return nil, errors.New("unsafe private description directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() < 8 || info.Size() > 512*1024 {
		return nil, errors.New("unsafe private description file")
	}
	return os.ReadFile(path)
}

func main() {
	if err := run(); err != nil {
		fmt.Println("CONTROLLER_EVIDENCE rejected")
		os.Exit(1)
	}
}
