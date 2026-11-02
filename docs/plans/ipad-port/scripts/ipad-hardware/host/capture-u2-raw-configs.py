#!/usr/bin/env python3
"""Save external raw USB configuration descriptors without opening the iPad.

The fixed Mac C helper uses only IOUSBLib methods Apple documents as usable
without USBDeviceOpen. This wrapper pins its source and binary, runs it with
a timeout, validates the full descriptor framing, and saves the raw bytes in
an ignored mode-0600 private baseline file. It prints only hashes and counts.
It makes no iPad file or USB mutation. A failed helper leaves no capture.
"""

import hashlib
import os
from pathlib import Path
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/u2-readonly-raw-config-descriptors.c"
SOURCE_SHA256 = "04b8f168105670624a5e6e46b26695ed7ab5fb7768e8e28e001c1b1c62734841"
BINARY = ROOT / "build/ipad-hardware/u2-readonly-raw-config-descriptors"
BINARY_SHA256 = "f1d32a82872d28a670764fb44d49cbf4d3d04248bcbfeed456b24774768dd60e"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
TARGET = BASE / "raw-configs.bin"


def checked(path, digest, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("unsafe capture input")
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("capture input changed")


def parse(data):
    if not data.startswith(b"U2CFGD1\0") or len(data) < 10:
        raise ValueError("invalid descriptor envelope")
    count = data[8]
    if not 1 <= count <= 8:
        raise ValueError("invalid configuration count")
    offset = 9
    configurations = []
    for _ in range(count):
        if len(data) - offset < 2:
            raise ValueError("truncated descriptor length")
        length = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
        if not 9 <= length <= 16384 or len(data) - offset < length:
            raise ValueError("truncated configuration")
        raw = data[offset:offset + length]
        offset += length
        if raw[0] < 9 or raw[1] != 2 or int.from_bytes(raw[2:4], "little") != length:
            raise ValueError("invalid configuration header")
        position = 0
        interfaces = endpoints = 0
        while position < length:
            size = raw[position]
            if size < 2 or position + size > length:
                raise ValueError("invalid subdescriptor")
            interfaces += raw[position + 1] == 4
            endpoints += raw[position + 1] == 5
            position += size
        configurations.append((raw[5], interfaces, endpoints))
    if offset != len(data) or len({item[0] for item in configurations}) != count:
        raise ValueError("ambiguous configuration data")
    return configurations


def capture():
    checked(SOURCE, SOURCE_SHA256, 32 * 1024)
    checked(BINARY, BINARY_SHA256, 1024 * 1024)
    if not BASE.is_dir() or stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    result = subprocess.run([str(BINARY)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode != 0 or len(result.stdout) > 128 * 1024:
        raise ValueError("raw descriptor helper unavailable")
    configurations = parse(result.stdout)
    active = [item for item in configurations if item[0] == 5]
    if len(active) != 1:
        raise ValueError("active configuration absent")
    return result.stdout, configurations, active[0]


def main():
    data, configurations, active = capture()
    if not BASE.is_dir() or stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short descriptor capture")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print("U2_RAW_CONFIGS count=" + str(len(configurations)) +
          " active=5 interfaces=" + str(active[1]) +
          " endpoints=" + str(active[2]))
    print("U2_RAW_CONFIGS sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_RAW_CONFIGS rejected")
        raise SystemExit(1)
