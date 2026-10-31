"""Fetch the broker's on-device learned USB device profile over pinned root Wi-Fi SSH.

Host tools use this instead of reference-device constants (USB vendor/product
IDs, healthy bcdUSB/MPS0, function list). The profile has no private IDs.
"""

import json
from pathlib import Path
import runpy
import shlex
import subprocess

HOST = Path(__file__).resolve().parent
ASK = ('import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(30);'
       's.connect("/var/jb/var/lib/mac2jb-u2-native/broker.sock");'
       's.sendall(b"profile\\n");print(s.recv(65536).decode().strip())')


def fetch(ssh=None):
    if ssh is None:
        ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(ASK)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    text = result.stdout.decode("utf-8", "replace").strip()
    if result.returncode or not text.startswith("OK profile {"):
        raise ValueError("broker has no learned device profile")
    profile = json.loads(text[len("OK profile "):])
    # 2 is a stock-only profile; 3 adds the appended-function section. Both
    # carry the fields host tools read, so accept either.
    if profile.get("schemaVersion") not in (2, 3) or not profile.get("functions"):
        raise ValueError("unsupported device profile")
    return profile
