#!/usr/bin/env python3
"""Swap one allowlisted U2 broker for another over pinned root Wi-Fi SSH (usage: OLD NEW [--ipad-check]).

Effect: makes a fresh Wi-Fi restore kit first (journal and every U2 file),
then runs device/u2-replace-broker.py --inspect and, with --transition,
the transition itself, streaming the exact Mac-built v9 binary. Requires
healthy Mac USB before and after. No USB controller call.
"""

import hashlib
from pathlib import Path
import runpy
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-replace-broker.py"
BINARIES = {"v12": ("u2-native-noop-trial-v12-learned-profile", "9629611372c6f570db18064a2cfcd077601f59a1b5a2a4644dbc3bdbefe37a3e"),
            "v11": ("u2-native-noop-trial-v11-auto-heal-restart", "8fdb044ff8840084e27e896432de060deecd6cdc9d27913b9ae3f379077b3736"),
            # Digests pin the exact artifact, not the variant name: rebuilding an
            # older variant from changed sources yields a different binary, so the
            # entry for an installed broker keeps the digest that is on the device.
            "v13": ("u3-native-additive-function-v13", "71cf7b63072919370e2e6b41aa6b249a761cc10ff684aa79fa3a49f6348dcc97"),
            "v14": ("u3-native-additive-function-v14", "f8e17bbdfc26df182c584383f180814a485014fe7244161af1066ff81e835229"),
            "v15": ("u3-native-additive-function-v15", "bbc4946fa6af6d3013be689ec581114266848f106bea1cad6b0fabed91f20e3a"),
            "v16": ("u3-native-additive-function-v16", "11f63007bd9e5ce2f16bc2c8eb88bc3245ed073857b3bfea1cb964b49b58df87"),
            "v17": ("u3-native-additive-function-v17", "2d1c7582a739c90397f8b2f6c0d483222e743dda818e26cb5fd9b80e017ed0fb"),
            "v18": ("u3-native-additive-function-v18", "0e2063d6d33a6567806f05eaa231106123d39d952c9b8c66db1a0845b53bdf70"),
            "v19": ("u3-native-additive-function-v19", "eddb506f52c5bd913438ef4fb44007368e9fe89fa1fa47f8a4569c8d15c0a224"),
            # v19 behaviour rebuilt from the tv_sec-only boot-session source.
            "v20": ("u3-native-additive-function-v20", "df0ac6a4fb2f24c639a8ffc703e01e3c8fbfba37e4f59e3c628a60a79f038c6d"),
            # v20 plus the interface-list publication and stored-description restore.
            "v21": ("u3-native-additive-function-v21", "81889579a0eaddc935f3c575e46caa7518d1da5f5cca9462ec82174bcb2b39e0"),
            # v21 plus publish-sole-configuration (Apple's standardKeyboard shape).
            "v22": ("u3-native-additive-function-v22", "9420e25cc412f6dd9edafe1b6087fd7909018d33af5fed309921499a3e1486f0"),
            # v22 plus the link-speed-tolerant verifier, installed as
            # /var/jb/usr/libexec/ipad2jb/usb-broker (label dev.ipad2jb.usbbroker).
            "v23": ("u3-native-additive-function-v23", "7ce33843f03639eb7af35d529ba0d2c8eb1fd517d2c1d89296072f2cc6866be9")}
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))


# --ipad-check: for an iPad cabled to a host other than this Mac (owner-approved
# standalone use, 2026-11-17). Instead of Mac USB, the iPad itself must show the
# controller on bus and configured by its host, with every learned-profile
# function registered, before and after the swap. Read-only; uses the helpers
# of the installed /var/jb/usr/bin/ipad2jb command.
IPAD_CHECK = r'''
import json, sys
sys.argv = ["x"]
exec(open("/var/jb/usr/bin/ipad2jb").read().split('if __name__ == "__main__":')[0])
_, state = controller()
expected = set(json.load(open(PROFILE))["functions"])
missing = sorted(expected - registered_functions())
ok = (state.get("OnBus") is True and state.get("DeviceState") == "Configured"
      and isinstance(state.get("SelectedConfiguration"), int) and state["SelectedConfiguration"] > 0
      and not missing)
print("IPAD_USB %s on-bus=%s state=%s selected=%s missing=%s" % (
    "ok" if ok else "bad", state.get("OnBus"), state.get("DeviceState"),
    state.get("SelectedConfiguration"), ",".join(missing) or "none"))
'''


def ipad_usb_healthy(ssh):
    result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(IPAD_CHECK)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90)
    line = result.stdout.decode("ascii", "replace").strip()
    print(line)
    return line.startswith("IPAD_USB ok ")


def main(mode, old, new, ipad_check=False):
    name, digest = BINARIES[new]
    binary = (ROOT / "build/ipad-hardware" / name).read_bytes()
    if hashlib.sha256(binary).hexdigest() != digest:
        raise ValueError("new binary changed")
    usb_ok = ((lambda: ipad_usb_healthy(runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))
                                        ["ssh_command"]())) if ipad_check else SUPPORT["usb_present"])
    if not usb_ok():
        raise ValueError("USB not healthy (%s)" % ("iPad check" if ipad_check else "Mac"))
    backup = subprocess.run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")],
                            stdout=subprocess.PIPE, timeout=400)
    print(backup.stdout.decode(), end="")
    if backup.returncode:
        raise ValueError("backup failed")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    source = shlex.quote(PAYLOAD.read_bytes().decode("ascii"))
    for step in (("--inspect",) if mode == "--inspect" else ("--inspect", "--replace")):
        result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + source + " " + step +
                                 " " + old + " " + new],
                                input=binary, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=90)
        print(result.stdout.decode("ascii", "replace"), end="")
        if result.returncode:
            raise ValueError("device step failed")
    if not usb_ok():
        raise ValueError("USB not healthy afterwards (%s)" % ("iPad check" if ipad_check else "Mac"))


if __name__ == "__main__":
    try:
        arguments = sys.argv[1:]
        ipad_check = "--ipad-check" in arguments
        arguments = [item for item in arguments if item != "--ipad-check"]
        if len(arguments) != 3 or arguments[0] not in ("--inspect", "--replace"):
            raise ValueError("usage: --inspect|--replace OLD NEW [--ipad-check]")
        main(*arguments, ipad_check=ipad_check)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_REPLACE rejected (%s)" % error)
        raise SystemExit(1)
