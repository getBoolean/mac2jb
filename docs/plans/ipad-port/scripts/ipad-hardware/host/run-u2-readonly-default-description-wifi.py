#!/usr/bin/env python3
"""Run the fixed read-only default-description classifier over pinned Wi-Fi.

This Mac script checks the exact repository payload, durable SSH identity and
host pin, and private Wi-Fi address. It sends the payload to the iPad's
installed Python as root through stdin, accepts only one categorical line,
and prints no private address or device identifier. Neither side writes an
iPad file or invokes a USB publication, bus-cycle, or registry-write API.
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-default-description.py"
PAYLOAD_SHA256 = "de7bede09f7287756d710b6ab5102037953449c7fce9a6f3347621b633e17627"
RELATION_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-default-description-relation.py"
RELATION_SHA256 = "8eee7d8a5bc2b07495c7aed5e0f1034c9a7b0bbd8c27975385ab971a5a8ff386"
RUNTIME_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-runtime-capabilities.py"
RUNTIME_SHA256 = "618c1bfe3ca10cbbf6493a225b2b7478d1f52a633de86c063ec52f45e0086c8f"
SNAPSHOT_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2_target_snapshot.py"
SNAPSHOT_SHA256 = "b31079908483b290aeb7d23e7b9d7ed96af1b4b550e5e0124a026329ce9723ba"
LAYOUT_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-package-layout.py"
LAYOUT_SHA256 = "28de31735db3ee385ab7d9a571c61ba31af39fc341e83fae77286deb8e6cd9ff"
ENTITLEMENTS_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-python-entitlements.py"
ENTITLEMENTS_SHA256 = "aeb80e6bb4f31a6740cb58e32e300a4c299cc19f1df576e061c6b82dd046c353"
CLEANUP_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-native-admission-cleanup.py"
CLEANUP_SHA256 = "62ec354d7fe5ebbc94526cd7260fdedda1629b397f6ed27be4ec843ea19d1b3d"
SERVICE_STATE_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-service-smoke-state.py"
SERVICE_STATE_SHA256 = "319572347b66e4b029774517fb5045babd122bf438f60d3e17904e8d62846c16"
INSTALLED_STATE_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-installed-native-state.py"
INSTALLED_STATE_SHA256 = "ef680230ebddac2e5e2a2ab2548d57ff7a07465e18bc51706c2d69b1e547be3e"
DPKG_AUDIT_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-dpkg-audit.py"
DPKG_AUDIT_SHA256 = "b3651369924f2a6b44a41ca86bb8de9fce19c353cc96d37ff6db112f4bd00644"
NATIVE_JOURNAL_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-native-journal-state.py"
NATIVE_JOURNAL_SHA256 = "cb5992879a3f216eb12a51433f33dd73f51735a5ce6263783ed4e014c8ab24a3"
FROM_CONTROLLER_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-description-from-controller.py"
FROM_CONTROLLER_SHA256 = "dfa20c04d12612b993907f5e8ce43a67d7279106442db16efbe142d76dd0430f"
TRIAL_STATUS_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-trial-service-status.py"
TRIAL_STATUS_SHA256 = "d92d46075362d11735ba3d5e10388f60b8aedd511d0f38e2551bb4746bfaf301"
V2_POSTREBOOT_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-v2-postreboot-state.py"
V2_POSTREBOOT_SHA256 = "040c9bdd7b78f834978cda96b3f2803c3ede6c75088f1cde5503da2f7da9fdcb"
BUS_SYMBOL_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-bus-cycle-symbol.py"
BUS_SYMBOL_SHA256 = "5c7a83ab2d9da5b2def32efee7ca44a3a2dd192c4f4ee03c4aa3fd2c21dfab24"
ARCHIVES_PAYLOAD = ROOT / "scripts/ipad-hardware/device/u2-readonly-archived-journals.py"
ARCHIVES_SHA256 = "d5a03eae12970ba924e0f8a63a30a0555dcf44bf5d4ab520667f5679492306e0"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
RESULT = re.compile(
    rb"U2_DEFAULT controller=(created|unavailable) "
    rb"description=(cf-object|absent|unexpected-type|unattempted)\n\Z"
)
RELATION_RESULT = re.compile(
    rb"(?:U2_RELATION (?:controller=unavailable|description=absent|"
    rb"info=(?:unavailable|unexpected-count)|registry=(?:unavailable|ambiguous)|"
    rb"serialization=unavailable|"
    rb"info=dict count=(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) "
    rb"relation=(?:equal-default|equal-live|different) "
    rb"default-subset=(?:yes|no) live-subset=(?:yes|no) "
    rb"configuration-list=(?:same|different|absent) "
    rb"missing=(?:expected-four|other) "
    rb"reconstructed=(?:equal-live|different) "
    rb"in-memory-object=(?:equal-live|different|skipped) "
    rb"controller-match=(?:yes|no))|U2_RELATION rejected)\n\Z"
)
RUNTIME_RESULT = re.compile(b"".join(
    rb"U2_RUNTIME " + name + rb"=(?:absent|other-owner|directory|executable|other)\n"
    for name in (b"launchctl-system", b"launchctl-rootless", b"python", b"ldid",
                 b"dpkg", b"jbctl", b"daemon-dir", b"libexec-dir")
) + rb"U2_RUNTIME stdlib=(?:ready|limited)\n\Z")
SNAPSHOT_RESULT = re.compile(
    rb"U2_SNAPSHOT target=expected controller=one live=dict:16 source=read boot=read\n\Z"
)
LAYOUT_RESULT = re.compile(
    rb"U2_PACKAGE_LAYOUT installed=(?:var-jb-prefix|usr-prefix|other) "
    rb"jb=(?:symlink|directory|other) arch=(?:iphoneos-arm64|iphoneos-arm|other)\n\Z"
)
ENTITLEMENTS_RESULT = re.compile(
    rb"U2_PYTHON_ENTITLEMENT setdescription=(?:yes|no)\n"
    rb"U2_PYTHON_ENTITLEMENT platform=(?:yes|no)\n\Z"
)
CLEANUP_RESULT = re.compile(
    rb"U2_NATIVE_CLEANUP paths=(?:absent|present) job=(?:absent|present)\n\Z"
)
SERVICE_STATE_RESULT = re.compile(
    rb"U2_SERVICE_STATE job=(?:loaded|absent) binary=(?:absent|directory|socket|regular|other) "
    rb"plist=(?:absent|directory|socket|regular|other) "
    rb"state=(?:absent|directory|socket|regular|other)\n"
    rb"U2_SERVICE_STATE socket=(?:absent|directory|socket|regular|other) "
    rb"lock=(?:absent|directory|socket|regular|other) "
    rb"journal=(?:absent|directory|socket|regular|other)\n\Z"
)
INSTALLED_STATE_RESULT = re.compile(
    rb"U2_INSTALLED_STATE package=(?:installed|other|absent) audit=(?:clean|other) "
    rb"job=(?:loaded|absent)\n"
    rb"U2_INSTALLED_STATE stage=(?:absent|regular|directory|socket|other) "
    rb"binary=(?:absent|regular|directory|socket|other) "
    rb"plist=(?:absent|regular|directory|socket|other) "
    rb"state=(?:absent|regular|directory|socket|other) "
    rb"journal=(?:absent|regular|directory|socket|other)\n\Z"
)
DPKG_AUDIT_RESULT = re.compile(
    rb"U2_DPKG_AUDIT exit=(?:zero|other) output=(?:empty|nonempty) "
    rb"sha256=[0-9a-f]{64}\n"
    rb"U2_DPKG_AUDIT affected-count=[0-9]{1,4} "
    rb"sample=(?:none|[a-zA-Z0-9.+,-]{1,320})\n"
    rb"U2_DPKG_AUDIT heading=[a-zA-Z0-9_]{1,120}\n\Z"
)
NATIVE_JOURNAL_RESULT = re.compile(
    rb"U2_NATIVE_JOURNAL phase=(?:absent|prepared|published|restoring|awaitingVerification|recoveryRequired|restored) "
    rb"sha256=(?:none|[0-9a-f]{64})\n\Z"
)
FROM_CONTROLLER_RESULT = re.compile(
    rb"U2_FROM_CONTROLLER (?:symbol=absent|controller=unavailable|"
    rb"description=absent|info=(?:unavailable|unexpected-count)|"
    rb"registry=unavailable|info=dict count=(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) "
    rb"live-count=(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) "
    rb"relation=(?:equal|different)|rejected)\n\Z"
)
TRIAL_STATUS_RESULT = re.compile(
    rb"U2_TRIAL_SERVICE job=(?:loaded|absent) running=(?:yes|no) "
    rb"binary=(?:absent|regular|socket|directory|other) "
    rb"plist=(?:absent|regular|socket|directory|other) "
    rb"socket=(?:absent|regular|socket|directory|other) "
    rb"phase=(?:unavailable|absent|prepared|published|restoring|"
    rb"awaitingVerification|recoveryRequired|restored) "
    rb"publication=(?:unavailable|enabled) "
    rb"original-job=(?:absent|loaded-stopped|running)\n\Z"
)
V2_POSTREBOOT_RESULT = re.compile(
    rb"U2_V2_POSTREBOOT job=(?:absent|loaded-stopped|running) "
    rb"binary=(?:absent|regular|socket|other) "
    rb"plist=(?:absent|regular|socket|other) "
    rb"socket=(?:absent|regular|socket|other) "
    rb"phase=(?:unavailable|awaitingVerification) "
    rb"original-job=(?:absent|loaded-stopped|running)\n\Z"
)
BUS_SYMBOL_RESULT = re.compile(
    rb"U2_BUS_SYMBOL set=(?:present|absent) cycle=(?:present|absent)\n\Z"
)
ARCHIVES_RESULT = re.compile(
    rb"U2_ARCHIVES first=exact v2=exact active=absent\n\Z"
)


def main():
    selector = sys.argv[1] if len(sys.argv) == 2 else ""
    if len(sys.argv) > 2 or selector not in ("", "--relation", "--runtime", "--snapshot", "--layout", "--entitlements", "--cleanup", "--service-state", "--installed-state", "--dpkg-audit", "--native-journal", "--from-controller", "--trial-status", "--v2-postreboot", "--bus-symbol", "--archives"):
        raise ValueError("invalid selector")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    payload, digest, grammar = {
        "": (PAYLOAD, PAYLOAD_SHA256, RESULT),
        "--relation": (RELATION_PAYLOAD, RELATION_SHA256, RELATION_RESULT),
        "--runtime": (RUNTIME_PAYLOAD, RUNTIME_SHA256, RUNTIME_RESULT),
        "--snapshot": (SNAPSHOT_PAYLOAD, SNAPSHOT_SHA256, SNAPSHOT_RESULT),
        "--layout": (LAYOUT_PAYLOAD, LAYOUT_SHA256, LAYOUT_RESULT),
        "--entitlements": (ENTITLEMENTS_PAYLOAD, ENTITLEMENTS_SHA256, ENTITLEMENTS_RESULT),
        "--cleanup": (CLEANUP_PAYLOAD, CLEANUP_SHA256, CLEANUP_RESULT),
        "--service-state": (SERVICE_STATE_PAYLOAD, SERVICE_STATE_SHA256, SERVICE_STATE_RESULT),
        "--installed-state": (INSTALLED_STATE_PAYLOAD, INSTALLED_STATE_SHA256, INSTALLED_STATE_RESULT),
        "--dpkg-audit": (DPKG_AUDIT_PAYLOAD, DPKG_AUDIT_SHA256, DPKG_AUDIT_RESULT),
        "--native-journal": (NATIVE_JOURNAL_PAYLOAD, NATIVE_JOURNAL_SHA256, NATIVE_JOURNAL_RESULT),
        "--from-controller": (FROM_CONTROLLER_PAYLOAD, FROM_CONTROLLER_SHA256, FROM_CONTROLLER_RESULT),
        "--trial-status": (TRIAL_STATUS_PAYLOAD, TRIAL_STATUS_SHA256, TRIAL_STATUS_RESULT),
        "--v2-postreboot": (V2_POSTREBOOT_PAYLOAD, V2_POSTREBOOT_SHA256, V2_POSTREBOOT_RESULT),
        "--bus-symbol": (BUS_SYMBOL_PAYLOAD, BUS_SYMBOL_SHA256, BUS_SYMBOL_RESULT),
        "--archives": (ARCHIVES_PAYLOAD, ARCHIVES_SHA256, ARCHIVES_RESULT),
    }[selector]
    info = payload.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ValueError("unsafe payload")
    source = payload.read_bytes()
    if hashlib.sha256(source).hexdigest() != digest:
        raise ValueError("payload digest changed")
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0 or len(result.stdout) > 512 or not grammar.fullmatch(result.stdout):
        raise ValueError("read-only classifier failed")
    if result.stdout in (b"U2_RELATION rejected\n", b"U2_FROM_CONTROLLER rejected\n"):
        raise ValueError("read-only relation unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_DEFAULT rejected")
        raise SystemExit(1)
