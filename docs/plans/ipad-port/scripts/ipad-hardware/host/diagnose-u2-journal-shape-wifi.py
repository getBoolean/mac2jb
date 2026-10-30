#!/usr/bin/env python3
"""Classify the retained native U2 journal format over pinned read-only SSH.

This diagnostic sends only fixed Python source to root stdin. It checks file
type/owner/mode/size, parses the envelope/record in memory, and prints only
categorical shape/checksum/phase results. It does not print recipe bytes,
controller identity, serial, boot token, or raw journal content, and it makes
no iPad file or USB change. Keep the journal intact on any failure.
"""

import runpy
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[6]
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
PAYLOAD = b'''import base64,hashlib,json,os,stat\n\
p="/var/jb/var/lib/mac2jb-u2-native/restore-journal.json"\n\
try:\n\
 i=os.lstat(p)\n\
 print("JOURNAL_SHAPE file="+("regular" if stat.S_ISREG(i.st_mode) else "other")+" owner="+("root" if i.st_uid==0 else "other")+" mode="+oct(stat.S_IMODE(i.st_mode))+" size="+("bounded" if 0<i.st_size<=2000000 else "other"))\n\
 d=open(p,"rb").read(2000001)\n\
 e=json.loads(d)\n\
 print("JOURNAL_SHAPE envelope="+("expected" if set(e)=={"payload","sha256"} else "other"))\n\
 b=base64.b64decode(e["payload"],validate=True)\n\
 print("JOURNAL_SHAPE checksum="+("match" if hashlib.sha256(b).hexdigest()==e["sha256"] else "other"))\n\
 r=json.loads(b)\n\
 print("JOURNAL_SHAPE record="+("expected" if set(r)=={"recipe","phase","leaseDeadlineUptime","externalVerificationSHA256"} else "other")+" phase="+(r.get("phase") if r.get("phase") in {"prepared","published","restoring","recoveryRequired","restored"} else "other"))\n\
 print("JOURNAL_SHAPE record-keys="+",".join(sorted(r)))\n\
except Exception:\n\
 print("JOURNAL_SHAPE parse=failed")\n'''


def main():
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=PAYLOAD, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode != 0 or len(result.stdout) > 400:
        raise ValueError("journal diagnostic unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("JOURNAL_SHAPE rejected")
        raise SystemExit(1)
