#!/var/jb/usr/bin/python3
"""Verify the U1 TrollStore test apps are uninstalled and remove their staged packages.

Effect: `--inspect` is read-only: lists installed app bundles whose
CFBundleIdentifier starts with dev.mac2jb. in the standard app roots, the
presence and SHA-256 of each fixed staged /var/mobile/Media/.mac2jb-u1-*.tipa,
and the ClientTruth.plist SHA-256. `--remove` additionally requires no
dev.mac2jb. app installed and unlinks only staged packages whose SHA-256
matches the Mac-built package. Nothing else is touched.
"""

import glob
import hashlib
import os
import plistlib
import stat
import sys

MEDIA = "/var/mobile/Media/"
TIPAS = {
    ".mac2jb-u1-stdout-toolbox.tipa": "c97a5d9f60a67329b3b1946e478e95f1afc903d51a7cb7902d8dbdc9a4309f13",
    ".mac2jb-u1-platform-admission.tipa": "e91aa892c3c1a80db00ae8884e8dbacb31fe9e03a3ac551c3f244c6ca975d85a",
    ".mac2jb-u1-ordinary-admission.tipa": "7dd7817c863b7add70a8d13f3764b05db8d39837283706ceb99cef635cdec961",
    ".mac2jb-u1-springboard-r2-baseline.tipa": "565ad2fd8b4d90130fd29e562ad446911a5364be67f7c8e1b3547b43b8f06c1a",
    ".mac2jb-u1-springboard-r2-setdescription.tipa": "0424a37259f8c873d474dcd1965ccdcc386f0d39814f408869432f2aa235d65d",
    ".mac2jb-u1-debug-ordinary.tipa": "3f2875acb9da2da2ebad2424aeb9570aa15bfaf49865f225458784281d21d37f",
    ".mac2jb-u1-springboard-marker.tipa": "2f76c3dca4ea0b19fa352fc274f1bfd5b65a9fc74d39fcd70247e65852965c72",
}
ROOTS = ("/var/containers/Bundle/Application/*/*.app", "/Applications/*.app",
         "/var/jb/Applications/*.app")
CLIENTTRUTH = ("/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/"
               "Library/ConfigurationProfiles/ClientTruth.plist")


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def apps():
    found = []
    for pattern in ROOTS:
        for bundle in glob.glob(pattern):
            try:
                with open(bundle + "/Info.plist", "rb") as handle:
                    ident = plistlib.load(handle).get("CFBundleIdentifier", "")
            except (OSError, plistlib.InvalidFileException):
                continue
            if isinstance(ident, str) and ident.startswith("dev.mac2jb."):
                found.append(ident)
    return sorted(found)


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--remove"):
        raise ValueError("fixed root mode required")
    installed = apps()
    print("U1_CLEANUP apps=%s" % (",".join(installed) or "none"))
    present = {}
    for name, digest in sorted(TIPAS.items()):
        path = MEDIA + name
        if not os.path.lexists(path):
            print("U1_CLEANUP tipa=%s state=absent" % name)
            continue
        info = os.lstat(path)
        actual = sha(path) if stat.S_ISREG(info.st_mode) else "not-regular"
        match = "exact" if actual == digest else "different"
        present[name] = match
        print("U1_CLEANUP tipa=%s state=present digest=%s" % (name, match))
    print("U1_CLEANUP clienttruth-sha256=%s" % sha(CLIENTTRUTH))
    if mode == "--inspect":
        return
    if installed:
        raise ValueError("apps still installed")
    removed = 0
    for name, match in present.items():
        if match == "exact":
            os.unlink(MEDIA + name)
            removed += 1
    directory = os.open(MEDIA, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print("U1_CLEANUP removed=%d kept-nonmatching=%d" % (removed, sum(m != "exact" for m in present.values())))


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError) as error:
        print("U1_CLEANUP rejected (%s)" % error)
        raise SystemExit(1)
