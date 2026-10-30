#!/var/jb/usr/bin/python3
"""Check one TrollStore helper and an unused toolbox destination.

What this code does: inspect bounded app bundle candidates, identify the
installed standard TrollStore by its Info.plist bundle ID, require a regular
executable root helper within that bundle, reject an existing MAC2JB toolbox
bundle or staged IPA, and report only fixed categories. It neither starts
TrollStore nor changes the iPad. The installer repeats these checks.
"""

import glob
import os
import plistlib
import stat


STAGED = "/var/mobile/Media/.mac2jb-u1-stdout-toolbox.tipa"
GLOBS = ("/var/containers/Bundle/Application/*/TrollStore*.app",
         "/Applications/TrollStore*.app", "/var/jb/Applications/TrollStore*.app",
         "/var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app",
         "/Applications/Mac2JBU1-Toolbox.app",
         "/var/jb/Applications/Mac2JBU1-Toolbox.app")


def candidates():
    paths = []
    for pattern in GLOBS:
        paths.extend(glob.glob(pattern))
    if len(paths) > 32:
        raise SystemExit(65)
    return paths


def bundle_id(path):
    try:
        if os.path.islink(path):
            return None
        info = path + "/Info.plist"
        st = os.lstat(info)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 262144:
            return None
        with open(info, "rb") as file:
            tree = plistlib.load(file)
        return tree.get("CFBundleIdentifier") if isinstance(tree, dict) else None
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return None


def main():
    if os.geteuid() != 0:
        raise SystemExit(66)
    matches = [path for path in candidates()
               if bundle_id(path) == "com.opa334.TrollStore"]
    toolbox = [path for path in candidates()
               if bundle_id(path) == "dev.mac2jb.u1probe.toolbox"]
    helper_ok = False
    if len(matches) == 1:
        helper = matches[0] + "/trollstorehelper"
        try:
            st = os.lstat(helper)
            helper_ok = (stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                         and bool(st.st_mode & 0o111))
        except OSError:
            pass
    print("TOOLBOX_PREFLIGHT trollstore=" + ("one" if len(matches) == 1 else "other"))
    print("TOOLBOX_PREFLIGHT helper=" + ("executable" if helper_ok else "unavailable"))
    print("TOOLBOX_PREFLIGHT toolbox=" + ("absent" if not toolbox else "present"))
    print("TOOLBOX_PREFLIGHT staged=" + ("absent" if not os.path.lexists(STAGED) else "present"))


if __name__ == "__main__":
    main()
