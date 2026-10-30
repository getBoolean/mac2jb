#!/var/jb/usr/bin/python3
"""Check fixed on-device app-launch CLI paths without launching anything.

What this code does: lstat a short fixed list of jailbreak app-opening tools
and report only executable/type categories. It never invokes a tool, reads a
user file, or changes the iPad. A later launch must use the exact bundle ID.
"""

import os
import stat


TOOLS = {
    "uiopen": ("/var/jb/usr/bin/uiopen", "/var/jb/bin/uiopen",
               "/usr/bin/uiopen", "/bin/uiopen"),
    "open": ("/var/jb/usr/bin/open", "/var/jb/bin/open",
             "/usr/bin/open", "/bin/open"),
    "appinst": ("/var/jb/usr/bin/appinst", "/var/jb/bin/appinst"),
    "uicache": ("/var/jb/usr/bin/uicache", "/var/jb/bin/uicache"),
}


def main():
    for name, paths in TOOLS.items():
        labels = []
        for path in paths:
            try:
                info = os.lstat(path)
                labels.append("executable" if stat.S_ISREG(info.st_mode)
                              and info.st_mode & 0o111 else "other")
            except OSError:
                labels.append("absent")
        print("APP_CLI " + name + "=" + ",".join(labels))


if __name__ == "__main__":
    main()
