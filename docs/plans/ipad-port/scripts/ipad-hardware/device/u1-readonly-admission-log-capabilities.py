#!/var/jb/usr/bin/python3
"""Find read-only code-admission evidence sources after a SIGKILL.

What this code does: classify only fixed system log tool paths and crash-log
directories by file type and access. It never executes a log tool, reads log
contents, prints filenames, or changes the iPad. Later inspection, if any,
must filter private identifiers before output leaves the device.
"""

import os
import stat


PATHS = {
    "system-log": "/usr/bin/log",
    "rootless-log": "/var/jb/usr/bin/log",
    "system-syslog": "/usr/bin/syslog",
    "rootless-dmesg": "/var/jb/usr/bin/dmesg",
    "mobile-crash": "/var/mobile/Library/Logs/CrashReporter",
    "private-mobile-crash": "/private/var/mobile/Library/Logs/CrashReporter",
    "rootless-mobile-crash": "/var/jb/var/mobile/Library/Logs/CrashReporter",
    "system-crash": "/var/log/CrashReporter",
}


def main():
    for label, path in PATHS.items():
        try:
            info = os.lstat(path)
            category = ("directory" if stat.S_ISDIR(info.st_mode)
                        else "regular" if stat.S_ISREG(info.st_mode)
                        else "other")
            readable = os.access(path, os.R_OK)
        except OSError:
            category = "absent-or-inaccessible"
            readable = False
        print("ADMISSION_LOG " + label + "=" + category + ":" +
              ("readable" if readable else "unreadable"))


if __name__ == "__main__":
    main()
