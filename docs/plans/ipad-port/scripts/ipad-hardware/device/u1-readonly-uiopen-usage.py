#!/var/jb/usr/bin/python3
"""Classify the installed uiopen CLI's no-argument usage without launching an app.

What this code does: run the fixed rootless uiopen executable with zero
arguments, bound it to three seconds and 2 KiB of captured output, and print
only whether its usage mentions a URL, bundle ID, or path. It does not pass a
target app/URL, alter files, or change USB/SSH configuration.
"""

import subprocess


def main():
    try:
        result = subprocess.run(["/var/jb/usr/bin/uiopen"],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=3)
    except subprocess.TimeoutExpired:
        print("UIOPEN_USAGE status=timeout")
        return
    data = (result.stdout + result.stderr)[:2048].lower()
    print("UIOPEN_USAGE status=" + str(result.returncode))
    for label, term in (("usage", b"usage"), ("url", b"url"),
                        ("bundle", b"bundle"), ("path", b"path")):
        print("UIOPEN_USAGE " + label + "=" + ("yes" if term in data else "no"))


if __name__ == "__main__":
    main()
