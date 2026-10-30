#!/var/jb/usr/bin/python3
"""Sample only the three exact U2 launchd labels twice, eight seconds apart.

This distinguishes a stable running retained v4 broker from a launchd restart
loop after reboot. It does not connect to any broker socket, read journal
contents, boot out a job, or touch the USB controller.
"""

import os
import subprocess
import time

LAUNCHCTL = "/var/jb/bin/launchctl"
LABELS = (
    ("v4", "system/dev.mac2jb.u2.nooptrialv4"),
    ("v5", "system/dev.mac2jb.u2.nooptrialv5"),
    ("original", "system/dev.mac2jb.u2.watchdog"),
)


def state(label):
    result = subprocess.run([LAUNCHCTL, "print", label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("oversized launchd status")
    if result.returncode:
        return "absent"
    return "running" if b"state = running" in result.stdout else "loaded-stopped"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    for round_number in (1, 2):
        values = {key: state(label) for key, label in LABELS}
        print("U2_POSTREBOOT_JOBS round=" + str(round_number) +
              " v4=" + values["v4"] + " v5=" + values["v5"] +
              " original=" + values["original"], flush=True)
        if round_number == 1:
            time.sleep(8)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_POSTREBOOT_JOBS rejected")
        raise SystemExit(1)
