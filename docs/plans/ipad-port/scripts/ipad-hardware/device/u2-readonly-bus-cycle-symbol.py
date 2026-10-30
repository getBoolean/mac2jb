#!/var/jb/usr/bin/python3
"""Check only whether the exact USB controller symbols resolve on this iPad.

This opens the IOKit image and looks up SetDescription and GoOffAndOnBus by
name. It never calls either function, opens no USB user client, and changes
no file, controller, bus, or service. Presence does not prove ABI or safety.
"""

import ctypes
import os


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    image = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    set_description = getattr(image, "IOUSBDeviceControllerSetDescription", None)
    cycle = getattr(image, "IOUSBDeviceControllerGoOffAndOnBus", None)
    print("U2_BUS_SYMBOL set=" + ("present" if set_description else "absent") +
          " cycle=" + ("present" if cycle else "absent"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        print("U2_BUS_SYMBOL rejected")
        raise SystemExit(1)
