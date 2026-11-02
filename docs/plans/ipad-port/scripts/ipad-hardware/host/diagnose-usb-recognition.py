#!/usr/bin/env python3
"""Classify Mac-side iPad USB recognition without contacting or changing it.

This host-only tool reads the usbmux device list and two IORegistry planes. It
prints only counts, USB configuration numbers, iOS-service state, and whether
ChatGPT owns a USB user client under the iPad. Unique identifiers, registry
paths, raw process names, and raw command output stay in memory. A listener or
Finder sidebar entry alone does not prove that pinned USB SSH can work.
"""

import re
import subprocess


LIMIT = 16 * 1024 * 1024


def read(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(result.stdout) > LIMIT or len(result.stderr) > 4096:
        return None
    return result


def first_ipad_subtree(lines):
    for index, line in enumerate(lines):
        if "+-o " in line and "iPad" in line.split("+-o ", 1)[1].split("  <", 1)[0]:
            depth = len(line.split("+-o ", 1)[0])
            end = index + 1
            while end < len(lines):
                if "+-o " in lines[end] and len(lines[end].split("+-o ", 1)[0]) <= depth:
                    break
                end += 1
            return lines[index:end]
    return []


def field(lines, name):
    pattern = re.compile(r'"' + re.escape(name) + r'"\s*=\s*(\d+)')
    for line in lines:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return "unknown"


def main():
    usb = read(["/opt/homebrew/bin/idevice_id", "-l"])
    if usb is None:
        print("USBMUX query=unavailable")
    else:
        count = len([line for line in usb.stdout.splitlines() if line.strip()])
        print("USBMUX query=" + ("ok" if usb.returncode == 0 else "failed") +
              " count=" + str(count if usb.returncode == 0 else 0))

    raw = read(["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w0"])
    service = read(["/usr/sbin/ioreg", "-p", "IOService", "-l", "-w0"])
    if raw is None or raw.returncode != 0 or service is None or service.returncode != 0:
        print("IOREG query=unavailable")
        return
    raw_lines = raw.stdout.decode("utf-8", "replace").splitlines()
    service_lines = service.stdout.decode("utf-8", "replace").splitlines()
    raw_ipad = first_ipad_subtree(raw_lines)
    service_ipad = first_ipad_subtree(service_lines)
    print("IOREG raw-ipad=" + ("yes" if raw_ipad else "no") +
          " current-configuration=" + field(raw_ipad, "kUSBCurrentConfiguration") +
          " override=" + field(raw_ipad, "kUSBConfigurationCurrentOverride"))
    ios_nodes = [line for line in service_ipad
                 if "+-o AppleUSBHostiOSDevice" in line]
    if len(ios_nodes) == 1:
        state = "unregistered" if "!registered" in ios_nodes[0] else "registered"
        matched = "unmatched" if "!matched" in ios_nodes[0] else "matched"
        print("IOREG ios-service=" + state + "," + matched)
    else:
        print("IOREG ios-service=" + ("absent" if not ios_nodes else "ambiguous"))
    print("IOREG chatgpt-user-client=" +
          ("yes" if any("IOUserClientCreator" in line and "ChatGPT" in line
                        for line in service_ipad) else "no"))


if __name__ == "__main__":
    main()
