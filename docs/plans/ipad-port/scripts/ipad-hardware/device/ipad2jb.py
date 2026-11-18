#!/var/jb/usr/bin/python3
"""ipad2jb: make this iPad type text as a USB keyboard on whatever host it is plugged into.

Usage (on the iPad, e.g. in NewTerm):   sudo ipad2jb [--cycle] [--keyboard-only] [TEXT]
TEXT defaults to "ipad2jb"; letters, digits and spaces only. --cycle also takes
the iPad off and on the bus after configuring the keyboard (not needed so far;
unconfirmed whether it is needed). --keyboard-only publishes the configuration
with the Keyboard interface alone (no AppleUSBMux), for hosts that only handle a
single-interface keyboard.

What it does, with no Mac involved:
  1. Checks the USB broker is idle and a host has selected a USB configuration.
  2. Journals the stock USB description (broker `prepare`).
  3. Starts the keyboard canary, which takes the broker's lease.
  4. Publishes a single "Standard Keyboard" configuration [AppleUSBMux, Keyboard]
     in place of the host-selected one. The controller goes on bus once the
     canary has configured the keyboard function, so the host sees a keyboard.
  5. The canary waits for the host to poll, types TEXT, and exits. Its exit
     returns the lease and the broker restores the stock USB description.
  6. Verifies on the iPad that the stock functions are all back, and (if a host
     is attached) that the controller is on bus, then confirms the broker's
     journal. If verification fails the journal is left open and nothing else
     is touched; the broker keeps healing and the Mac tools can confirm later.

Files: canary /var/jb/usr/libexec/ipad2jb/keyboard-canary; broker socket
/var/jb/var/lib/mac2jb-u2-native/broker.sock. Must run as root.
"""

import ctypes
import hashlib
import json
import os
import plistlib
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

CANARY = "/var/jb/usr/libexec/ipad2jb/keyboard-canary"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET_PATH = STATE + "/broker.sock"
PROFILE = STATE + "/device-profile.json"
LAUNCHCTL = "/var/jb/bin/launchctl"
BROKER_LABEL = re.compile(r"dev\.(ipad2jb\.usbbroker|mac2jb\.u2\.[a-z0-9]{1,24})\Z")
IDLE = "OK phase=absent publication=enabled"
CANARY_OUTPUT = []
TEXT = re.compile(r"[A-Za-z0-9 ]{1,64}\Z")


LOG_DIR = "/var/jb/var/log/ipad2jb"
LOG_LINES = []


def say(message):
    LOG_LINES.append(time.strftime("%H:%M:%S ") + message)
    print("ipad2jb: " + message, flush=True)


def save_log(extra=""):
    """The last run's messages and canary output, for diagnosis afterwards."""
    try:
        os.makedirs(LOG_DIR, mode=0o755, exist_ok=True)
        with open(os.path.join(LOG_DIR, "last-run.txt"), "w") as handle:
            handle.write("\n".join(LOG_LINES) + "\n" + extra)
    except OSError:
        pass


def ask(command, timeout=150):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(timeout)
        peer.connect(SOCKET_PATH)
        peer.sendall(command.encode() + b"\n")
        return peer.recv(512).decode("ascii", "replace").strip()


# --- IOKit: the sole USB device controller, its CurrentState, and function nubs ---

IO = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
CF = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
IO.IOServiceMatching.argtypes = (ctypes.c_char_p,)
IO.IOServiceMatching.restype = ctypes.c_void_p
IO.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_uint32))
IO.IOIteratorNext.argtypes = (ctypes.c_uint32,)
IO.IOIteratorNext.restype = ctypes.c_uint32
IO.IOObjectRelease.argtypes = (ctypes.c_uint32,)
IO.IORegistryEntryGetRegistryEntryID.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64))
IO.IORegistryEntryCreateCFProperty.argtypes = (ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_uint32)
IO.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
CF.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
CF.CFStringCreateWithCString.restype = ctypes.c_void_p
CF.CFRelease.argtypes = (ctypes.c_void_p,)
CF.CFPropertyListCreateData.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long,
                                        ctypes.c_ulong, ctypes.c_void_p)
CF.CFPropertyListCreateData.restype = ctypes.c_void_p
CF.CFDataGetLength.argtypes = (ctypes.c_void_p,)
CF.CFDataGetLength.restype = ctypes.c_long
CF.CFDataGetBytePtr.argtypes = (ctypes.c_void_p,)
CF.CFDataGetBytePtr.restype = ctypes.c_void_p
UTF8 = 0x08000100


def services(class_name):
    matching = IO.IOServiceMatching(class_name)
    iterator = ctypes.c_uint32()
    if not matching or IO.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator)):
        return []
    found = []
    while True:
        entry = IO.IOIteratorNext(iterator.value)
        if not entry:
            break
        found.append(entry)
    IO.IOObjectRelease(iterator.value)
    return found


def property_value(entry, key):
    name = CF.CFStringCreateWithCString(None, key.encode(), UTF8)
    value = IO.IORegistryEntryCreateCFProperty(entry, name, None, 0)
    CF.CFRelease(name)
    if not value:
        return None
    data = CF.CFPropertyListCreateData(None, value, 200, 0, None)
    CF.CFRelease(value)
    if not data:
        return None
    try:
        raw = ctypes.string_at(CF.CFDataGetBytePtr(data), CF.CFDataGetLength(data))
    finally:
        CF.CFRelease(data)
    return plistlib.loads(raw)


def controller():
    """(registry id, CurrentState dict) of the sole USB device controller."""
    entries = services(b"IOUSBDeviceController")
    try:
        if len(entries) != 1:
            raise ValueError("expected one USB device controller, found %d" % len(entries))
        identifier = ctypes.c_uint64()
        IO.IORegistryEntryGetRegistryEntryID(entries[0], ctypes.byref(identifier))
        state = property_value(entries[0], "CurrentState") or {}
        return identifier.value, state
    finally:
        for entry in entries:
            IO.IOObjectRelease(entry)


def registered_functions():
    entries = services(b"IOUSBDeviceInterface")
    names = set()
    for entry in entries:
        name = property_value(entry, "USBDeviceFunction")
        if isinstance(name, str):
            names.add(name)
        IO.IOObjectRelease(entry)
    return names


# --- broker housekeeping ---

def raise_broker_memory_limit(megabytes=96):
    """The broker's jetsam limit resets to 6 MB when launchd restarts it, which
    kills it during a publication. Raise it on the running process (root only)."""
    listing = subprocess.run([LAUNCHCTL, "list"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=20).stdout.decode("utf-8", "replace")
    for line in listing.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and BROKER_LABEL.fullmatch(fields[2].strip()) and fields[0].isdigit():
            pid = int(fields[0])
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.memorystatus_control.argtypes = (ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32,
                                                  ctypes.c_void_p, ctypes.c_size_t)
            request = ctypes.create_string_buffer(struct.pack("<iIiI", megabytes, 0, megabytes, 0), 16)
            if libc.memorystatus_control(7, pid, 0, request, 16) != 0:
                raise ValueError("could not raise the broker's memory limit")
            return
    raise ValueError("the USB broker is not running")


class Renewal:
    """Keeps the publication's lease alive while the canary works."""

    def __init__(self):
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.wait(10):
            try:
                ask("renew-lease", timeout=20)
            except OSError:
                pass

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=25)


class Canary:
    def __init__(self, registry_id, text):
        self.process = subprocess.Popen(
            [CANARY, "--function", "Keyboard", "--controller", str(registry_id),
             "--lease-seconds", "600", "--hold-until-released", "yes", "--text", text],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        self.output = b""

    def wait_for(self, marker, seconds, required=None):
        deadline = time.monotonic() + seconds
        scanned = 0
        while True:
            for line in self.output[scanned:].splitlines(True):
                if not line.endswith(b"\n"):
                    break
                scanned += len(line)
                if line.startswith(marker) and (required is None or required in line):
                    return line
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                return None
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                return None
            self.output += chunk

    def release_and_collect(self, seconds=180):
        # communicate() closes the canary's input itself, which is the release
        # signal. Closing it first made older Pythons raise "I/O operation on
        # closed file" when communicate() flushed it.
        try:
            rest = self.process.communicate(timeout=seconds)[0]
        except subprocess.TimeoutExpired:
            self.process.kill()
            rest = self.process.communicate(timeout=10)[0]
        self.output += rest or b""
        return self.process.returncode, self.output.decode("ascii", "replace")


def verify_and_confirm(seconds=120):
    """Device-side restore check, then confirm the journal. Returns True when cleared."""
    with open(PROFILE) as handle:
        expected = set(json.load(handle)["functions"])
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        status = ask("status")
        _, state = controller()
        missing = sorted(expected - registered_functions())
        selected = state.get("SelectedConfiguration")
        on_bus = state.get("OnBus")
        host_ok = on_bus is True and isinstance(selected, int) and selected > 0
        last = ("status=%s missing=%s on-bus=%s selected=%s"
                % (status, ",".join(missing) or "none", on_bus, selected))
        if status == "OK phase=recoveryRequired publication=enabled" and not missing and host_ok:
            # The broker restored and wants a heal before verification: `heal`
            # records awaitingVerification once the controller is configured,
            # exactly as the Mac confirmation tool does first.
            last += " heal=" + ask("heal")
            continue
        if status == "OK phase=awaitingVerification publication=enabled" and not missing and host_ok:
            evidence = ("ipad2jb device-side restore check %s %s\n" % (time.time(), last)).encode()
            reply = ask("confirm " + hashlib.sha256(evidence).hexdigest())
            if reply == "OK verified-and-cleared":
                return True, last
            last += " confirm=" + reply
            break
        if status == IDLE:
            return True, last
        time.sleep(2)
    return False, last


def main(text, cycle=False, keyboard_only=False):
    if os.geteuid() != 0:
        raise ValueError("run as root: sudo ipad2jb")
    if not TEXT.fullmatch(text):
        raise ValueError("text must be 1-64 letters, digits or spaces")
    if not os.path.isfile(CANARY):
        raise ValueError("keyboard canary missing at " + CANARY)
    raise_broker_memory_limit()
    status = ask("status")
    if status != IDLE:
        if "awaitingVerification" in status or "recoveryRequired" in status:
            say("an earlier run left the restore unverified; checking it now")
            cleared, detail = verify_and_confirm()
            if not cleared:
                raise ValueError("earlier restore still unverified (%s)" % detail)
        else:
            raise ValueError("USB broker is busy (%s)" % status)
    registry_id, state = controller()
    selected = state.get("SelectedConfiguration")
    if not isinstance(selected, int) or selected < 1 or state.get("OnBus") is not True:
        raise ValueError("no USB host has selected a configuration; plug the iPad into the host first")
    say("host selected USB configuration %d" % selected)

    if ask("prepare") != "OK prepared":
        raise ValueError("broker would not journal the stock USB description")
    canary = Canary(registry_id, text)
    renewal = None
    try:
        if canary.wait_for(b"U3_HID_CANARY lease=held", 20) is None:
            raise ValueError("keyboard canary did not take the broker lease")
        renewal = Renewal()
        interfaces = "Keyboard" if keyboard_only else "AppleUSBMux,Keyboard"
        reply = ask("publish-sole-configuration %d %s" % (selected, interfaces))
        if reply != "OK published-sole-configuration":
            raise ValueError("broker refused to publish the keyboard (%s)" % reply)
        say("keyboard published; waiting for it to be configured")
        if canary.wait_for(b"U3_HID_CANARY operations ", 60, b"aborted-by=255") is None:
            raise ValueError("keyboard function was not configured")
        # No bus cycle by default. The keyboard function registers only once
        # the canary has configured it, and the controller goes on bus only
        # after every function registered, so the host's first enumeration
        # already sees a complete keyboard. On the Switch 2 an explicit cycle
        # left the SuperSpeed link in Compliance until the cable was replugged.
        if cycle:
            reply = ask("cycle-bus")
            if not reply.startswith("OK bus-cycled"):
                raise ValueError("bus cycle refused (%s)" % reply)
        say("waiting for the host to start reading the keyboard, then typing %r" % text)
    finally:
        code, output = canary.release_and_collect()
        if renewal is not None:
            renewal.finish()
    CANARY_OUTPUT.append(output)
    enumerated = re.search(r"enumeration host=([a-z-]+)", output)
    written = re.search(r"reports written=(\d+) stop=([A-Za-z]+)", output)
    expected_reports = 2 * len(text)
    typed = written is not None and int(written.group(1)) == expected_reports \
        and written.group(2) == "completed"
    say("host %s; %s of %d key reports collected by the host"
        % ("enumerated the keyboard" if enumerated and enumerated.group(1) == "enumerated"
           else "did not enumerate the keyboard",
           written.group(1) if written else "0", expected_reports))
    say("restoring stock USB")
    cleared, detail = verify_and_confirm()
    if cleared:
        say("stock USB restored and verified on the iPad")
    else:
        say("restore not verified yet (%s); the broker keeps healing it" % detail)
    return 0 if typed and cleared else 2


if __name__ == "__main__":
    try:
        arguments = sys.argv[1:]
        if arguments in (["-h"], ["--help"]):
            print(__doc__, end="")
            raise SystemExit(0)
        cycle = "--cycle" in arguments
        keyboard_only = "--keyboard-only" in arguments
        arguments = [item for item in arguments if item not in ("--cycle", "--keyboard-only")]
        code = main(" ".join(arguments) if arguments else "ipad2jb", cycle=cycle,
                    keyboard_only=keyboard_only)
        save_log("\n--- canary ---\n" + "".join(CANARY_OUTPUT))
        raise SystemExit(code)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        say("stopped: %s" % error)
        save_log("\n--- canary ---\n" + "".join(CANARY_OUTPUT))
        raise SystemExit(1)
