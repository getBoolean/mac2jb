#!/usr/bin/env python3
"""Find the target iPad's Wi-Fi address without exposing it in output.

What this code does: passively browse local Apple companion-link Bonjour
advertisements, resolve only one iPad-named service to a private IPv4 address,
then try the existing pinned Mac identity and USB-established SSH host key at
that address. It runs only `id -u` as mobile and root; successful verification
stores the address in the private Mac credential directory for later reuse.
No iPad file, SSH policy, USB setting, or system file is changed. Ordinary SSH
connection/accounting logs are possible. An ambiguous or unverified match is
rejected without saving an address.
"""

import ipaddress
import os
from pathlib import Path
import re
import runpy
import signal
import socket
import subprocess


HERE = Path(__file__).resolve().parent
HELPER = HERE / "backup-clienttruth-over-root-ssh.py"
ADDRESS_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/wifi-ipv4")
SERVICE = "_companion-link._tcp"
SERVICE_MARKER = SERVICE + "."
HOST_KEY_ALIAS = "[127.0.0.1]:2222"
PRIVATE = tuple(ipaddress.IPv4Network(value) for value in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
HOST_PATTERN = re.compile(r"can be reached at ([A-Za-z0-9_.-]+):[0-9]+")


def query_dns_sd(arguments, seconds):
    child = subprocess.Popen(["/usr/bin/dns-sd", *arguments],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        output, _ = child.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        child.send_signal(signal.SIGINT)
        try:
            output, _ = child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            output, _ = child.communicate()
    if len(output) > 65536:
        raise RuntimeError("Bonjour output exceeded cap")
    return output.decode("utf-8", "replace")


def candidate_address():
    browse = query_dns_sd(["-B", SERVICE, "local."], 6)
    names = set()
    for line in browse.splitlines():
        if " Add " in line and SERVICE_MARKER in line:
            name = line.split(SERVICE_MARKER, 1)[1].strip()
            if "ipad" in name.lower() and 0 < len(name) <= 128:
                names.add(name)
    if len(names) != 1:
        raise RuntimeError("iPad Bonjour service absent or ambiguous")
    name = next(iter(names))
    resolved = query_dns_sd(["-L", name, SERVICE, "local."], 5)
    hosts = set(HOST_PATTERN.findall(resolved))
    if len(hosts) != 1:
        raise RuntimeError("Bonjour target resolution failed")
    addresses = set()
    for result in socket.getaddrinfo(next(iter(hosts)), None, socket.AF_INET,
                                     socket.SOCK_STREAM):
        address = ipaddress.IPv4Address(result[4][0])
        if any(address in network for network in PRIVATE):
            addresses.add(str(address))
    if len(addresses) != 1:
        raise RuntimeError("private target address absent or ambiguous")
    return next(iter(addresses))


def main():
    if ADDRESS_FILE.exists() or ADDRESS_FILE.is_symlink():
        raise RuntimeError("private address file already exists")
    helper = runpy.run_path(str(HELPER))
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    address = candidate_address()
    for account, expected in (("mobile", b"501"), ("root", b"0")):
        command = ["/usr/bin/ssh", *helper["ssh_options"](),
                   "-o", "HostKeyAlias=" + HOST_KEY_ALIAS,
                   "-o", "AddressFamily=inet", "-T", "-p", "22",
                   account + "@" + address, "/var/jb/usr/bin/id -u"]
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=12)
        if result.returncode != 0 or result.stdout.strip() != expected:
            raise RuntimeError("pinned SSH target verification failed")
    descriptor = os.open(ADDRESS_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o600)
    try:
        data = (address + "\n").encode("ascii")
        if os.write(descriptor, data) != len(data):
            raise RuntimeError("private address write incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print("WIRELESS_DISCOVERY pinned-mobile-root=ok address=stored-privately")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired,
            socket.gaierror) as error:
        print("WIRELESS_DISCOVERY rejected " + type(error).__name__)
        raise SystemExit(1)
