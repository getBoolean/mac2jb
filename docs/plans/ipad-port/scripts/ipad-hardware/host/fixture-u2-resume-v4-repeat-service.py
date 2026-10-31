#!/usr/bin/env python3
"""Mac-only stale-socket gate fixture; never contacts the iPad."""

from contextlib import redirect_stdout
import errno
import io
import os
from pathlib import Path
import runpy
import socket
import stat
import subprocess
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[6]
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-resume-v4-repeat-service.py"


def main():
    functions = runpy.run_path(str(DEVICE))
    namespace = functions["main"].__globals__
    path = "/fixture/broker.sock"
    state = "stale"
    booted = False
    unlinked = []

    def lstat(name):
        if name != path or state == "absent":
            raise FileNotFoundError(name)
        mode = stat.S_IFREG if state == "file" else stat.S_IFSOCK
        return SimpleNamespace(st_mode=mode | 0o600, st_uid=0, st_nlink=1,
                               st_dev=1, st_ino=2)

    class Peer:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _seconds):
            pass

        def connect(self, name):
            assert name == path
            if state == "stale":
                raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
            if state == "timeout":
                raise socket.timeout("timed out")

    def unlink(name):
        nonlocal state
        assert name == path and state == "stale"
        unlinked.append(name)
        state = "absent"

    def bootstrap(command, **_kwargs):
        nonlocal booted
        assert command == [namespace["LAUNCHCTL"], "bootstrap", "system", namespace["PLIST"]]
        booted = True
        return subprocess.CompletedProcess(command, 0)

    with mock.patch.object(os, "lstat", side_effect=lstat), \
            mock.patch.object(os, "unlink", side_effect=unlink), \
            mock.patch.object(os, "geteuid", return_value=0), \
            mock.patch.object(socket, "socket", return_value=Peer()), \
            mock.patch.object(subprocess, "run", side_effect=bootstrap), \
            mock.patch.dict(namespace, {"SOCKET": path,
                                        "preconditions": lambda: None,
                                        "loaded": lambda _label: booted,
                                        "ready": lambda: booted}):
        with redirect_stdout(io.StringIO()):
            functions["main"]("--inspect")
            assert state == "stale" and not unlinked
            functions["main"]("--stage")
        assert booted and unlinked == [path] and state == "absent"

        for rejected in ("live", "timeout", "file"):
            state = rejected
            booted = False
            try:
                functions["main"]("--inspect")
            except ValueError:
                pass
            else:
                raise AssertionError(rejected + " socket accepted")
            assert state == rejected and unlinked == [path]
    print("U2_V4_REPEAT_SERVICE fixture=passed device=untouched")


if __name__ == "__main__":
    main()
