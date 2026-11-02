#!/usr/bin/env python3
"""Exercise the Mac string-probe envelope parser without a USB device."""

from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[6]
PROBE = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/probe-u2-readonly-string-descriptors.py"))


def rejects(parser, data):
    try:
        parser(data)
    except (ValueError, UnicodeError):
        return
    raise AssertionError("malformed string evidence accepted")


def main():
    languages = PROBE["languages"]
    strings = PROBE["strings"]
    assert languages(b"U2LANG1\0\x04\x03\x09\x04") == [0x0409]
    rejects(languages, b"U2LANG1\0\x04\x03\x00\x00")
    rejects(languages, b"U2LANG1\0\x04\x03\x09")
    good = b"U2STR1\0\0\x09\x04\x01\x05\x04\x04\x03A\x00"
    language, values = strings(good)
    assert language == 0x0409 and values == {5: b"\x04\x03A\x00"}
    rejects(strings, good + b"x")
    rejects(strings, good[:-1])
    rejects(strings, b"U2STR1\0\0\x09\x04\x02" + good[11:] * 2)
    rejects(strings, b"U2STR1\0\0\x09\x04\x01\x00\x04\x04\x03A\x00")
    print("PASS U2 string-descriptor envelope parser")


if __name__ == "__main__":
    main()
