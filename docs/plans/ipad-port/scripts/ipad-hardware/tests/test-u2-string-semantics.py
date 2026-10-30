#!/usr/bin/env python3
"""Test value-based USB string equivalence without a connected device."""

from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[6]
COMPARE = runpy.run_path(str(ROOT / "scripts/ipad-hardware/host/u2-string-semantics.py"))["compare"]


def raw(config_string, interface_string, mac_string, endpoint_count=0):
    configs = []
    for number in range(1, 6):
        interface = bytes((9, 4, 0, 0, endpoint_count, 2, 6, 0, interface_string))
        ethernet = bytes((13, 0x24, 0x0F, mac_string)) + bytes(9)
        length = 9 + len(interface) + len(ethernet)
        header = bytes((9, 2, length, 0, 1, number, config_string, 0x80, 50))
        configs.append(header + interface + ethernet)
    return b"U2CFGD1\0" + bytes((5,)) + b"".join(
        len(config).to_bytes(2, "little") + config for config in configs)


def strings(values):
    entries = []
    for index, value in sorted(values.items()):
        encoded = value.encode("utf-16-le")
        descriptor = bytes((len(encoded) + 2, 3)) + encoded
        entries.append(bytes((index, len(descriptor))) + descriptor)
    return b"U2STR1\0\0\x09\x04" + bytes((len(entries),)) + b"".join(entries)


def rejects(*arguments):
    try:
        COMPARE(*arguments)
    except ValueError:
        return
    raise AssertionError("semantic USB difference accepted")


def main():
    original_raw = raw(1, 2, 3)
    renumbered_raw = raw(4, 5, 6)
    original_strings = strings({1: "Configuration", 2: "Interface", 3: "A1B2C3D4E5F6"})
    renumbered_strings = strings({4: "Configuration", 5: "Interface", 6: "A1B2C3D4E5F6"})
    result = COMPARE(original_raw, original_strings,
                     renumbered_raw, renumbered_strings)
    assert result == {"configurations": 5, "resolved_references": 15,
                      "renumbered_references": 15}
    rejects(original_raw, original_strings, raw(4, 5, 6, endpoint_count=1),
            renumbered_strings)
    rejects(original_raw, original_strings, renumbered_raw,
            strings({4: "Configuration", 5: "Changed", 6: "A1B2C3D4E5F6"}))
    rejects(original_raw, original_strings, raw(4, 0, 6), renumbered_strings)
    rejects(original_raw, original_strings, renumbered_raw,
            strings({4: "Configuration", 5: "Interface"}))
    print("PASS U2 resolved USB string semantics")


if __name__ == "__main__":
    main()
