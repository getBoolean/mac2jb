#!/usr/bin/env python3
"""Compare USB configuration descriptors by resolved string values.

This is a pure, offline comparison. The caller supplies two private raw
configuration streams and their separately captured STRING descriptors.
It requires equal framing and all non-string bytes; each referenced string
must resolve to equal UTF-16LE content even if its numeric index changed.
It does not claim host interface/driver, pairing, or journal equivalence.
"""

from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[6]
RAW = runpy.run_path(str(ROOT / "scripts/ipad-hardware/host/diagnose-u2-semantic-descriptors.py"))
STRINGS = runpy.run_path(str(ROOT / "scripts/ipad-hardware/host/probe-u2-readonly-string-descriptors.py"))


def references(descriptor):
    if len(descriptor) < 2:
        raise ValueError("short descriptor")
    kind = descriptor[1]
    if kind == 2:
        if len(descriptor) < 9:
            raise ValueError("short configuration descriptor")
        return (6,)
    if kind == 4:
        if len(descriptor) < 9:
            raise ValueError("short interface descriptor")
        return (8,)
    if kind == 11:
        if len(descriptor) < 8:
            raise ValueError("short association descriptor")
        return (7,)
    if kind == 0x24 and len(descriptor) >= 3 and descriptor[2] == 0x0F:
        if len(descriptor) < 4:
            raise ValueError("short CDC Ethernet descriptor")
        return (3,)
    return ()


def compare(before_raw, before_strings, after_raw, after_strings):
    before_language, original = STRINGS["strings"](before_strings)
    after_language, current = STRINGS["strings"](after_strings)
    if before_language != after_language:
        raise ValueError("USB string language changed")
    old_configs = RAW["configurations"](before_raw)
    new_configs = RAW["configurations"](after_raw)
    changed_indices = resolved = 0
    for old_config, new_config in zip(old_configs, new_configs):
        old_descriptors = RAW["descriptors"](old_config)
        new_descriptors = RAW["descriptors"](new_config)
        if len(old_descriptors) != len(new_descriptors):
            raise ValueError("descriptor count changed")
        for old, new in zip(old_descriptors, new_descriptors):
            if len(old) != len(new) or old[1] != new[1]:
                raise ValueError("descriptor framing changed")
            positions = references(old)
            if positions != references(new):
                raise ValueError("string reference positions changed")
            for index, (left, right) in enumerate(zip(old, new)):
                if index not in positions and left != right:
                    raise ValueError("non-string descriptor byte changed")
            for position in positions:
                old_index, new_index = old[position], new[position]
                if old_index == new_index == 0:
                    continue
                if not old_index or not new_index:
                    raise ValueError("USB string reference added or removed")
                if old_index not in original or new_index not in current:
                    raise ValueError("USB string value unavailable")
                if original[old_index][2:] != current[new_index][2:]:
                    raise ValueError("USB string value changed")
                changed_indices += old_index != new_index
                resolved += 1
    return {"configurations": len(old_configs),
            "resolved_references": resolved,
            "renumbered_references": changed_indices}
