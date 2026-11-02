#!/usr/bin/env python3
"""Validate the source-only kernel gadget candidate gate.

This test is Mac-only and performs no device or network access.  The Markdown
matrix contains one machine-readable JSON block so the safety classification
cannot drift away from the prose unnoticed.
"""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
MATRIX = ROOT / "docs/plans/ipad-port/research/kernel-gadget-candidate-matrix.md"
START = "<!-- candidate-matrix:start -->"
END = "<!-- candidate-matrix:end -->"

REQUIRED_CANDIDATES = {
    "existing-class-reuse",
    "catalogue-existing-class",
    "volatile-code-existing-classes",
    "new-arm64e-class",
    "match-path-patch",
}
REQUIRED_FIELDS = {
    "id", "mechanism", "executable_code", "pac_vtable", "catalogue_mutation",
    "persistence", "same_boot_removal", "rollback_owner", "build_dependence",
    "hid_report_path", "highest_public_evidence", "source_disposition", "blockers",
}
INTERMEDIATE_STATES = {
    "none", "code-executed", "entry-called", "service-registered",
    "personality-installed",
}


def load_matrix(text):
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError("matrix must contain exactly one marked data block")
    body = text.split(START, 1)[1].split(END, 1)[0].strip()
    if not body.startswith("```json\n") or not body.endswith("\n```"):
        raise ValueError("marked data block must be a fenced JSON object")
    value = json.loads(body[len("```json\n"):-len("\n```")])
    if set(value) != {"schema_version", "verdict", "candidates"}:
        raise ValueError("unexpected top-level matrix fields")
    if value["schema_version"] != 1 or value["verdict"] not in {
            "advance-to-read-only-profile", "source-only-stop"}:
        raise ValueError("invalid schema version or verdict")
    return value


def candidate_can_advance(candidate):
    missing = REQUIRED_FIELDS - set(candidate)
    extra = set(candidate) - REQUIRED_FIELDS
    if missing or extra:
        raise ValueError("candidate fields mismatch: missing=%s extra=%s" %
                         (sorted(missing), sorted(extra)))
    if not isinstance(candidate["blockers"], list):
        raise ValueError("candidate blockers must be a list")
    if candidate["persistence"] != "volatile":
        return False
    if candidate["same_boot_removal"] != "source-supported":
        return False
    if candidate["rollback_owner"] != "surviving-independent-owner":
        return False
    if candidate["highest_public_evidence"] in INTERMEDIATE_STATES:
        return False
    if candidate["hid_report_path"] != "source-supported":
        return False
    return not candidate["blockers"]


def validate(matrix):
    candidates = matrix["candidates"]
    if not isinstance(candidates, list):
        raise ValueError("candidates must be a list")
    ids = [candidate.get("id") for candidate in candidates]
    if len(ids) != len(set(ids)) or set(ids) != REQUIRED_CANDIDATES:
        raise ValueError("candidate set is incomplete or duplicated")
    advancing = [candidate["id"] for candidate in candidates
                 if candidate_can_advance(candidate)]
    expected = ("advance-to-read-only-profile" if advancing else "source-only-stop")
    if matrix["verdict"] != expected:
        raise ValueError("verdict disagrees with classified candidates")
    for candidate in candidates:
        disposition = ("advance" if candidate["id"] in advancing else "stop")
        if candidate["source_disposition"] != disposition:
            raise ValueError("candidate disposition disagrees with its evidence: " +
                             candidate["id"])
    return advancing


def fixture(candidate_id="fixture", **changes):
    value = {
        "id": candidate_id,
        "mechanism": "fixture",
        "executable_code": "not-required",
        "pac_vtable": "not-required",
        "catalogue_mutation": "not-required",
        "persistence": "volatile",
        "same_boot_removal": "source-supported",
        "rollback_owner": "surviving-independent-owner",
        "build_dependence": "none",
        "hid_report_path": "source-supported",
        "highest_public_evidence": "function-bound",
        "source_disposition": "advance",
        "blockers": [],
    }
    value.update(changes)
    return value


def check_safety_rules():
    assert candidate_can_advance(fixture())
    assert not candidate_can_advance(fixture(rollback_owner="none"))
    assert not candidate_can_advance(fixture(
        persistence="boot-image-replacement", same_boot_removal="reboot-only"))
    for state in ("code-executed", "service-registered"):
        assert not candidate_can_advance(fixture(highest_public_evidence=state))


def main():
    check_safety_rules()
    matrix = load_matrix(MATRIX.read_text(encoding="utf-8"))
    advancing = validate(matrix)
    print("PASS U3 source-only candidate matrix; advancing=" +
          (",".join(advancing) if advancing else "none"))


if __name__ == "__main__":
    main()
