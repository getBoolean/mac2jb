#!/usr/bin/env python3
"""Hermetically test the Mac-local U1 authorization evidence importer.

The harness builds temporary batch directories from the existing validated
probe-report fixture. It never opens SSH, never contacts the iPad, and never
writes outside its temporary directory.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types


REPO_ROOT = Path(__file__).resolve().parents[6]
SCRIPT = REPO_ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/summarize-u1-authorization-batch.py"
FIXTURE_SOURCE = REPO_ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/tests/test-ipad-probe-stdout-validator.py"
VARIANTS = (
    "baseline",
    "setdescription",
    "controller-client",
    "interface-client",
)


def load_fixture_module() -> object:
    module = types.ModuleType("probe_fixture")
    module.__file__ = "<probe fixture source>"
    code = compile(
        FIXTURE_SOURCE.read_bytes(),
        module.__file__,
        "exec",
        dont_inherit=True,
        optimize=0,
    )
    exec(code, module.__dict__)
    return module


FIXTURES = load_fixture_module()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_report(document: dict[str, object]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def write_batch(root: Path) -> None:
    reports: list[dict[str, object]] = []
    for variant_index, variant in enumerate(VARIANTS):
        for round_number in (1, 2):
            document = FIXTURES.fixture(variant=variant)
            document["capturedAt"] = (
                f"2026-10-29T18:{variant_index * 2 + round_number:02d}:00Z"
            )
            data = encode_report(document)
            name = f"{variant}-round-{round_number}.json"
            (root / name).write_bytes(data)
            reports.append(
                {
                    "file": name,
                    "round": round_number,
                    "sha256": digest(data[:-1]),
                    "topologyFingerprint": document["topologyFingerprint"],
                    "variant": variant,
                }
            )
    manifest = {
        "attestationManifestSha256": "a" * 64,
        "launcherSha256": "53f86a362b585077d11cbe97417cf12a7fa8f9c9c61d9867cd7836b78c06110c",
        "reportValidatorSha256": "7afa3421436d1598809f81c06629792cb41830b668e03f913c841adfe75455a9",
        "reports": reports,
        "schemaVersion": 1,
    }
    (root / "batch-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


def invoke(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-S", str(SCRIPT), str(root)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def load_manifest(root: Path) -> dict[str, object]:
    return json.loads((root / "batch-manifest.json").read_text(encoding="ascii"))


def store_manifest(root: Path, manifest: dict[str, object]) -> None:
    (root / "batch-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


def refresh_report_record(root: Path, name: str, document: dict[str, object]) -> None:
    data = encode_report(document)
    (root / name).write_bytes(data)
    manifest = load_manifest(root)
    for record in manifest["reports"]:
        if record["file"] == name:
            record["sha256"] = digest(data[:-1])
            record["topologyFingerprint"] = document["topologyFingerprint"]
    store_manifest(root, manifest)


def expect_rejected(root: Path) -> None:
    result = invoke(root)
    assert result.returncode == 65, (result.returncode, result.stdout, result.stderr)
    assert result.stdout == ""
    assert result.stderr == "Authorization evidence rejected; no summary was emitted.\n"


def test_valid_summary(root: Path) -> None:
    result = invoke(root)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["schemaVersion"] == 1
    assert summary["evidenceStatus"] == "unauthenticated-local-self-consistency-check"
    assert summary["provenance"]["authenticated"] is False
    assert summary["topologyComparison"] == "equal-within-unauthenticated-capture"
    assert summary["role"]["peerKind"] == "capture-host"
    assert summary["role"]["orientation"] == "a"
    assert len(summary["variants"]) == 4
    assert [item["variant"] for item in summary["variants"]] == list(VARIANTS)
    assert all(len(item["reportSha256"]) == 2 for item in summary["variants"])
    assert all("registryID" not in json.dumps(item) for item in summary["variants"])
    assert summary["source"]["assertedAttestationManifestSha256"] == "a" * 64
    baseline = summary["variants"][0]
    assert baseline["controllerCount"] == 1
    assert baseline["functionCount"] == 1
    assert baseline["linkedFunctionCount"] == 1
    assert baseline["unresolvedFunctionCount"] == 0
    assert baseline["privateReadback"]["IOUSBDeviceControllerCreate"]["ioReturn"] == 0


def test_manifest_rejections(base: Path) -> None:
    for mutate in (
        lambda manifest: manifest.update(schemaVersion=2),
        lambda manifest: manifest.update(launcherSha256="0" * 64),
        lambda manifest: manifest["reports"].pop(),
        lambda manifest: manifest["reports"][0].update(file="../report.json"),
        lambda manifest: manifest["reports"][0].update(sha256="f" * 64),
    ):
        root = Path(tempfile.mkdtemp(dir=base))
        write_batch(root)
        manifest = load_manifest(root)
        mutate(manifest)
        store_manifest(root, manifest)
        expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    path = root / "batch-manifest.json"
    text = path.read_text(encoding="ascii")
    path.write_text(text.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1'), encoding="ascii")
    expect_rejected(root)


def test_unresolved_function_summary(base: Path) -> None:
    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    for round_number in (1, 2):
        document = FIXTURES.fixture(variant="baseline")
        document["capturedAt"] = f"2026-10-29T18:{round_number:02d}:00Z"
        document["functions"][0].pop("controllerRegistryID")
        document["topologyFingerprint"] = FIXTURES.topology_fingerprint(document)
        refresh_report_record(
            root,
            f"baseline-round-{round_number}.json",
            document,
        )
    result = invoke(root)
    assert result.returncode == 0, result.stderr
    baseline = json.loads(result.stdout)["variants"][0]
    assert baseline["functionCount"] == 1
    assert baseline["linkedFunctionCount"] == 0
    assert baseline["unresolvedFunctionCount"] == 1


def test_layout_and_file_rejections(base: Path) -> None:
    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    (root / "extra").write_text("extra")
    expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    report = root / "baseline-round-1.json"
    report.unlink()
    report.symlink_to(root / "baseline-round-2.json")
    expect_rejected(root)

    real = Path(tempfile.mkdtemp(dir=base))
    write_batch(real)
    link = base / "linked-batch"
    link.symlink_to(real, target_is_directory=True)
    expect_rejected(link)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    report = root / "baseline-round-1.json"
    report.unlink()
    os.mkfifo(report)
    expect_rejected(root)


def test_report_rejections(base: Path) -> None:
    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    path = root / "baseline-round-1.json"
    path.write_bytes(path.read_bytes() + b"\n")
    expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    document = FIXTURES.fixture(variant="baseline")
    document["capturedAt"] = "2026-10-29T18:01:00Z"
    document["role"]["orientation"] = "b"
    document["topologyFingerprint"] = FIXTURES.topology_fingerprint(document)
    refresh_report_record(root, "baseline-round-1.json", document)
    expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    document = FIXTURES.fixture(variant="baseline")
    document["capturedAt"] = "2026-10-29T18:01:00Z"
    document["operations"][0]["kind"] = "mutation"
    document["topologyFingerprint"] = FIXTURES.topology_fingerprint(document)
    refresh_report_record(root, "baseline-round-1.json", document)
    expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    for variant in VARIANTS:
        for round_number in (1, 2):
            document = FIXTURES.fixture(variant=variant)
            document["capturedAt"] = (
                "2026-10-29T18:01:00Z"
                if round_number == 1
                else "2026-10-29T18:02:00Z"
            )
            document["role"]["peerKind"] = "unreviewed-peer"
            document["role"]["peerIdentity"] = FIXTURES.identity(
                "mac2jb-nintendo-switch-primary"
            )
            document["topologyFingerprint"] = FIXTURES.topology_fingerprint(document)
            refresh_report_record(
                root,
                f"{variant}-round-{round_number}.json",
                document,
            )
    expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    document = FIXTURES.fixture(variant="baseline")
    document["capturedAt"] = "2026-10-29T18:02:00Z"
    document["controllers"][0]["name"] = "changed-controller"
    document["topologyFingerprint"] = FIXTURES.topology_fingerprint(document)
    refresh_report_record(root, "baseline-round-2.json", document)
    expect_rejected(root)

    root = Path(tempfile.mkdtemp(dir=base))
    write_batch(root)
    first = root / "baseline-round-1.json"
    second = root / "baseline-round-2.json"
    second.write_bytes(first.read_bytes())
    manifest = load_manifest(root)
    for record in manifest["reports"]:
        if record["file"] == "baseline-round-2.json":
            record["sha256"] = digest(second.read_bytes()[:-1])
            record["topologyFingerprint"] = FIXTURES.fixture(
                variant="baseline"
            )["topologyFingerprint"]
    store_manifest(root, manifest)
    result = invoke(root)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["evidenceStatus"] == "unauthenticated-local-self-consistency-check"
    assert summary["provenance"]["authenticated"] is False


def test_source_has_no_device_transport() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported.isdisjoint({"socket", "subprocess"})
    for forbidden in ('"/usr/bin/ssh"', '"mobile@', '"scp"'):
        assert forbidden not in source


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-u1-summary-tests-") as temporary:
        base = Path(temporary)
        valid = base / "valid"
        valid.mkdir()
        write_batch(valid)
        test_valid_summary(valid)
        test_manifest_rejections(base)
        test_unresolved_function_summary(base)
        test_layout_and_file_rejections(base)
        test_report_rejections(base)
        test_source_has_no_device_transport()
    print("PASS U1 authorization summary tests (6 groups, 19 scenarios)")


if __name__ == "__main__":
    main()
