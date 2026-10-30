#!/usr/bin/env python3
"""Run the reviewed U1 stdout probes twice and preserve only validated reports.

What this code does:
1. Before any network access, pins the SSH credentials, device launcher, stdout
   validator, and installed-toolbox attestation validator by SHA-256. It then
   revalidates the locally preserved installed app: exact file set and hashes,
   TrollStore-aware code identity, page hashes, and entitlements.
2. Runs baseline, set-description-only, controller-client, and interface-client
   twice, each in a fresh key-only SSH session. The device launcher receives the
   signed executable hash from the revalidated attestation and checks it before
   and after launch.
3. Gives every SSH and validator child a fresh process group, a wall deadline,
   and a regular-file output limit. Timeout, signal, oversized output, nonzero
   status, malformed JSON, or a validator mismatch kills and reaps the complete
   local group and stops all later device access.
4. Requires equal topology fingerprints across each variant's two rounds. Only
   after all eight reports pass does it publish raw reports and a local manifest
   through a Darwin no-replace rename beneath ignored build storage.

The remote path streams a shell script and report JSON only. It creates no iPad
file and invokes no mutation API. Expected device effects are reads, transient
process/IOKit state, access metadata, and ordinary SSH/system logs. The local
raw reports can contain registry details and must not be committed.

Security boundary: the authenticated ``mobile`` account is assumed honest, with
no concurrent same-UID process replacing installed app paths. Pre/post hashes
detect lasting replacement but cannot bind pathname execution against a
swap-and-restore race; Darwin exposes no usable ``fexecve`` path for this flow.

Installation and attestation are separate prerequisites; this runner never
installs or modifies the toolbox. The owner dropped mandatory adversarial
reviews on 2026-10-30; retain the exact input and read-only checks.
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile


SOURCE_FILE = Path(__file__).resolve()
SCRIPT_DIRECTORY = Path(
    os.environ.get("MAC2JB_SCRIPT_DIRECTORY", str(SOURCE_FILE.parent))
)
REPO_ROOT = (SCRIPT_DIRECTORY.parents[4]
             if SCRIPT_DIRECTORY.parent.parent.name == "ipad-port"
             else SCRIPT_DIRECTORY.parent.parent)
BUILD_DIRECTORY = REPO_ROOT / "build/ipad-hardware"
ATTESTATION_DIRECTORY = BUILD_DIRECTORY / "installed-toolbox-attestation"
IDENTITY_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-probe-ed25519")
KNOWN_HOSTS_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-known-hosts")
SSH = Path("/usr/bin/ssh")
EXPECTED_IDENTITY_SHA = "50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd"
EXPECTED_KNOWN_HOSTS_SHA = "1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35"
EXPECTED_LAUNCHER_SHA = "ef9854bc6f23ff4d386976b83401f5a342efd4cb97f7ae9eac7deaf110062511"
EXPECTED_REPORT_VALIDATOR_SHA = "7afa3421436d1598809f81c06629792cb41830b668e03f913c841adfe75455a9"
EXPECTED_ATTESTATION_VALIDATOR_SHA = "4b82e513f5573c01867ef2747fac540583a1ca48ccb15880583595b06fd882f0"
MAX_INPUT_SIZE = 2 * 1024 * 1024
MAX_REPORT_SIZE = 2 * 1024 * 1024
SSH_TIMEOUT = 45.0
VALIDATOR_TIMEOUT = 10.0
ATTESTATION_TIMEOUT = 60.0
ATTESTATION_FILE_LIMIT = 4 * 1024 * 1024
RENAME_EXCL = 0x00000004
VARIANTS = {
    "baseline": "mac2jb-u1-baseline",
    "setdescription": "Probes/mac2jb-u1-setdescription",
    "controller-client": "Probes/mac2jb-u1-controller-client",
    "interface-client": "Probes/mac2jb-u1-interface-client",
}
POWERS = {
    "operator-observed-vbus-charging",
    "operator-observed-vbus-not-charging",
    "operator-observed-no-vbus",
    "operator-not-observed",
}
PASS_PATTERN = re.compile(
    rb"PASS probe report ([0-9a-f]{64}) ([0-9a-f]{64})\n"
)
HEX64 = re.compile(r"[0-9a-f]{64}")
ACTIVE_PROCESS: subprocess.Popen[bytes] | None = None
RECEIVED_SIGNAL = 0


class Rejection(Exception):
    pass


class Interrupted(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejection(message)


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Rejection("duplicate JSON key")
        result[key] = value
    return result


def read_regular(path: Path, maximum: int, *, require_single_link: bool = True) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and (not require_single_link or status.st_nlink == 1)
            and 0 < status.st_size <= maximum,
            "unsafe regular file",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            require(total <= maximum, "file exceeded cap")
            chunks.append(chunk)
        data = b"".join(chunks)
        require(len(data) == status.st_size, "file extent changed")
        return data
    finally:
        os.close(descriptor)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def copy_pinned(source: Path, destination: Path, expected: str, maximum: int) -> bytes:
    data = read_regular(source, maximum)
    require(sha256(data) == expected, "pinned digest mismatch")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "short staged write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(sha256(read_regular(destination, maximum)) == expected, "staged digest")
    return data


def load_module(path: Path) -> object:
    specification = importlib.util.spec_from_file_location("mac2jb_attestation_validator", path)
    require(specification is not None and specification.loader is not None, "validator import")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def validate_attestation(staged_validator: Path, scratch: Path) -> tuple[str, dict[str, str]]:
    root_status = os.lstat(ATTESTATION_DIRECTORY)
    require(stat.S_ISDIR(root_status.st_mode), "attestation directory")
    require(
        set(item.name for item in ATTESTATION_DIRECTORY.iterdir())
        == {"Mac2JBU1-Toolbox.app", "attestation-manifest.json"},
        "attestation root layout",
    )
    manifest_path = ATTESTATION_DIRECTORY / "attestation-manifest.json"
    manifest_data = read_regular(manifest_path, MAX_INPUT_SIZE)
    try:
        manifest = json.loads(
            manifest_data.decode("ascii"),
            object_pairs_hook=reject_duplicate_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejection("attestation manifest") from error
    require(
        isinstance(manifest, dict)
        and set(manifest)
        == {
            "appDirectory",
            "archiveSha256",
            "bundleIdentifier",
            "code",
            "directories",
            "files",
            "schemaVersion",
            "sourceFamily",
        },
        "attestation manifest keys",
    )

    module = load_module(staged_validator)
    app_name = module.APP_NAME
    expected_files = module.EXPECTED_FILES
    expected_directories = module.EXPECTED_DIRECTORY_METADATA
    require(
        manifest["schemaVersion"] == 2
        and manifest["appDirectory"] == app_name
        and manifest["bundleIdentifier"] == module.EXPECTED_INFO["CFBundleIdentifier"]
        and manifest["sourceFamily"] in {"container", "system", "rootless"}
        and isinstance(manifest["archiveSha256"], str)
        and HEX64.fullmatch(manifest["archiveSha256"]) is not None,
        "attestation identity",
    )
    expected_directory_manifest = {
        relative or ".": {"gid": gid, "mode": f"{mode:04o}", "uid": uid}
        for relative, (mode, uid, gid) in expected_directories.items()
    }
    require(manifest["directories"] == expected_directory_manifest, "directory manifest")

    app = ATTESTATION_DIRECTORY / app_name
    expected_directory_paths = {app} | {
        app / relative for relative in expected_directories if relative
    }
    expected_file_paths = {app / relative for relative in expected_files}
    observed_directories: set[Path] = set()
    observed_files: set[Path] = set()
    for directory, names, files in os.walk(app, topdown=True, followlinks=False):
        directory_path = Path(directory)
        require(not directory_path.is_symlink(), "symlinked evidence directory")
        observed_directories.add(directory_path)
        for name in names:
            child = directory_path / name
            require(not child.is_symlink(), "symlinked evidence directory")
        for name in files:
            child = directory_path / name
            require(not child.is_symlink(), "symlinked evidence file")
            observed_files.add(child)
    require(
        observed_directories == expected_directory_paths
        and observed_files == expected_file_paths,
        "evidence app layout",
    )

    file_manifest = manifest["files"]
    require(isinstance(file_manifest, dict) and set(file_manifest) == set(expected_files), "file manifest")
    executable_hashes: dict[str, str] = {}
    for relative, expected_mode in expected_files.items():
        content = read_regular(app / relative, module.MAX_MEMBER_SIZE)
        record = file_manifest[relative]
        require(
            isinstance(record, dict)
            and set(record) == {"gid", "mode", "sha256", "size", "uid"}
            and record["uid"] == module.EXPECTED_CHILD_UID
            and record["gid"] == module.EXPECTED_CHILD_GID
            and record["mode"] == f"{expected_mode:04o}"
            and record["size"] == len(content)
            and record["sha256"] == sha256(content),
            "file manifest record",
        )
        if relative in module.EXPECTED_CODE:
            executable_hashes[relative] = record["sha256"]

    try:
        code_records = module.validate_reconstructed_app(app, scratch)
    except Interrupted:
        raise
    except Exception as error:
        raise Rejection("installed code revalidation") from error
    require(manifest["code"] == code_records, "code attestation record")
    require(set(executable_hashes) == set(VARIANTS.values()), "executable hash set")
    return sha256(manifest_data), executable_hashes


def attestation_helper(arguments: list[str]) -> int:
    if len(arguments) != 2:
        return 64
    try:
        manifest_sha, executable_hashes = validate_attestation(
            Path(arguments[0]),
            Path(arguments[1]),
        )
    except Interrupted:
        return 128 + RECEIVED_SIGNAL
    except (OSError, Rejection, ValueError, subprocess.SubprocessError):
        return 65
    result = {
        "executableHashes": executable_hashes,
        "manifestSha256": manifest_sha,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait()
    except ChildProcessError:
        pass


def handle_signal(signum: int, _frame: object) -> None:
    global RECEIVED_SIGNAL
    RECEIVED_SIGNAL = signum
    raise Interrupted()


def run_bounded(
    arguments: list[str],
    output: Path,
    *,
    timeout: float,
    output_limit: int,
    input_data: bytes | None = None,
    file_limit: int | None = None,
) -> int:
    global ACTIVE_PROCESS
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )

    handled = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled)

    def child_setup() -> None:
        child_file_limit = file_limit if file_limit is not None else output_limit
        resource.setrlimit(resource.RLIMIT_FSIZE, (child_file_limit, child_file_limit))
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    child_environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
    if "MAC2JB_SCRIPT_DIRECTORY" in os.environ:
        child_environment["MAC2JB_SCRIPT_DIRECTORY"] = str(SCRIPT_DIRECTORY)

    try:
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=descriptor,
                stderr=subprocess.DEVNULL,
                env=child_environment,
                start_new_session=True,
                preexec_fn=child_setup,
            )
            ACTIVE_PROCESS = process
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            process.communicate(input=input_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_process_group(process)
            return 125
        status = process.returncode
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if status is None or status < 0:
            return 125
        return status
    except BaseException:
        if "process" in locals():
            kill_process_group(process)
        raise
    finally:
        ACTIVE_PROCESS = None
        os.close(descriptor)


def run_attestation_preflight(
    staged_validator: Path,
    scratch: Path,
    result_path: Path,
) -> tuple[str, dict[str, str]]:
    status = run_bounded(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            str(SOURCE_FILE),
            "--internal-attestation",
            str(staged_validator),
            str(scratch),
        ],
        result_path,
        timeout=ATTESTATION_TIMEOUT,
        output_limit=64 * 1024,
        file_limit=ATTESTATION_FILE_LIMIT,
    )
    require(status == 0, "installed code revalidation failed")
    data = read_regular(result_path, 64 * 1024)
    require(data.endswith(b"\n") and not data.endswith(b"\n\n"), "attestation receipt framing")
    try:
        receipt = json.loads(
            data[:-1].decode("ascii"),
            object_pairs_hook=reject_duplicate_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejection("attestation receipt") from error
    require(
        isinstance(receipt, dict)
        and set(receipt) == {"executableHashes", "manifestSha256"}
        and isinstance(receipt["manifestSha256"], str)
        and HEX64.fullmatch(receipt["manifestSha256"]) is not None,
        "attestation receipt shape",
    )
    executable_hashes = receipt["executableHashes"]
    require(
        isinstance(executable_hashes, dict)
        and set(executable_hashes) == set(VARIANTS.values())
        and all(
            isinstance(value, str) and HEX64.fullmatch(value) is not None
            for value in executable_hashes.values()
        ),
        "attested executable hashes",
    )
    return receipt["manifestSha256"], executable_hashes


def remote_command(variant: str, peer: str, orientation: str, power: str, digest: str) -> str:
    clean_path = "/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin"
    base = (
        "exec 2>&-; set +euxv; env_path=; "
        "for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do "
        "if [ -f \"$candidate\" ] && [ ! -L \"$candidate\" ] && [ -r \"$candidate\" ] && "
        "[ -x \"$candidate\" ] && [ ! -w \"$candidate\" ]; then env_path=$candidate; break; fi; done; "
        "shell_path=; for candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash "
        "/var/jb/usr/bin/dash /var/jb/bin/bash /var/jb/usr/bin/bash; do "
        "if [ -f \"$candidate\" ] && [ ! -L \"$candidate\" ] && [ -r \"$candidate\" ] && "
        "[ -x \"$candidate\" ] && [ ! -w \"$candidate\" ]; then shell_path=$candidate; break; fi; done; "
        "if [ -z \"$env_path\" ]; then exit 127; fi; "
        "if [ -z \"$shell_path\" ]; then exit 126; fi; "
        f"\"$env_path\" -i PATH={shlex.quote(clean_path)} LC_ALL=C \"$shell_path\" -s -- "
    )
    return base + " ".join(shlex.quote(item) for item in (variant, peer, orientation, power, digest))


def ssh_arguments(remote: str, identity: Path, known_hosts: Path) -> list[str]:
    return [
        str(SSH),
        "-F", "/dev/null", "-T", "-p", "2222", "-i", str(identity),
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "KnownHostsCommand=none",
        "-o", "UpdateHostKeys=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
        "-o", "PermitLocalCommand=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        "-o", "NumberOfPasswordPrompts=0", "-o", "LogLevel=ERROR",
        "mobile@127.0.0.1", remote,
    ]


def write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "short evidence write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_exclusive(parent: Path, source: str, destination: str) -> None:
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        library = ctypes.CDLL(None, use_errno=True)
        function = library.renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        if function(descriptor, os.fsencode(source), descriptor, os.fsencode(destination), RENAME_EXCL) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(
    output: Path,
    staging: Path,
    reports: list[dict[str, object]],
    report_bytes: dict[str, bytes],
    manifest_sha: str,
) -> str:
    os.mkdir(staging, 0o700)
    staging_status = os.lstat(staging)
    published = False
    try:
        for name, data in report_bytes.items():
            write_exclusive(staging / name, data)
        manifest = {
            "attestationManifestSha256": manifest_sha,
            "launcherSha256": EXPECTED_LAUNCHER_SHA,
            "reportValidatorSha256": EXPECTED_REPORT_VALIDATOR_SHA,
            "reports": reports,
            "schemaVersion": 1,
        }
        manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii")
        write_exclusive(staging / "batch-manifest.json", manifest_data)
        fsync_directory(staging)
        rename_exclusive(output.parent, staging.name, output.name)
        published = True
        return sha256(manifest_data)
    finally:
        if not published:
            try:
                status = os.lstat(staging)
                if status.st_dev == staging_status.st_dev and status.st_ino == staging_status.st_ino:
                    shutil.rmtree(staging)
            except FileNotFoundError:
                pass


def run(arguments: list[str]) -> int:
    if len(arguments) != 3:
        print(
            "Usage: run-installed-toolbox-authorization-batch.py PEER ORIENTATION POWER_STATE",
            file=sys.stderr,
        )
        return 64
    peer, orientation, power = arguments
    if peer not in {"capture-host", "switch"} or orientation not in {"a", "b"} or power not in POWERS:
        return 64

    output = BUILD_DIRECTORY / f"probe-capture-{peer}-{orientation}-{power}"
    staging = BUILD_DIRECTORY / f".probe-capture-{peer}-{orientation}-{power}.staging"
    try:
        require(SCRIPT_DIRECTORY.is_absolute(), "script directory contract")
        script_directory_status = os.lstat(SCRIPT_DIRECTORY)
        require(
            stat.S_ISDIR(script_directory_status.st_mode)
            and not stat.S_ISLNK(script_directory_status.st_mode),
            "script directory contract",
        )
        build_status = os.lstat(BUILD_DIRECTORY)
        require(stat.S_ISDIR(build_status.st_mode), "build directory")
        require(not output.exists() and not output.is_symlink(), "capture already exists")
        require(not staging.exists() and not staging.is_symlink(), "stale capture staging")
        current_uid = os.getuid()
        for credential, modes in (
            (IDENTITY_FILE, {0o400, 0o600}),
            (KNOWN_HOSTS_FILE, {0o400, 0o440, 0o444, 0o600, 0o640, 0o644}),
        ):
            status = os.lstat(credential)
            require(
                stat.S_ISREG(status.st_mode)
                and status.st_nlink == 1
                and status.st_uid == current_uid
                and stat.S_IMODE(status.st_mode) in modes,
                "credential metadata",
            )

        with tempfile.TemporaryDirectory(prefix="mac2jb-u1-authorization-") as temporary:
            temporary_root = Path(temporary)
            staged_launcher = temporary_root / "launcher.sh"
            staged_report_validator = temporary_root / "report-validator.py"
            staged_attestation_validator = temporary_root / "attestation-validator.py"
            staged_identity = temporary_root / "identity"
            staged_known_hosts = temporary_root / "known-hosts"
            launcher_data = copy_pinned(
                SCRIPT_DIRECTORY / "device/u1-readonly-run-installed-toolbox-probe.sh",
                staged_launcher,
                EXPECTED_LAUNCHER_SHA,
                MAX_INPUT_SIZE,
            )
            copy_pinned(
                SCRIPT_DIRECTORY / "validate-probe-stdout.py",
                staged_report_validator,
                EXPECTED_REPORT_VALIDATOR_SHA,
                MAX_INPUT_SIZE,
            )
            copy_pinned(
                SCRIPT_DIRECTORY / "validate-installed-toolbox-trollstore.py",
                staged_attestation_validator,
                EXPECTED_ATTESTATION_VALIDATOR_SHA,
                MAX_INPUT_SIZE,
            )
            copy_pinned(IDENTITY_FILE, staged_identity, EXPECTED_IDENTITY_SHA, 64 * 1024)
            copy_pinned(KNOWN_HOSTS_FILE, staged_known_hosts, EXPECTED_KNOWN_HOSTS_SHA, 64 * 1024)
            attestation_scratch = temporary_root / "attestation-scratch"
            os.mkdir(attestation_scratch, 0o700)
            manifest_sha, executable_hashes = run_attestation_preflight(
                staged_attestation_validator,
                attestation_scratch,
                temporary_root / "attestation-result.json",
            )

            reports: list[dict[str, object]] = []
            report_bytes: dict[str, bytes] = {}
            for variant, executable in VARIANTS.items():
                fingerprints: list[str] = []
                for round_number in (1, 2):
                    report_name = f"{variant}-round-{round_number}.json"
                    report_path = temporary_root / report_name
                    remote = remote_command(
                        variant,
                        peer,
                        orientation,
                        power,
                        executable_hashes[executable],
                    )
                    ssh_status = run_bounded(
                        ssh_arguments(remote, staged_identity, staged_known_hosts),
                        report_path,
                        timeout=SSH_TIMEOUT,
                        output_limit=MAX_REPORT_SIZE,
                        input_data=launcher_data,
                    )
                    require(ssh_status == 0, "SSH or device launcher failed")
                    data = read_regular(report_path, MAX_REPORT_SIZE)

                    result_path = temporary_root / f"{variant}-round-{round_number}.result"
                    validator_status = run_bounded(
                        [
                            "/usr/bin/python3", "-I", "-S", str(staged_report_validator),
                            str(report_path), variant, peer, orientation, power,
                        ],
                        result_path,
                        timeout=VALIDATOR_TIMEOUT,
                        output_limit=4096,
                    )
                    require(validator_status == 0, "stdout report rejected")
                    result = read_regular(result_path, 4096)
                    match = PASS_PATTERN.fullmatch(result)
                    require(match is not None, "validator receipt")
                    report_sha = sha256(data[:-1]) if data.endswith(b"\n") else ""
                    require(report_sha == match.group(1).decode(), "report receipt hash")
                    fingerprint = match.group(2).decode()
                    fingerprints.append(fingerprint)
                    report_bytes[report_name] = data
                    reports.append(
                        {
                            "file": report_name,
                            "round": round_number,
                            "sha256": report_sha,
                            "topologyFingerprint": fingerprint,
                            "variant": variant,
                        }
                    )
                require(fingerprints[0] == fingerprints[1], "topology changed between rounds")

            published_sha = publish(output, staging, reports, report_bytes, manifest_sha)
    except Interrupted:
        return 128 + RECEIVED_SIGNAL
    except Rejection as error:
        print(f"Authorization batch rejected: {error}; no capture was accepted.", file=sys.stderr)
        return 65
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Authorization batch rejected; no capture was accepted.", file=sys.stderr)
        return 65
    print(f"PASS authorization batch {published_sha} {output.name}")
    return 0


if __name__ == "__main__":
    for handled in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled, handle_signal)
    if sys.argv[1:2] == ["--internal-attestation"]:
        raise SystemExit(attestation_helper(sys.argv[2:]))
    raise SystemExit(run(sys.argv[1:]))
