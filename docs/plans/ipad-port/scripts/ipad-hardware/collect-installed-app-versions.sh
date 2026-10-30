#!/bin/sh
# Read-only CoreDevice collector for the exact Dopamine and TrollStore app builds.
# Do not run until this exact revision passes adversarial review with an explicit
# finding that no reachable command makes a persistent target-device change.
#
# What this script does:
# 1. Asks Apple's `devicectl` for the currently available-device inventory and
#    selects the single `iPad14,5` record without printing its name, serial,
#    UDID, or CoreDevice identifier. Stale known-device records are excluded by
#    CoreDevice's documented `State = available` filter.
# 2. Uses that private local identifier only as a quoted argument to two
#    read-only installed-app inventories: one exact Dopamine bundle-ID query and
#    one TrollStore bundle-prefix search. Default/removable apps are included,
#    while App Clips and container paths remain excluded.
# 3. Parses all JSON documents locally under isolated Python, accepts only the
#    official Dopamine bundle identifier and the standard or stealth TrollStore
#    identifier family, and emits only sanitized version/build labels.
# 4. Keeps raw JSON and the device identifier in a mode-0700 temporary directory,
#    caps each document at 8 MiB, suppresses command diagnostics, and removes all
#    temporary evidence on every normal, error, or handled-signal exit.
#
# The device operations are inventory reads. CoreDevice/lockdown and process logs,
# local temporary-file metadata, and ordinary access/accounting metadata may still
# change incidentally. No install, uninstall, mount, launch, pairing, trust, file
# transfer, or other target mutation command is present.

set +euxv
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
LC_ALL=C
export PATH LC_ALL
umask 077

if [ "$#" -ne 0 ]; then
  command printf '%s\n' 'Usage: collect-installed-app-versions.sh' >&2
  exit 64
fi

readonly target_product_type='iPad14,5'
readonly xcrun_path='/usr/bin/xcrun'

if [ ! -f "$xcrun_path" ] || [ -L "$xcrun_path" ] || [ ! -x "$xcrun_path" ]; then
  command printf '%s\n' 'The fixed xcrun executable is unavailable.' >&2
  exit 66
fi

temp_dir=$(/usr/bin/mktemp -d /tmp/mac2jb-app-versions.XXXXXX) || exit 70
case "$temp_dir" in /tmp/mac2jb-app-versions.*) ;; *) exit 70 ;; esac
devices_json="$temp_dir/devices.json"
dopamine_apps_json="$temp_dir/dopamine-apps.json"
trollstore_apps_json="$temp_dir/trollstore-apps.json"
device_id_file="$temp_dir/device-id"
result_file="$temp_dir/result"

cleanup() {
  /bin/rm -f "$devices_json" "$dopamine_apps_json" "$trollstore_apps_json" \
    "$device_id_file" "$result_file" 2>/dev/null
  /bin/rmdir "$temp_dir" 2>/dev/null
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

process_runner_code='import os
import signal
import subprocess
import sys

handled = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
received = 0


class Interrupted(Exception):
    pass


def handler(signum, _frame):
    global received
    received = signum
    signal.pthread_sigmask(signal.SIG_BLOCK, handled)
    raise Interrupted()


def kill_and_reap(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait()
    except ChildProcessError:
        pass


previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled)
for item in handled:
    signal.signal(item, handler)


def restore_child_mask():
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


try:
    process = subprocess.Popen(
        sys.argv[1:],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=restore_child_mask,
    )
except BaseException:
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    raise
try:
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    try:
        status = process.wait(timeout=25)
    except subprocess.TimeoutExpired:
        kill_and_reap(process)
        raise SystemExit(125)
except Interrupted:
    kill_and_reap(process)
    raise SystemExit(128 + received)
except BaseException:
    kill_and_reap(process)
    raise
if status < 0:
    kill_and_reap(process)
    raise SystemExit(125)
raise SystemExit(status)'

run_bounded() (
  # macOS `ulimit -f` uses 512-byte blocks: 16,384 blocks is 8 MiB.
  ulimit -f 16384 2>/dev/null || exit 70
  exec /usr/bin/env -i PATH="$PATH" LC_ALL=C \
    /usr/bin/python3 -I -S -c "$process_runner_code" "$@"
)

if ! run_bounded "$xcrun_path" devicectl list devices \
  --filter "State = 'available'" --timeout 10 --json-output "$devices_json"; then
  command printf '%s\n' 'CoreDevice device inventory failed; no app query ran.' >&2
  exit 69
fi

/usr/bin/python3 -I -S -c 'import json
import os
import re
import stat
import sys

source, output, target = sys.argv[1:]
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
status = os.fstat(fd)
if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or not 0 < status.st_size <= 8 * 1024 * 1024:
    raise SystemExit(65)
def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


with os.fdopen(fd, "r", encoding="utf-8") as handle:
    document = json.load(handle, object_pairs_hook=reject_duplicate_keys)


identifier_pattern = re.compile(r"[A-Za-z0-9._:-]{1,128}")
matches = []
if not isinstance(document, dict) or not isinstance(document.get("result"), dict):
    raise SystemExit(65)
devices = document["result"].get("devices")
if not isinstance(devices, list):
    raise SystemExit(65)
for record in devices:
    if not isinstance(record, dict):
        raise SystemExit(65)
    hardware = record.get("hardwareProperties")
    if not isinstance(hardware, dict) or hardware.get("productType") != target:
        continue
    matches.append(record)
if len(matches) != 1:
    valid_identifiers = [
        record.get("identifier")
        for record in matches
        if isinstance(record.get("identifier"), str)
        and identifier_pattern.fullmatch(record["identifier"])
    ]
    def count_class(value):
        return "zero" if value == 0 else "one" if value == 1 else "multiple"
    def yes_no(value):
        return "yes" if value else "no"
    all_valid = len(valid_identifiers) == len(matches)
    all_same = all_valid and len(set(valid_identifiers)) == 1
    identical = bool(matches) and all(record == matches[0] for record in matches[1:])
    print(
        "target-selection: "
        f"records={count_class(len(matches))} "
        f"valid-identifiers={count_class(len(valid_identifiers))} "
        f"unique-identifiers={count_class(len(set(valid_identifiers)))} "
        f"all-valid={yes_no(all_valid)} "
        f"all-same={yes_no(all_same)} "
        f"records-identical={yes_no(identical)}",
        file=sys.stderr,
    )
    raise SystemExit(66)
identifier = matches[0].get("identifier")
if not isinstance(identifier, str) or not identifier_pattern.fullmatch(identifier):
    print("target-selection: records=one identifier=invalid", file=sys.stderr)
    raise SystemExit(66)
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.write(descriptor, (identifier + "\n").encode("ascii"))
os.close(descriptor)
' "$devices_json" "$device_id_file" "$target_product_type" || {
  command printf '%s\n' 'The exact target could not be selected without ambiguity.' >&2
  exit 66
}

device_id=$(/bin/cat "$device_id_file") || exit 70
case "$device_id" in ''|*[!A-Za-z0-9._:-]*) exit 66 ;; esac
if [ "${#device_id}" -gt 128 ]; then exit 66; fi

if ! run_bounded "$xcrun_path" devicectl device info apps \
  --device "$device_id" --include-default-apps --include-removable-apps \
  --no-include-app-clips --bundle-id com.opa334.Dopamine \
  --timeout 15 --json-output "$dopamine_apps_json"; then
  command printf '%s\n' 'CoreDevice Dopamine app inventory failed.' >&2
  exit 69
fi

if ! run_bounded "$xcrun_path" devicectl device info apps \
  --device "$device_id" --include-default-apps --include-removable-apps \
  --no-include-app-clips --search com.opa334.TrollStore \
  --timeout 15 --json-output "$trollstore_apps_json"; then
  command printf '%s\n' 'CoreDevice TrollStore app inventory failed.' >&2
  exit 69
fi

/usr/bin/python3 -I -S -c 'import json
import os
import re
import stat
import sys

sources = sys.argv[1:-1]
output = sys.argv[-1]
if len(sources) != 2:
    raise SystemExit(65)
def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


documents = []
for source in sources:
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    status = os.fstat(fd)
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or not 0 < status.st_size <= 8 * 1024 * 1024:
        raise SystemExit(65)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        documents.append(json.load(handle, object_pairs_hook=reject_duplicate_keys))


def normalized(key):
    return "".join(character for character in key.lower() if character.isalnum())


def unique_direct_value(node, accepted_keys):
    values = set()
    for key, value in node.items():
        if normalized(str(key)) in accepted_keys and isinstance(value, (str, int)):
            values.add(str(value))
    if len(values) > 1:
        raise ValueError("conflicting metadata aliases")
    return next(iter(values)) if values else None


safe_value = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_() -]{0,63}")
bundle_keys = {"bundleidentifier", "bundleid"}
version_keys = {"version", "shortversion", "bundleshortversion", "cfbundleshortversionstring"}
build_keys = {"build", "buildversion", "bundleversion", "cfbundleversion"}
found = {"dopamine": set(), "trollstore": set()}
apps = []
for document in documents:
    if not isinstance(document, dict) or not isinstance(document.get("result"), dict):
        raise SystemExit(65)
    document_apps = document["result"].get("apps")
    if not isinstance(document_apps, list):
        raise SystemExit(65)
    apps.extend(document_apps)
for node in apps:
    if not isinstance(node, dict):
        raise SystemExit(65)
    bundle = unique_direct_value(node, bundle_keys)
    if bundle is None:
        continue
    lower = bundle.lower()
    if lower == "com.opa334.dopamine":
        label = "dopamine"
        family = "standard"
    elif lower == "com.opa334.trollstore" or lower.startswith("com.opa334.trollstore.ts_"):
        label = "trollstore"
        family = "standard" if lower == "com.opa334.trollstore" else "stealth"
    else:
        continue
    version = unique_direct_value(node, version_keys) or "not-observed"
    build = unique_direct_value(node, build_keys) or "not-observed"
    if version != "not-observed" and not safe_value.fullmatch(version):
        raise SystemExit(65)
    if build != "not-observed" and not safe_value.fullmatch(build):
        raise SystemExit(65)
    found[label].add((version, build, family))
for values in found.values():
    if len(values) > 1:
        raise SystemExit(66)


def render(label):
    values = found[label]
    if not values:
        return f"{label}-app: not-observed"
    version, build, family = next(iter(values))
    return f"{label}-app: version={version} build={build} bundle-family={family}"

lines = [render("dopamine"), render("trollstore")]
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.write(descriptor, ("\n".join(lines) + "\n").encode("ascii"))
os.close(descriptor)
' "$dopamine_apps_json" "$trollstore_apps_json" "$result_file" || {
  command printf '%s\n' 'Installed-app metadata was malformed or ambiguous.' >&2
  exit 65
}

line_count=$(/usr/bin/wc -l < "$result_file" | /usr/bin/tr -d ' ')
if [ "$line_count" != 2 ]; then exit 65; fi
/bin/cat "$result_file"
exit 0
