# iPad hardware test scripts

All Mac-local test harnesses for iPad hardware discovery and U1 safety tooling live in this directory. Operational host scripts remain one level up under `scripts/ipad-hardware/`; exact on-device payloads remain under `scripts/ipad-hardware/device/`.

Run one harness from the repository root:

```sh
python3 scripts/ipad-hardware/tests/test-ipad-trollstore-packaging.py
```

Run every Python harness:

```sh
for test_file in scripts/ipad-hardware/tests/test-ipad-*.py; do
  python3 "$test_file" || exit
done
```

The harnesses are Mac-local. Tests that model iPad behavior use temporary fixtures and fake SSH/tool processes; they do not contact the physical device.
