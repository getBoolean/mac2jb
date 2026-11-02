# Device payloads

Payloads that host tools stream to the device over pinned root (or mobile) SSH and run with the device's `/var/jb/usr/bin/python3 -I -S -B`. Each host wrapper pins the payload's SHA-256; change a payload only together with its wrapper's pin. Each file's docstring states its effect. Index: [`../../README.md`](../../README.md).
