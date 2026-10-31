#!/var/jb/usr/bin/python3
"""Read-only export of the stock /usr/libexec/ptpd Mach-O for offline Mac analysis.

Effect: reads one fixed regular file (<= 8 MiB) and prints its SHA-256 and
base64 bytes. Starts nothing, writes nothing.
"""
import base64, hashlib, os, stat
PATH = "/usr/libexec/ptpd"
info = os.lstat(PATH)
if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
    raise SystemExit("PTPD_BINARY unsafe")
data = open(PATH, "rb").read()
print("PTPD_BINARY sha256=%s size=%d data=%s" % (hashlib.sha256(data).hexdigest(), len(data), base64.b64encode(data).decode()))
