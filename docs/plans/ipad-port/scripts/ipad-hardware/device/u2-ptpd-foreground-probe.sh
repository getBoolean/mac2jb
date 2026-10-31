#!/bin/sh
# Start the stock /usr/libexec/ptpd with its launchd arguments (-t usb) as the
# current account, detached, then report after 4 s and 12 s whether it is still
# alive. Leaves it running if alive (it is the normal USB PTP owner). Writes
# only its stdout/stderr to a private temporary file which it then prints
# truncated and removes. No USB controller call, journal, or broker access.
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/var/jb/usr/bin:/var/jb/bin
if [ -n "$(ps -A -o comm= | grep -x '/usr/libexec/ptpd')" ]; then echo "PTPD_PROBE already-running"; exit 2; fi
out=$(mktemp /tmp/ptpd-probe.XXXXXX) || exit 1
/usr/libexec/ptpd -t usb >"$out" 2>&1 &
pid=$!
sleep 4; if kill -0 $pid 2>/dev/null; then a4=alive; else a4=exited; fi
sleep 8; if kill -0 $pid 2>/dev/null; then a12=alive; else wait $pid; a12="exited:$?"; fi
echo "PTPD_PROBE t4=$a4 t12=$a12"
head -c 600 "$out" | tr -cd '[:print:]\n' | sed 's/^/PTPD_OUT /'
rm -f "$out"
