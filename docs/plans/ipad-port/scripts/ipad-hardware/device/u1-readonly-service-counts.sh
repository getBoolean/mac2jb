#!/bin/sh
# On-device U1 discovery payload. Observational only.
# On normal completion, output order is controller count, then interface count.

# Close diagnostics before executing any path-bearing command.
exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

count_services() {
  service_class=$1
  service_count=$(
    /usr/sbin/ioreg -r -d 1 -c "$service_class" 2>&- |
      /var/jb/usr/bin/grep -c -E '^[[:space:]|]*\+-o[[:space:]]' 2>&-
  )
  case "$service_count" in
    ''|*[!0-9]*) service_count=0 ;;
  esac
}

count_services 'IOUSBDeviceController'
controller_count=$service_count

count_services 'IOUSBDeviceInterface'
interface_count=$service_count

command printf '%s\n%s\n' "$controller_count" "$interface_count"
