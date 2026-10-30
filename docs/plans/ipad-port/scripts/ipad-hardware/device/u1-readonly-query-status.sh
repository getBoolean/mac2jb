#!/bin/sh
# On-device U1 diagnostic payload. Observational only: raw ioreg output is never emitted.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

normalize_decimal() {
  case "$1" in
    ''|*[!0-9]*) command printf '%s' '255' ;;
    *) command printf '%s' "$1" ;;
  esac
}

count_service_query() {
  service_class=$1
  query_output=$(/usr/sbin/ioreg -r -d 1 -c "$service_class" 2>&-)
  query_status=$?
  service_count=0
  saved_ifs=$IFS
  IFS='
'
  case $- in
    *f*) restore_glob=0 ;;
    *) restore_glob=1; set -f ;;
  esac
  for scan_line in $query_output; do
    scan_prefix=$scan_line
    while :; do
      case "$scan_prefix" in
        ' '*) scan_prefix=${scan_prefix#?} ;;
        '|'*) scan_prefix=${scan_prefix#?} ;;
        *) break ;;
      esac
    done
    case "$scan_prefix" in
      '+-o '*) service_count=$((service_count + 1)) ;;
    esac
  done
  IFS=$saved_ifs
  if [ "$restore_glob" -eq 1 ]; then set +f; fi
}

count_service_query 'IOUSBDeviceController'
controller_status=$(normalize_decimal "$query_status")
controller_count=$service_count

count_service_query 'IOUSBDeviceInterface'
interface_status=$(normalize_decimal "$query_status")
interface_count=$service_count

configuration_output=$(/usr/sbin/ioreg -p IODeviceTree -r -k configuration-string -l 2>&-)
configuration_status=$(normalize_decimal "$?")
configuration_label='not observed'
saved_ifs=$IFS
IFS='
'
case $- in
  *f*) restore_glob=0 ;;
  *) restore_glob=1; set -f ;;
esac
for scan_line in $configuration_output; do
  scan_prefix=$scan_line
  while :; do
    case "$scan_prefix" in
      ' '*) scan_prefix=${scan_prefix#?} ;;
      '|'*) scan_prefix=${scan_prefix#?} ;;
      *) break ;;
    esac
  done
  case "$scan_prefix" in
    '"configuration-string"'*'='*) configuration_label='present' ;;
  esac
done
IFS=$saved_ifs
if [ "$restore_glob" -eq 1 ]; then set +f; fi

command printf '%s\n' \
  "controller-query-status: $controller_status" \
  "controller-service-count: $controller_count" \
  "interface-query-status: $interface_status" \
  "interface-service-count: $interface_count" \
  "configuration-query-status: $configuration_status" \
  "configuration-string: $configuration_label"
