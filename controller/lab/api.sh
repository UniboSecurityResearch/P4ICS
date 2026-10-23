#!/bin/bash
# Client of the controller API, with the admin certificate of the lab.
#   p4ics-api [METHOD] PATH [JSON]
#   p4ics-api /status
#   p4ics-api POST '/rekey?wait=1'
#   p4ics-api POST /tunnels '{"a": "195.11.14.5", "b": "200.1.1.7"}'
# P4ICS_API (default https://100.0.1.11:3333) and P4ICS_PKI (/shared/p4ics/pki)
# select the controller and the certificates.
set -eu
method=GET
case ${1:-} in GET|POST|DELETE) method=$1; shift ;; esac
[ $# -ge 1 ] || { echo "usage: $0 [GET|POST|DELETE] PATH [JSON]" >&2; exit 2; }
pki=${P4ICS_PKI:-/shared/p4ics/pki}
args=(-sS --fail-with-body --cacert "$pki/ca.pem" --cert "$pki/admin.pem" --key "$pki/admin-key.pem" -X "$method")
[ $# -ge 2 ] && args+=(-H 'Content-Type: application/json' -d "$2")
curl "${args[@]}" "${P4ICS_API:-https://100.0.1.11:3333}$1"
echo
