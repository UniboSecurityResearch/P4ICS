#!/usr/bin/env bash
# Real Modbus (pymodbus), DNP3 (stepfunc/dnp3) and EtherNet/IP (cpppo) traffic
# through two P4ICS switches. Needs the loriringhio97/dnp3 image
# (docker build -f Dockerfile/dnp3.Dockerfile -t loriringhio97/dnp3 .).
# Privileged because it creates network namespaces inside the container.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
docker build -q -t p4ics-protocols-test "$ROOT/tests/protocols" >/dev/null
exec docker run --rm --privileged --entrypoint python3 \
    -v "$ROOT:/p4ics:ro" p4ics-protocols-test /p4ics/tests/protocols/e2e_protocols.py "$@"
