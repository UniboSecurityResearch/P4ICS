#!/usr/bin/env bash
# Validate tests/reference/p4ics_ref.py against the P4ICS switch (bmv2 + the
# extern of testbed/s1) inside the loriringhio97/p4 image. Only NET_ADMIN is
# needed: the veth pairs live in the container's own network namespace.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${P4_IMAGE:-loriringhio97/p4@sha256:4ecf4ad5c433ff214f076ad06d051c2c9b5b9394bb6dfc0bb81a102b53fff5f2}"

exec docker run --rm --cap-add NET_ADMIN --entrypoint python3 \
    -v "$ROOT:/p4ics:ro" "$IMAGE" /p4ics/tests/bmv2/interop.py "$@"
