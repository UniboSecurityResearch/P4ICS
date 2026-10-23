#!/usr/bin/env bash
# The optional P4Runtime controller (controller/) against two
# simple_switch_grpc with mutual TLS, with TCP traffic through them: static
# and on-demand tunnels, rekeying under traffic, switch and controller
# restarts, two controllers agreeing on keys. Builds the controller with the
# local Go toolchain, or in a golang container, unless P4ICS_CONTROLLER_BIN
# names a binary. Privileged because it creates network namespaces.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${P4_IMAGE:-loriringhio97/p4@sha256:4ecf4ad5c433ff214f076ad06d051c2c9b5b9394bb6dfc0bb81a102b53fff5f2}"
GO_IMAGE="${GO_IMAGE:-golang:1.25.6-bookworm}"

BIN="${P4ICS_CONTROLLER_BIN:-}"
if [ -z "$BIN" ]; then
    OUT="$(mktemp -d)"
    trap 'rm -rf "$OUT"' EXIT
    BIN="$OUT/p4ics-controller"
    GO="$(command -v go || echo /usr/local/go/bin/go)"
    if [ -x "$GO" ]; then
        (cd "$ROOT/controller" && CGO_ENABLED=0 GOTOOLCHAIN=local "$GO" build -trimpath -o "$BIN" ./cmd/p4ics-controller)
    else
        docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=0 \
            -v "$ROOT/controller:/src:ro" -v "$OUT:/out" -w /src "$GO_IMAGE" \
            go build -buildvcs=false -trimpath -o /out/p4ics-controller ./cmd/p4ics-controller
    fi
fi
docker run --rm --privileged --entrypoint python3 \
    -v "$ROOT:/p4ics:ro" -v "$BIN:/usr/local/bin/p4ics-controller:ro" \
    "$IMAGE" /p4ics/tests/controller/e2e_controller.py "$@"
