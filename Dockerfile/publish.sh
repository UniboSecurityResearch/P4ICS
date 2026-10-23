#!/usr/bin/env bash
# Build the images of this repository for linux/amd64 and linux/arm64 and
# push them to Docker Hub (docker login first):
#
#   Dockerfile/publish.sh v2.0.0              # dnp3, enip, modbus, p4ics-controller
#   Dockerfile/publish.sh v2.0.0 dnp3 enip    # some of them
#
# Each image gets <tag>; dnp3, enip and p4ics-controller also get latest.
# loriringhio97/modbus:latest is left as published: it is the image the
# testbed was validated with (testbed/lab.conf).
#
# Needs QEMU for the arm64 half (docker run --privileged --rm tonistiigi/binfmt
# --install arm64) and a builder that can push multi-platform images: the
# default one with the containerd image store, or `docker buildx create --use`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ $# -ge 1 ] || { echo "usage: $0 TAG [IMAGE...]" >&2; exit 2; }
tag=$1
shift
[ $# -gt 0 ] || set -- dnp3 enip modbus p4ics-controller

for image; do
    case $image in
        dnp3|enip)        file=$image     latest=1 ;;
        p4ics-controller) file=controller latest=1 ;;
        modbus)           file=modbus     latest=0 ;;
        *) echo "unknown image $image" >&2; exit 2 ;;
    esac
    tags=(-t "loriringhio97/$image:$tag")
    [ "$latest" = 1 ] && tags+=(-t "loriringhio97/$image:latest")
    echo "== loriringhio97/$image ($tag$([ "$latest" = 1 ] && echo ', latest'))"
    docker buildx build --platform linux/amd64,linux/arm64 -f "$ROOT/Dockerfile/$file.Dockerfile" \
        "${tags[@]}" --push "$ROOT"
done
