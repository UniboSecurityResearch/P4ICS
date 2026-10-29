#!/bin/bash
# Kathara lab of the testbed with the optional P4Runtime controller in place
# of simple_switch_CLI: s1 and s2 run simple_switch_grpc (mutual TLS) on a
# management LAN, 100.0.1.0/24, with the controller.
#
#   make_lab.sh [--peer] OUTDIR
#
#   (default)  c1 manages s1 and s2
#   --peer     c1 manages s1, c2 manages s2; they agree on keys by Diffie-Hellman
#
# The web GUI of c1 is published on the host at http://localhost:8080 (c2:
# 8081), user admin, password in OUTDIR/shared/p4ics/gui-password.
#
# Needs the loriringhio97/p4ics-controller image
# (docker build -f Dockerfile/controller.Dockerfile -t loriringhio97/p4ics-controller .).
# The testbed itself (testbed/, simple_switch + simple_switch_CLI) is unchanged.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
mode=single
if [ "${1:-}" = "--peer" ]; then
    mode=peer
    shift
fi
[ $# -eq 1 ] || { echo "usage: $0 [--peer] OUTDIR" >&2; exit 2; }
out=$1
[ ! -e "$out" ] || { echo "$out already exists" >&2; exit 1; }

cp -r "$ROOT/testbed" "$out"
rm -rf "$out/shared" "$out"/s?/extern_lib/*.so
mkdir "$out/shared"
# simple_switch_CLI tooling: the controller does this (p4ics-api POST /rekey).
rm -f "$out"/rotate_keys.sh "$out"/sync_switches.sh "$out"/s?.shutdown \
      "$out"/s?/change_key.sh "$out"/s?/p4ics_setup.sh "$out"/s?/startup.sh "$out"/s?/retrieve_info.sh
cp "$HERE/s1.startup" "$HERE/s2.startup" "$HERE/c1.startup" "$HERE/c1.shutdown" "$out/"
mkdir "$out/c1"
cp "$HERE/$mode/c1.yml" "$HERE/topology.json" "$out/c1/"
devices="c1"
if [ "$mode" = peer ]; then
    cp "$HERE/c2.startup" "$out/"
    mkdir "$out/c2"
    cp "$HERE/peer/c2.yml" "$HERE/topology.json" "$out/c2/"
    devices="c1 c2"
fi
{
    echo
    echo "# P4Runtime control plane (controller/lab/make_lab.sh, $mode)"
    echo 's1[2]="M"'
    echo 's2[2]="M"'
    port=8080
    for d in $devices; do
        echo "$d[0]=\"M\""
        echo "$d[image]=\"loriringhio97/p4ics-controller\""
        echo "# web GUI: http://localhost:$port"
        echo "$d[bridged]=true"
        echo "$d[port]=\"$port:8080/tcp\""
        port=$((port + 1))
    done
} >> "$out/lab.conf"
echo "Lab in $out ($mode). Start it with: cd $out && kathara lstart"
echo "Controller API: kathara exec c1 -- p4ics-api /status"
echo "Web GUI: http://localhost:8080$([ "$mode" = peer ] && echo ' (c2: 8081)') (user admin, password in $out/shared/p4ics/gui-password)"
