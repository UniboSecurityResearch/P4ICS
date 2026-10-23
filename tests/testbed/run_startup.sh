#!/usr/bin/env bash
# Run the Kathara startup/shutdown scripts of s1 and s2 in two containers that
# share /shared, the way Kathara does (device directory copied to /), and
# check what they configure: shared lab key, mode, SPI, ics_sec, counter.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${P4_IMAGE:-loriringhio97/p4@sha256:4ecf4ad5c433ff214f076ad06d051c2c9b5b9394bb6dfc0bb81a102b53fff5f2}"
SHARED="$(mktemp -d)"
NAMES="p4ics-startup-s1 p4ics-startup-s2"
trap 'docker rm -f $NAMES >/dev/null 2>&1 || true; docker run --rm -v "$SHARED:/shared" --entrypoint rm "$IMAGE" -rf /shared/* /shared/.p4ics_key.lock >/dev/null 2>&1 || true; rmdir "$SHARED" 2>/dev/null || true' EXIT

fail=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
cli() { docker exec -i "p4ics-startup-$1" simple_switch_CLI <<< "$2" 2>/dev/null; }
# Action data of a table entry or default entry, as table_dump prints it.
action_data() { cli "$1" "table_dump $2" | sed -n "s/.*Action entry: MyIngress.$3 - //p"; }
# 0x-less hex of the key words (the first $2 / 32 of them), leading zeros stripped.
key_hex() {
    local hex="" i
    IFS=, read -r -a w <<< "$1"
    for i in 0 1 2 3 4 5 6 7; do
        if [ "$i" -lt $(( $2 / 32 )) ]; then hex+=$(printf '%08x' "${w[$i]}"); else hex+=00000000; fi
    done
    echo "$hex" | sed 's/^0*//'
}

boot() {   # boot <s1|s2>: start a device and run its startup script
    docker run -d --name "p4ics-startup-$1" --cap-add NET_ADMIN --network none \
        -v "$ROOT/testbed:/testbed:ro" -v "$SHARED:/shared" --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "p4ics-startup-$1" sh -c "ip link add eth0 type veth peer name eth1 && ip link set eth0 up && ip link set eth1 up && cp -r /testbed/$1/. / && cp /testbed/$1.startup /testbed/$1.shutdown /"
    docker exec -d "p4ics-startup-$1" bash -c "cd / && bash $1.startup > /startup.log 2>&1"
}

boot s1
boot s2
for _ in $(seq 120); do
    grep -q s1 "$SHARED/startup.temp" 2>/dev/null && grep -q s2 "$SHARED/startup.temp" 2>/dev/null && break
    sleep 1
done
check "both switches finished their startup" "grep -q s2 '$SHARED/startup.temp' && grep -q s1 '$SHARED/startup.temp'"

key=$(cat "$SHARED/p4ics_key" 2>/dev/null || true)
IFS=, read -r -a words <<< "$key"
check "a 256-bit lab key was generated in shared/" "[ \${#words[@]} -eq 8 ]"
for sw in s1 s2; do
    check "$sw loaded the lab key in phase 0" \
        "action_data $sw p4ics_keys set_key | grep -qx '$(key_hex "$key" 256)'"
    local_sa=$(action_data $sw p4ics_local set_local_sa)
    check "$sw has its SPI and protects with phase 0" "[ '${local_sa%%, *}' = '0${sw#s}' ] && echo '$local_sa' | grep -q ', 00, '"
    check "$sw counter base is the time in ns since 2020" "[ \$(( 0x${local_sa##*, } )) -gt 200000000000000000 ]"
    check "$sw ics_sec has cipher and decipher" \
        "[ \"\$(cli $sw 'table_dump ics_sec' | grep -Ec 'Action entry: MyIngress[.](de)?cipher ')\" = 2 ]"
done

docker exec p4ics-startup-s1 bash -c "cd / && bash change_key.sh 128" >/dev/null
check "change_key.sh 128 truncates the key" \
    "action_data s1 p4ics_keys set_key | grep -qx '$(key_hex "$key" 128)'"
docker exec p4ics-startup-s1 bash -c "cd / && bash change_key.sh 256" >/dev/null

# Hitless rotation, as rotate_keys.sh drives it: install everywhere, then activate.
echo "1,2,3,4,5,6,7,8" > "$SHARED/p4ics_key.next"
for sw in s1 s2; do docker exec p4ics-startup-$sw bash -c "cd / && bash p4ics_setup.sh install 1 /shared/p4ics_key.next"; done
check "rotation: both phases hold a key on s1 and s2" \
    "[ \$(action_data s1 p4ics_keys set_key | wc -l) = 2 ] && [ \$(action_data s2 p4ics_keys set_key | wc -l) = 2 ]"
check "rotation: s1 still protects with phase 0 until activated" "action_data s1 p4ics_local set_local_sa | grep -q ', 00, '"
for sw in s1 s2; do docker exec p4ics-startup-$sw bash -c "cd / && bash p4ics_setup.sh activate 1"; done
check "rotation: after activate both protect with phase 1" \
    "action_data s1 p4ics_local set_local_sa | grep -q ', 01, ' && action_data s2 p4ics_local set_local_sa | grep -q ', 01, '"
rm -f "$SHARED/p4ics_key.next"

echo no-encryption > "$SHARED/p4ics_mode"
docker exec p4ics-startup-s2 bash -c "cd / && bash p4ics_setup.sh init" >/dev/null
check "no-encryption mode empties ics_sec" "! cli s2 'table_dump ics_sec' | grep -Eq 'Action entry: MyIngress[.](de)?cipher '"
rm -f "$SHARED/p4ics_mode"

docker exec p4ics-startup-s1 bash -c "cd / && bash s1.shutdown"
check "shutdown removes the lab key" "[ ! -e '$SHARED/p4ics_key' ]"
docker exec p4ics-startup-s1 bash -c "cd / && bash p4ics_setup.sh key" >/dev/null
check "next start generates a different key" "[ -s '$SHARED/p4ics_key' ] && [ \"\$(cat '$SHARED/p4ics_key')\" != '$key' ]"

[ $fail -eq 0 ] && echo "startup checks passed" || { echo "startup checks FAILED"; docker exec p4ics-startup-s1 cat /startup.log | tail -5; }
exit $fail
