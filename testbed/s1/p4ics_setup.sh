#!/bin/bash
# P4ICS switch configuration that does not live in commands.txt.
#
#   ./p4ics_setup.sh init        at startup, after commands.txt
#   ./p4ics_setup.sh key [BITS]  load the lab key truncated to BITS
#                                (128..256; default: the lab mode, else 256)
#
# Key: one random 256-bit key per lab run in /shared/p4ics_key (8 decimal
# words), created by the first switch that starts and removed at lclean by
# s1.shutdown/s2.shutdown; rotate it with testbed/rotate_keys.sh. It is never
# part of the repository.
# Mode: /shared/p4ics_mode, written by auto_test.sh: 128|160|192|224|256 (key
# size) or no-encryption|tls (ics_sec emptied: plaintext and TLS baselines).
set -eu

SHARED=${P4ICS_SHARED:-/shared}
KEY=$SHARED/p4ics_key
LOCK=$SHARED/.p4ics_key.lock
CLI=${P4ICS_CLI:-simple_switch_CLI}

mode() {
    cat "$SHARED/p4ics_mode" 2>/dev/null || echo 256
}

ensure_key() {
    if mkdir "$LOCK" 2>/dev/null; then
        if [ ! -s "$KEY" ]; then
            # 8 random non-zero 32-bit words (a zero word would end the key early)
            od -An -N64 -tu4 /dev/urandom | tr -s ' \n' '\n' | grep -v '^0*$' | head -8 |
                paste -sd, - > "$KEY.tmp"
            mv "$KEY.tmp" "$KEY"
        fi
        rmdir "$LOCK"
    fi
    for _ in $(seq 60); do
        [ -s "$KEY" ] && return 0
        sleep 1
    done
    echo "p4ics_setup: no key in $KEY" >&2
    exit 1
}

load_key() {
    local bits=${1:-$(mode)} cmds="" i v
    case $bits in
        128|160|192|224|256) ;;
        *) echo "p4ics_setup: key size must be 128, 160, 192, 224 or 256" >&2; exit 1 ;;
    esac
    IFS=, read -r -a words < "$KEY"
    for i in 0 1 2 3 4 5 6 7; do
        v=0
        [ "$i" -lt $((bits / 32)) ] && v=${words[$i]}
        cmds+="register_write keys $i $v"$'\n'
    done
    $CLI <<< "$cmds" > /dev/null
}

case ${1:-} in
    init)
        ensure_key
        case $(mode) in
            no-encryption|tls) $CLI <<< "table_clear ics_sec" > /dev/null ;;
            *) load_key ;;
        esac
        # The packet counter starts at the nanoseconds since 2020-01-01: no
        # switch sends a packet per nanosecond, so after a restart counters
        # never repeat (anti-replay window, IV uniqueness).
        $CLI <<< "register_write p4ics_tx_counter 0 $(( $(date +%s%N) - 1577836800000000000 ))" > /dev/null
        ;;
    key)
        ensure_key
        load_key "${2:-}"
        ;;
    *)
        echo "usage: $0 init | key [128|160|192|224|256]" >&2
        exit 2
        ;;
esac
