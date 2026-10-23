#!/bin/bash
# P4ICS switch configuration that does not live in commands.txt, through
# simple_switch_CLI (a P4Runtime controller, controller/, can do the same).
#
#   ./p4ics_setup.sh init                at startup, after commands.txt
#   ./p4ics_setup.sh key [BITS]          reload the lab key truncated to BITS
#                                        (128..256; default: the lab mode, else 256)
#   ./p4ics_setup.sh install PHASE FILE  load the key in FILE into key phase PHASE
#   ./p4ics_setup.sh activate PHASE      protect with PHASE from now on
#
# Key: one random 256-bit key per lab run in /shared/p4ics_key (8 decimal
# words), created by the first switch that starts and removed at lclean by
# s1.shutdown/s2.shutdown. rotate_keys.sh replaces it without dropping
# traffic: install in the idle phase everywhere, then activate it.
# Mode: /shared/p4ics_mode, optional, written before kathara lstart:
# 128|160|192|224|256 (key size) or no-encryption|tls (ics_sec emptied:
# plaintext and TLS baselines).
set -eu

SHARED=${P4ICS_SHARED:-/shared}
KEY=$SHARED/p4ics_key
PHASE_FILE=$SHARED/p4ics_phase
LOCK=$SHARED/.p4ics_key.lock
CLI=${P4ICS_CLI:-simple_switch_CLI}
COMMANDS=${P4ICS_COMMANDS:-commands.txt}

mode() {
    cat "$SHARED/p4ics_mode" 2>/dev/null || echo 256
}

phase() {
    cat "$PHASE_FILE" 2>/dev/null || echo 0
}

# SPI of this switch, from "table_set_default p4ics_local set_local_sa <spi> ..."
spi() {
    awk '$1 == "table_set_default" && $2 == "p4ics_local" { print $4 }' "$COMMANDS"
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

# 0x + 64 hex digits: the words of FILE, zero after the first BITS/32.
key_hex() {
    local file=$1 bits=$2 hex="0x" i v
    case $bits in
        128|160|192|224|256) ;;
        *) echo "p4ics_setup: key size must be 128, 160, 192, 224 or 256" >&2; exit 1 ;;
    esac
    IFS=, read -r -a words < "$file"
    for i in 0 1 2 3 4 5 6 7; do
        v=0
        [ "$i" -lt $((bits / 32)) ] && v=${words[$i]}
        hex+=$(printf '%08x' "$v")
    done
    echo "$hex"
}

install_key() {   # install_key PHASE FILE BITS
    local handle
    handle=$($CLI <<< "table_dump_entry_from_key p4ics_keys $1" 2>/dev/null |
             grep -o 'Dumping entry 0x[0-9a-f]*' | awk '{ print $3 }' || true)
    if [ -n "$handle" ]; then
        # table_dump prints the handle in hex, table_modify wants it in decimal
        $CLI <<< "table_modify p4ics_keys set_key $((handle)) => $(key_hex "$2" "$3")" > /dev/null
    else
        $CLI <<< "table_add p4ics_keys set_key $1 => $(key_hex "$2" "$3")" > /dev/null
    fi
}

# The counter base is the current time in ns since 2020-01-01: no switch
# sends a packet per nanosecond, so counters never go back, even across
# restarts (anti-replay window, IV uniqueness).
activate() {
    $CLI <<< "table_set_default p4ics_local set_local_sa $(spi) $1 $(( $(date +%s%N) - 1577836800000000000 ))" > /dev/null
}

case ${1:-} in
    init)
        ensure_key
        case $(mode) in
            no-encryption|tls) $CLI <<< "table_clear ics_sec" > /dev/null ;;
            *) install_key "$(phase)" "$KEY" "$(mode)" ;;
        esac
        activate "$(phase)"
        ;;
    key)
        ensure_key
        install_key "$(phase)" "$KEY" "${2:-$(mode)}"
        ;;
    install)
        install_key "$2" "$3" "$(mode)"
        ;;
    activate)
        activate "$2"
        ;;
    *)
        echo "usage: $0 init | key [BITS] | install PHASE FILE | activate PHASE" >&2
        exit 2
        ;;
esac
