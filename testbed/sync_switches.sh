#!/usr/bin/env bash
# s1 and s2 run the same P4 program, extern and setup scripts. Kathara copies
# each device directory on its own, so s2 keeps a copy of s1's files.
#   ./sync_switches.sh          copy them from s1 to s2
#   ./sync_switches.sh --check  fail if s2 differs from s1
set -euo pipefail
cd "$(dirname "$0")"
FILES="industrial_aes.p4 p4ics_setup.sh change_key.sh nanomsg_client.py
       extern_lib/Makefile extern_lib/declaration.p4 extern_lib/definition.cpp
       extern_lib/p4ics_crypto.h extern_lib/p4ics_aes_tables.h"

status=0
for f in $FILES; do
    if [ "${1:-}" = "--check" ]; then
        cmp -s "s1/$f" "s2/$f" || { echo "s2/$f differs from s1/$f (run testbed/sync_switches.sh)" >&2; status=1; }
    else
        cp -p "s1/$f" "s2/$f"
    fi
done
exit $status
