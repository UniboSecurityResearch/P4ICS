#!/usr/bin/env bash
# Rotate the P4ICS key of the running lab (run on the Kathara host). The new
# key replaces shared/p4ics_key and is loaded on s1 and s2 with the current
# key size; frames in flight during the swap are dropped.
set -euo pipefail
cd "$(dirname "$0")"
od -An -N64 -tu4 /dev/urandom | tr -s ' \n' '\n' | grep -v '^0*$' | head -8 |
    paste -sd, - > shared/p4ics_key.tmp
mv shared/p4ics_key.tmp shared/p4ics_key
for sw in s1 s2; do
    kathara exec "$sw" "bash ./p4ics_setup.sh key"
done
echo "P4ICS key rotated on s1 and s2"
