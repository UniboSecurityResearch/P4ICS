#!/usr/bin/env bash
# Rotate the P4ICS key of the running lab without dropping traffic (run on the
# Kathara host, from testbed/): the new key goes into the idle key phase of
# every switch, then every switch starts protecting with it. Receivers pick
# the key by the phase bit of each frame, so frames in flight still verify.
set -euo pipefail
cd "$(dirname "$0")"
SWITCHES="${*:-s1 s2}"
old=$(cat shared/p4ics_phase 2>/dev/null || echo 0)
new=$((1 - old))

od -An -N64 -tu4 /dev/urandom | tr -s ' \n' '\n' | grep -v '^0*$' | head -8 |
    paste -sd, - > shared/p4ics_key.next
for sw in $SWITCHES; do
    kathara exec "$sw" "bash ./p4ics_setup.sh install $new /shared/p4ics_key.next"
done
for sw in $SWITCHES; do
    kathara exec "$sw" "bash ./p4ics_setup.sh activate $new"
done
mv shared/p4ics_key.next shared/p4ics_key
echo "$new" > shared/p4ics_phase
echo "P4ICS key rotated on $SWITCHES (phase $old -> $new)"
