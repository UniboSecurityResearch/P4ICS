# shellcheck disable=SC2148
simple_switch -i 1@eth0 -i 2@eth1 industrial_aes.json --log-console -- --load-modules=extern_lib/definition.so > /dev/tty 2>&1 &
while [[ $(pgrep simple_switch) -eq 0 ]]; do sleep 1; done
until simple_switch_CLI <<< "help"; do sleep 1; done

simple_switch_CLI <<< $(cat commands.txt)
# P4ICS packet counter starts at the nanoseconds since 2020-01-01: no switch
# sends a packet per nanosecond, so after a restart counters never repeat
# (anti-replay window, IV uniqueness).
simple_switch_CLI <<< "register_write p4ics_tx_counter 0 $(( $(date +%s%N) - 1577836800000000000 ))"