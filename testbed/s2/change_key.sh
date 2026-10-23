# shellcheck disable=SC2148
# This script changes the key size of the switch without restarting it: the
# words of the lab key (/shared/p4ics_key) are loaded into the `keys`
# register truncated to the given size (see p4ics_setup.sh).

# Here we select the different key sizes
if [[ $# -ne 1 ]]; then
    echo 'Too many/few arguments, expecting one' >&2
    exit 1
fi

case $1 in
    128|160|192|224|256)
        bash ./p4ics_setup.sh key "$1"
    ;;

    *)
        # The wrong first argument.
        echo 'Expected "128", "160", "192", "224" or "256"' >&2
        exit 1
esac
