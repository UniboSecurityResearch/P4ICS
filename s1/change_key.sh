# Here we select the different key sizes
if [[ $# -ne 1 ]]; then
    echo 'Too many/few arguments, expecting one' >&2
    exit 1
fi

case $1 in
    128)
        # replace register<bit<32>>(8) keys; or register<bit<32>>(6) keys;
        # with register<bit<32>>(4) keys;
        sed -i -E 's/register<bit<32>>\(([6|8])\) keys;/register<bit<32>>(4) keys;/g' modbus_extraction.p4

        # delete the bit k5,k6,k7,k8
        sed -i -E 's/bit<32> k(5|6|7|8);//g' modbus_extraction.p4

        # replace Nk=8 or Nk=6 with Nk=4
        sed -i -E 's/Nk = (8|6)/Nk = 4/g' /extern_lib/definition.cpp

        # delete any line that starts with "register_write keys 4|5|6|7"
        sed -i -E '/^register_write keys (4|5|6|7)/d' commands.txt
    ;;

    192)
        # replace register<bit<32>>(4) keys; or register<bit<32>>(8) keys;
        # with register<bit<32>>(6) keys;
        sed -i -E 's/register<bit<32>>\(([4|8])\) keys;/register<bit<32>>(6) keys;/g' modbus_extraction.p4

        # add the bits k5 and k6 in modbus_extraction.p4
        sed -i '/^bit<32> k1; bit<32> k2; bit<32> k3; bit<32> k4;/c\ bit<32> k1; bit<32> k2; bit<32> k3; bit<32> k4; bit<32> k5; bit<32> k6;' modbus_extraction.p4

        # replace Nk=4 or Nk=8 with Nk=6 in definition.cpp
        sed -i -E 's/Nk = (4|8)/Nk = 6/g' /extern_lib/definition.cpp

        # add another 2 words to the standard 4 words in commands.txt
        # but if there are eight words in total, delete the two word in excess
        n=$(grep -c '^register_write' commands.txt)
        if [ "$n" == 4 ]; then
            sed -i '/^register_write keys 3/ a\
            register_write keys 4 102358694\
            register_write keys 5 259174683' commands.txt
        fi
        if [ "$n" == 8 ]; then
            sed -i -E '/^register_write keys (6|7)/d' commands.txt
        fi

    ;;

    256)
        # replace register<bit<32>>(4) keys; or register<bit<32>>(6) keys;
        # with register<bit<32>>(8) keys;
        sed -i -E 's/register<bit<32>>\(([4|6])\) keys;/register<bit<32>>(4) keys;/g' modbus_extraction.p4

        # add the bits k5,k6, k7,k7 in modbus_extraction.p4
        sed -i '/^bit<32> k1; bit<32> k2; bit<32> k3; bit<32> k4;/c\
        bit<32> k1; bit<32> k2; bit<32> k3; bit<32> k4; bit<32> k5; bit<32> k6; bit<32> k7; bit<32> k8;' modbus_extraction.p4

        # replace Nk=4 or Nk=6 with Nk=8
        sed -i -E 's/Nk = (4|6)/Nk = 8/g' /extern_lib/definition.cpp

        # add another 4 words to the standard 4 words in commands.txt
        n=$(grep -c '^register_write' commands.txt)
        if [ "$n" == 4]; then
            sed -i '/^register_write keys 3/ a\
            register_write keys 4 102358694\
            register_write keys 5 259174683\
            register_write keys 6 243695780\
            register_write keys 7 096548217' commands.txt
        fi
        if [ "$n" == 6]; then
            sed -i '/^register_write keys 5/ a\
            register_write keys 6 243695780\
            register_write keys 7 096548217' commands.txt
        fi
    ;;

    *)
        # The wrong first argument.
        echo 'Expected "128", "192", or "256"' >&2
        exit 1
esac


