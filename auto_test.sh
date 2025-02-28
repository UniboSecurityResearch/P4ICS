#!/bin/bash

# Function to print usage
usage() {
    echo "Usage: $0 [--all] [--128] [--160] [--192] [--224] [--256] [--rtt] [--ppt] [--deq] [--no-encryption] [--tls]"
    echo "Options:"
    echo "  --all               Run all configurations"
    echo "  --no-encryption     Run test without encryption functionality"
    echo "  --tls               Run test with Modbus using TLS encryption"
    echo "  --128               Run 128-bit configuration"
    echo "  --160               Run 160-bit configuration"
    echo "  --192               Run 192-bit configuration"
    echo "  --224               Run 224-bit configuration"
    echo "  --256               Run 256-bit configuration"
    echo "Measurement options:"
    echo "  --rtt               Measure Round Trip Time"
    echo "  --ppt               Measure Packet Processing Time"
    echo "  --deq               Measure Packet Dequeuing Timedelta"

    echo "Note: If no measurement options are selected, all measurements will be performed"
    exit 1
}

# EXTENSIBILITY 
# Set the command to execute the client
default_client="python modbus_client.py"
# Set the command to execute the server
default_server="python server.py"

export client="$default_client"
export server="$default_server"

KEYS=( "128" "160" "192" "224" "256" )

# Function to be executed on cleanup
cleanup() {
    echo "Performing cleanup..."
    # Add your cleanup tasks here
    kathara lclean
    rm -f shared/startup.temp
    exit
}

# Function to check if a container is ready
wait_for_container() {
    local container=$1
    local max_attempts=30
    local attempt=1
    local delay=2

    echo "Waiting for $container to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        # Check if startup is complete by looking for a marker in shared/startup.temp
        if grep -q "$container" shared/startup.temp 2&>/dev/null; then
            echo "$container is ready!"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts: $container not ready yet, waiting..."
        sleep $delay
        attempt=$((attempt + 1))
    done

    echo "Timeout waiting for $container to be ready"
    return 1
}

# Initialize all flags to 0
ALL=0
NO_ENCRYPTION=0
TLS=0
BIT_128=0
BIT_160=0
BIT_192=0
BIT_224=0
BIT_256=0
MEASURE_RTT=0
MEASURE_PPT=0
MEASURE_DEQ=0

# Parse command line arguments
TEMP=$(getopt -o '' --long all,no-encryption,tls,128,160,192,224,256,rtt,ppt,deq -n "$0" -- "$@")
if [ $? -ne 0 ]; then
    usage
fi


eval set -- "$TEMP"

# Extract options
while true; do
    case "$1" in
        --all)
            ALL=1
            shift
            ;;
        --no-encryption)
            NO_ENCRYPTION=1
            shift
            ;;
        --tls)
            TLS=1
            shift
            ;;
        --128)
            BIT_128=1
            shift
            ;;
        --160)
            BIT_160=1
            shift
            ;;
        --192)
            BIT_192=1
            shift
            ;;
        --224)
            BIT_224=1
            shift
            ;;
        --256)
            BIT_256=1
            shift
            ;;
        --rtt)
            MEASURE_RTT=1
            shift
            ;;
        --ppt)
            MEASURE_PPT=1
            shift
            ;;
        --deq)
            MEASURE_DEQ=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            usage
            ;;
    esac
done

# If --all is specified, set all configuration flags to 1
if [ $ALL -eq 1 ]; then
    NO_ENCRYPTION=1
    TLS=1
    BIT_128=1
    BIT_160=1
    BIT_192=1
    BIT_224=1
    BIT_256=1
fi

# Check if at least one configuration option was selected
if [ $ALL -eq 0 ] && [ $NO_ENCRYPTION -eq 0 ] && [ $TLS -eq 0 ] && [ $BIT_128 -eq 0 ] && [ $BIT_160 -eq 0 ] && [ $BIT_192 -eq 0 ] && [ $BIT_224 -eq 0 ] && [ $BIT_256 -eq 0 ]; then
    echo "Error: At least one configuration option must be selected"
    usage
fi

# If no measurement options are selected, enable all measurements
if [ $MEASURE_RTT -eq 0 ] && [ $MEASURE_PPT -eq 0 ] && [ $MEASURE_DEQ -eq 0 ]; then
    echo "No specific measurements selected. Enabling all measurements..."
    MEASURE_RTT=1
    MEASURE_PPT=1
    MEASURE_DEQ=1
fi

# function to print the mode
detect_mode(){
    if [ "$MODE" = "no-encryption" ] || [ "$MODE" = "tls" ]; then
        CUR_MODE="$MODE"
    else CUR_MODE="$MODE"-bit
    fi
}

measure_ppt(){
    echo "Measuring Packet Processing Time for $CUR_MODE configuration"
    if [ "$1" = "write" ]; then
        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --ppt ${MODE} -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            exit
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --ppt ${MODE} -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            exit
        fi
    fi

    if [ "$1" = "read" ]; then
        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --ppt ${MODE} -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            exit
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --ppt ${MODE} -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            exit
        fi  
    fi
}

measure_deq(){
    echo "Measuring Packet Dequeuing Timedelta for $CUR_MODE configuration"
    if [ "$1" = "write" ]; then
        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --deq ${MODE} -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            exit
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --deq ${MODE} -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            exit
        fi
    fi

    if [ "$1" = "read" ]; then
        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --deq ${MODE} -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            exit
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --deq ${MODE} -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            exit
        fi  
    fi
}

# Function to run a specific configuration
run_configuration() {
    local MODE=$1

    if [ "$MODE" = "tls" ];then 
        export client="python tls_client.py"
        export server="python server_tls.py"
    fi

    detect_mode

    echo "Starting Kathara for $CUR_MODE configuration..."

    # delete any line that starts with "register_write keys 4|5|6|7"
    sed -i -E '/^register_write keys (4|5|6|7)/d' s1/commands.txt
    sed -i -E '/^register_write keys (4|5|6|7)/d' s2/commands.txt

    # Change the commands.txt in s1 and s2 according to the current size of the key
    case $MODE in
        no-encryption | tls)
            # set the register from 4 up to 7 to 0 in commands.txt in s1
            sed -i '/^register_write keys 3/ a\
register_write keys 4 0\
register_write keys 5 0\
register_write keys 6 0\
register_write keys 7 0' ./s1/commands.txt

            # set the register from 4 up to 7 to 0 in commands.txt in s2
            sed -i '/^register_write keys 3/ a\
register_write keys 4 0\
register_write keys 5 0\
register_write keys 6 0\
register_write keys 7 0' ./s2/commands.txt
            #delete the line that add the modbus_sec table to disable in-network encryption
            sed -i -E '/^table_add modbus_sec/d' s1/commands.txt
            sed -i -E '/^table_add modbus_sec/d' s2/commands.txt
            
        ;;

        128)
            # set the register from 4 up to 7 to 0 in commands.txt in s1
            sed -i '/^register_write keys 3/ a\
register_write keys 4 0\
register_write keys 5 0\
register_write keys 6 0\
register_write keys 7 0' ./s1/commands.txt

            # set the register from 4 up to 7 to 0 in commands.txt in s2
            sed -i '/^register_write keys 3/ a\
register_write keys 4 0\
register_write keys 5 0\
register_write keys 6 0\
register_write keys 7 0' ./s2/commands.txt
        ;;

        160)
            # set the register from 4 up to 7 to 0 in commands.txt in s1
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 0\
register_write keys 6 0\
register_write keys 7 0' ./s1/commands.txt

            # set the register from 4 up to 7 to 0 in commands.txt in s2
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 0\
register_write keys 6 0\
register_write keys 7 0' ./s2/commands.txt

        ;;

        192)
            # set the register from 4 up to 7 to 0 in commands.txt in s1
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 259174683\
register_write keys 6 0\
register_write keys 7 0' ./s1/commands.txt

            # set the register from 4 up to 7 to 0 in commands.txt in s2
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 259174683\
register_write keys 6 0\
register_write keys 7 0' ./s2/commands.txt

        ;;

        224)
            # set the register from 4 up to 7 to 0 in commands.txt in s1
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 259174683\
register_write keys 6 243695780\
register_write keys 7 0' ./s1/commands.txt

            # set the register from 4 up to 7 to 0 in commands.txt in s2
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 259174683\
register_write keys 6 243695780\
register_write keys 7 0' ./s2/commands.txt

        ;;

        256)
            # set the register from 4 up to 7 to 0 in commands.txt in s1
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 259174683\
register_write keys 6 243695780\
register_write keys 7 096548217' ./s1/commands.txt

            # set the register from 4 up to 7 to 0 in commands.txt in s2
            sed -i '/^register_write keys 3/ a\
register_write keys 4 102358694\
register_write keys 5 259174683\
register_write keys 6 243695780\
register_write keys 7 096548217' ./s2/commands.txt

        ;;

        *)
            # The wrong first argument.
            echo 'Expected "128", "160", "192", "224" or "256"' >&2
            exit 1
    esac

    if [[ "${KEYS[*]}" =~ $MODE ]]; then
        #restore encryption adding the rules to match the table modbus_sec
#         if ! grep '^table_add modbus_sec' s1/commands.txt; then
#             sed -i '/^register_write keys 7/ a\
# table_add modbus_sec cipher 2 =>' ./s1/commands.txt
#         fi
#         if ! grep '^table_add modbus_sec' s2/commands.txt; then
#             sed -i '/^register_write keys 7/ a\
# table_add modbus_sec cipher 2 =>' ./s2/commands.txt
#         fi
        # delete any rule that add an entry to modbus_sec to be sure that only the rules added after are in commands.txt
        sed -i -E '/^table_add modbus_sec/d' s1/commands.txt
        sed -i -E '/^table_add modbus_sec/d' s2/commands.txt
        sed -i '/^register_write keys 7/ a\
table_add modbus_sec decipher 1 =>\
table_add modbus_sec cipher 2 =>' ./s1/commands.txt
        sed -i '/^register_write keys 7/ a\
table_add modbus_sec decipher 1 =>\
table_add modbus_sec cipher 2 =>' ./s2/commands.txt
    fi
    
    # Clean any previous Kathara instance
    kathara lclean
    
    # Start Kathara with specific configuration
    if ! kathara lstart --noterminals
    then
        echo "Error: Failed to start Kathara for $CUR_MODE configuration"
        kathara lclean
        return 1
    fi

    echo "Kathara started successfully for $CUR_MODE configuration!"
    
    # Wait for containers to be ready
    if ! wait_for_container "h1"; then
        echo "Error: h1 failed to start properly"
        kathara lclean
        return 1
    fi

    if ! wait_for_container "h2"; then
        echo "Error: h2 failed to start properly"
        kathara lclean
        return 1
    fi

    if ! wait_for_container "s1"; then
        echo "Error: s1 failed to start properly"
        kathara lclean
        return 1
    fi

    if ! wait_for_container "s2"; then
        echo "Error: s2 failed to start properly"
        kathara lclean
        return 1
    fi

    echo "Processing $CUR_MODE configuration..."

    # RTT - Round Trip Time
    if [ $MEASURE_RTT -eq 1 ]; then
        echo "Measuring Round Trip Time..."
        echo "Starting server in h2..."
        kathara exec h2 $server &
        # give server the time to start
        sleep 2

        echo "Starting client in h1..."
        [[ "$MODE" = "tls" ]] && client_mode="" || client_mode=$MODE
        if ! kathara exec h1 "$client --test-rtt-write $client_mode" >/dev/tty 2>&1; then
            echo "Error: RTT measurement failed"
            exit
        fi

        if [ $MEASURE_PPT -eq 1 ]; then
            measure_ppt "write"
        fi

        if [ $MEASURE_DEQ -eq 1 ]; then
            measure_deq "write"
        fi

        echo "Starting client in h1..."
        if ! kathara exec h1 "$client --test-rtt-read $client_mode" >/dev/tty 2>&1; then
            echo "Error: RTT measurement failed"
            exit
        fi

        if [ $MEASURE_PPT -eq 1 ]; then
            measure_ppt "read"
        fi

        if [ $MEASURE_DEQ -eq 1 ]; then
            measure_deq "read"
        fi

    fi

    # PPT - Packet Prcessing Time
    if [ $MEASURE_PPT -eq 1 ] && [ $MEASURE_RTT -ne 1 ]; then
        echo "Measuring Packet Processing Time..."

        # WRITE
        #h2
        echo "Starting server in h2..."
        kathara exec h2 $server &
        # give server the time to start
        sleep 2

        #h1
        echo "Starting client in h1..."
        [[ "$MODE" = "tls" ]] && client_mode="" || client_mode=$MODE
        if ! kathara exec h1 "$client --test-write $client_mode" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            exit
        fi
        

        measure_ppt "write"

        if [ $MEASURE_DEQ -eq 1 ]; then
            measure_deq "write"
        fi

        # READ
        #h1
        echo "Starting client in h1..."
        if ! kathara exec h1 "$client --test-read $client_mode" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            exit
        fi      

        measure_ppt "read"

        if [ $MEASURE_DEQ -eq 1 ]; then
            measure_deq "read"
        fi
    fi

    # DEQ - Packet Dequeuing Timedelta
    if [ $MEASURE_DEQ -eq 1 ] && [ $MEASURE_RTT -ne 1 ] && [ $MEASURE_PPT -ne 1 ]; then
        echo "Measuring Dequeuing Timedelta..."

        # WRITE
        #h2
        echo "Starting server in h2..."
        kathara exec h2 $server &
        # give server the time to start
        sleep 2

        #h1
        echo "Starting client in h1..."
        [[ "$MODE" = "tls" ]] && client_mode="" || client_mode=$MODE
        if ! kathara exec h1 "$client --test-write $client_mode" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            kathara lclean
        fi

        measure_deq "write"

        # READ
        #h1
        echo "Starting client in h1..."
        if ! kathara exec h1 "$client --test-read $client_mode" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            kathara lclean
        fi

        measure_deq "read"    
    fi
    
    # After processing, clean up
    echo "Cleaning up $CUR_MODE configuration..."
    # restore the default client and server
    if [ "$MODE" = "tls" ];then 
        export client="$default_client"
        export server="$default_server"
    fi

    rm -f shared/startup.temp
    kathara lclean
} ## run_configuration()

# Set up trap for both SIGINT and EXIT
#trap cleanup SIGINT EXIT
rm -f shared/startup.temp

rm -f shared/startup.temp
# Process each selected configuration
if [ $NO_ENCRYPTION -eq 1 ]; then
    run_configuration "no-encryption"
fi

if [ $TLS -eq 1 ]; then
    run_configuration "tls"
fi

if [ $BIT_128 -eq 1 ]; then
    run_configuration "128"
fi

if [ $BIT_160 -eq 1 ]; then
    run_configuration "160"
fi

if [ $BIT_192 -eq 1 ]; then
    run_configuration "192"
fi

if [ $BIT_224 -eq 1 ]; then
    run_configuration "224"
fi

if [ $BIT_256 -eq 1 ]; then
    run_configuration "256"
fi

# cp shared/results* results/mul_key
