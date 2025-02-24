#!/bin/bash

# Function to print usage
usage() {
    echo "Usage: $0 [--all] [--128] [--160] [--192] [--224] [--256] [--rtt] [--ppt] [--deq]"
    echo "Options:"
    echo "  --all    Run all configurations"
    echo "  --128    Run 128-bit configuration"
    echo "  --160    Run 160-bit configuration"
    echo "  --192    Run 192-bit configuration"
    echo "  --224    Run 224-bit configuration"
    echo "  --256    Run 256-bit configuration"
    echo "Measurement options:"
    echo "  --rtt    Measure Round Trip Time"
    echo "  --ppt    Measure Packet Processing Time"
    echo "  --deq    Measure Dequeuing Timedelta"
    echo "Note: If no measurement options are selected, all measurements will be performed"
    exit 1
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
        if grep -q "$container" shared/startup.temp; then
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
BIT_128=0
BIT_160=0
BIT_192=0
BIT_224=0
BIT_256=0
MEASURE_RTT=0
MEASURE_PPT=0
MEASURE_DEQ=0

# Parse command line arguments
TEMP=$(getopt -o '' --long all,128,160,192,224,256,rtt,ppt,deq -n "$0" -- "$@")
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
    BIT_128=1
    BIT_160=1
    BIT_192=1
    BIT_224=1
    BIT_256=1
fi

# Check if at least one configuration option was selected
if [ $ALL -eq 0 ] && [ $BIT_128 -eq 0 ] && [ $BIT_160 -eq 0 ] && [ $BIT_192 -eq 0 ] && [ $BIT_224 -eq 0 ] && [ $BIT_256 -eq 0 ]; then
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


# Function to run a specific configuration
run_configuration() {
    local bits=$1
    echo "Starting Kathara for ${bits}-bit configuration..."
    # delete any line that starts with "register_write keys 4|5|6|7"
    sed -i -E '/^register_write keys (4|5|6|7)/d' s1/commands.txt
    sed -i -E '/^register_write keys (4|5|6|7)/d' s2/commands.txt

    # Change the commands.txt in s1 and s2 according to the current size of the key
    case $bits in
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
    
    # Clean any previous Kathara instance
    kathara lclean
    
    # Start Kathara with specific configuration
    if ! kathara lstart --noterminals
    then
        echo "Error: Failed to start Kathara for ${bits}-bit configuration"
        kathara lclean
        return 1
    fi

    echo "Kathara started successfully for ${bits}-bit configuration!"
    
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

    echo "Processing ${bits}-bit configuration..."

    # RTT - Round Trip Time
    if [ $MEASURE_RTT -eq 1 ]; then
        echo "Measuring Round Trip Time..."
        echo "Starting server in h2..."
        kathara exec h2 "python server.py" &
        # give server the time to start
        sleep 2

        echo "Starting client in h1..."
        if ! kathara exec h1 "python modbus_client.py --test-rtt ${bits}" >/dev/tty 2>&1; then
            echo "Error: RTT measurement failed"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi
    fi

    # PPT - Packet Prcessing Time
    if [ $MEASURE_PPT -eq 1 ]; then
        echo "Measuring Packet Processing Time..."

        # WRITE
        #h2
        echo "Starting server in h2..."
        kathara exec h2 "python server.py" &
        # give server the time to start
        sleep 2

        #h1
        echo "Starting client in h1..."
        if ! kathara exec h1 "python modbus_client.py --test-write" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi
        

        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --ppt ${bits} -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --ppt ${bits} -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi

        # READ
        #h1
        echo "Starting client in h1..."
        if ! kathara exec h1 "python modbus_client.py --test-read" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi      

        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --ppt ${bits} -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --ppt ${bits} -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            kathara lclean
            rm -f shared/startup.temp
            exit
        fi  
    fi

    # DEQ - Packet Dequeuing Timedelta
    if [ $MEASURE_DEQ -eq 1 ]; then
        echo "Measuring Dequeuing Timedelta..."

        # WRITE
        #h2
        echo "Starting server in h2..."
        kathara exec h2 "python server.py" &
        # give server the time to start
        sleep 3

        #h1
        echo "Starting client in h1..."
        if ! kathara exec h1 "python modbus_client.py --test-write" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            kathara lclean
        fi

        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --deq $bits -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            kathara lclean
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --deq $bits -w" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            kathara lclean
        fi

        # READ
        #h1
        echo "Starting client in h1..."
        if ! kathara exec h1 "python modbus_client.py --test-read" >/dev/tty 2>&1; then
            echo "Error: PPT measurement failed | error in modbus client on h1"
            kathara lclean
        fi

        # retrieve info from the switches
        #s1
        echo "Retreiving info from s1"
        if ! kathara exec s1 "./retrieve_info.sh --deq $bits -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s1"
            kathara lclean
        fi

        #s2
        echo "Retreiving info from s2"
        if ! kathara exec s2 "./retrieve_info.sh --deq $bits -r" >/dev/tty 2>&1; then
            echo "Error: PPT info retrieve failed in s2"
            kathara lclean
        fi
        
    fi
    
    # After processing, clean up
    echo "Cleaning up ${bits}-bit configuration..."
    rm -f shared/startup.temp
    kathara lclean

}

rm -f shared/startup.temp
# Process each selected configuration
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

