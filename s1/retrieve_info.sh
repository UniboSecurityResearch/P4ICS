#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [--ppt BIT_LENGTH] [--deq BIT_LENGTH]"
    echo "Options:"
    echo "  --ppt BIT_LENGTH    PPT option with key length (128/160/192/224/256)"
    echo "  --deq BIT_LENGTH    DEQ option with key length (128/160/192/224/256)"
    exit 1
}

# Function to validate bit length
validate_bit_length() {
    local length=$1
    case "$length" in
        128|160|192|224|256) return 0 ;;
        *) return 1 ;;
    esac
}

# Initialize variables
PPT_FLAG=false
DEQ_FLAG=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ppt)
            PPT_FLAG=true
            shift
            if [[ $# -gt 0 ]] && validate_bit_length "$1"; then
                KEY="$1"
                shift
            else
                echo "Error: --ppt requires a valid bit length (128/160/192/224/256)"
                usage
            fi
            ;;
        --deq)
            DEQ_FLAG=true
            shift
            if [[ $# -gt 0 ]] && validate_bit_length "$1"; then
                KEY="$1"
                shift
            else
                echo "Error: --deq requires a valid bit length (128/160/192/224/256)"
                usage
            fi
            ;;
        *)
            echo "Error: Unknown option $1"
            usage
            ;;
    esac
done


if [ "$PPT_FLAG" = true ]; then
    echo "PPT option was selected"
    echo "packet_processing_time_array: " > /shared/ppt_"${KEY}"-bit_s1.txt 
    echo "register_read packet_processing_time_array" | simple_switch_CLI >> /shared/ppt_"${KEY}"-bit_s1.txt 
fi

if [ "$DEQ_FLAG" = true ]; then
    echo "DEQ option was selected"
    echo "packet_dequeuing_timedelta_array: " >> /shared/deq_"${KEY}"-bit_s1.txt 
    echo "register_read packet_dequeuing_timedelta_array" | simple_switch_CLI >> /shared/deq_"${KEY}"-bit_s1.txt 
fi

# If no options were provided, show usage
if [ "$PPT_FLAG" = false ] && [ "$DEQ_FLAG" = false ]; then
    usage
fi


# echo "packet_processing_time_array: " > /shared/results_s1.txt
# echo "register_read packet_processing_time_array" | simple_switch_CLI >> /shared/results_s1.txt

# echo "" >> /shared/results_s1.txt 
# echo "packet_dequeuing_timedelta_array: " >> /shared/results_s1.txt
# echo "register_read packet_dequeuing_timedelta_array" | simple_switch_CLI >> /shared/results_s1.txt