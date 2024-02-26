#!/bin/bash

echo "packet_processing_time_array: " > /shared/results_s1.txt
echo "register_read packet_processing_time_array" | simple_switch_CLI >> /shared/results_s1.txt

echo "" >> /shared/results_s1.txt
echo "packet_dequeuing_timedelta_array: " >> /shared/results_s1.txt
echo "register_read packet_dequeuing_timedelta_array" | simple_switch_CLI >> /shared/results_s1.txt