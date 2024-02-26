#!/usr/bin/python3

import os, re, sys
from statistics import stdev, variance         

def extract_results():
    if len(sys.argv) == 2:
        directory = './' + sys.argv[1] + '/'
    else:
        directory = './'

    for filename in os.listdir(directory):
        print(filename)
        f = os.path.join(directory, filename)
        if os.path.isfile(f):
            with open(f, "r") as results_file:
                match = re.findall("RuntimeCmd: packet_processing_time_array= .*", results_file.read())
                packet_processing_time_array = str(match).replace("RuntimeCmd: packet_processing_time_array= ", "").replace(" ","").replace("']","").replace("['","").split(",")
                packet_processing_time_array = list(map(lambda x: float(x), packet_processing_time_array))

                results_file.seek(0)
                match = re.findall("RuntimeCmd: packet_dequeuing_timedelta_array= .*", results_file.read())
                packet_dequeuing_timedelta_array = str(match).replace("RuntimeCmd: packet_dequeuing_timedelta_array= ", "").replace(" ","").replace("']","").replace("['","").split(",")
                packet_dequeuing_timedelta_array = list(map(lambda x: float(x), packet_dequeuing_timedelta_array))

                # write number packet_processing_time_array on filename_packet_processing_time.txt
                with open(directory + filename.split(".txt")[0] + "_packet_processing_time.txt", "w") as packet_processing_time_file:
                    for i in range(len(packet_processing_time_array)):
                        packet_processing_time_file.write("%s\n" % (packet_processing_time_array[i]))
                
                # write number packet_dequeuing_timedelta_array on filename_packet_dequeuing_timedelta.txt
                with open(directory + filename.split(".txt")[0] + "_packet_dequeuing_timedelta.txt", "w") as packet_dequeuing_timedelta_file:
                    for i in range(len(packet_dequeuing_timedelta_array)):
                        packet_dequeuing_timedelta_file.write("%s\n" % (packet_dequeuing_timedelta_array[i]))

if __name__ == "__main__":
    extract_results()