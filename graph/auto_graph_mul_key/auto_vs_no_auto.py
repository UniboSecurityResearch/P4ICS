#!/usr/bin/python3
import os
import numpy as np
import matplotlib.pyplot as plt

def read_and_filter(file_path):
    """
    Reads floating-point values one per line from file_path and filters
    out outliers using the interquartile range (IQR) method.
    """
    data = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data.append(float(line))
                except ValueError:
                    continue
    if not data:
        return data
    Q1, Q3 = np.percentile(data, [25, 75])
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    filtered_data = [x for x in data if lower_bound <= x <= upper_bound]
    return filtered_data

# Base directory where the files are located.
base_dir = "./results/mul_key/"

# ---------------------------
# Files for the two conditions
# ---------------------------
# With AutoTest (using the "cipher" files)
s1_with_auto_file = os.path.join(
    base_dir, "results_s1_cipher_write_packet_processing_time_128-bit.txt"
)
s2_with_auto_file = os.path.join(
    base_dir, "results_s2_cipher_write_packet_processing_time_128-bit.txt"
)

# No AutoTest (using the "chiper_no_auto" files)
s1_no_auto_file = os.path.join(
    base_dir, "results_s1_chiper_no_auto_write_packet_processing_time_128-bit.txt"
)
s2_no_auto_file = os.path.join(
    base_dir, "results_s2_chiper_no_auto_write_packet_processing_time_128-bit.txt"
)

# ---------------------------
# Read and filter the data from each file
# ---------------------------
s1_with_auto_data = read_and_filter(s1_with_auto_file)
s2_with_auto_data = read_and_filter(s2_with_auto_file)
s1_no_auto_data   = read_and_filter(s1_no_auto_file)
s2_no_auto_data   = read_and_filter(s2_no_auto_file)

# Compute mean processing times (if data missing, default to 0)
mean_s1_with_auto = np.mean(s1_with_auto_data) if s1_with_auto_data else 0
mean_s2_with_auto = np.mean(s2_with_auto_data) if s2_with_auto_data else 0
mean_s1_no_auto   = np.mean(s1_no_auto_data)   if s1_no_auto_data else 0
mean_s2_no_auto   = np.mean(s2_no_auto_data)   if s2_no_auto_data else 0

# Print out the computed means for verification
print("===== PACKET PROCESSING TIMES =====")
print("With AutoTest - Switch 1: Mean =", mean_s1_with_auto)
print("With AutoTest - Switch 2: Mean =", mean_s2_with_auto)
print("No AutoTest   - Switch 1: Mean =", mean_s1_no_auto)
print("No AutoTest   - Switch 2: Mean =", mean_s2_no_auto)

# ---------------------------
# Plotting: Stacked Bar Chart
# ---------------------------
# Two categories: "With AutoTest" and "No AutoTest"
categories = ["With AutoTest", "No AutoTest"]
x = np.arange(len(categories))
width = 0.5  # width of each bar

# Prepare the values for stacking:
# S1 is in orange (bottom) and S2 is in blue (stacked on top)
with_auto_s1 = mean_s1_with_auto
with_auto_s2 = mean_s2_with_auto

no_auto_s1   = mean_s1_no_auto
no_auto_s2   = mean_s2_no_auto

# Create the stacked bar chart
fig, ax = plt.subplots(figsize=(8, 6))

# Plot the bottom (Switch 1) bars
bar_with_auto = ax.bar(
    x[0], with_auto_s1, width, label="S1 (Orange)", color="tab:blue"
)
bar_no_auto   = ax.bar(
    x[1], no_auto_s1, width, label="S1 (Orange)", color="tab:blue"
)

# Plot the top (Switch 2) bars, stacked on top of S1 bars
ax.bar(
    x[0],
    with_auto_s2,
    width,
    bottom=with_auto_s1,
    label="S2",
    color="tab:orange"
)
ax.bar(
    x[1],
    no_auto_s2,
    width,
    bottom=no_auto_s1,
    label="S2",
    color="tab:orange"
)

ax.set_ylabel("Avg Packet Processing Time (ms)", fontsize=14)
ax.set_title("Stacked Packet Processing Time: With vs No AutoTest", fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=12)
ax.legend(fontsize=12)
plt.tight_layout()
plt.show()
