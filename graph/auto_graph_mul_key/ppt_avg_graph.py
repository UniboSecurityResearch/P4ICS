#!/usr/bin/python3
import os
import numpy as np
import matplotlib.pyplot as plt

def read_and_filter(file_path):
    """
    Read the data from a file and filter out outliers using the IQR method.
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

# List of encryption key lengths for the in-switch encryption tests.
key_lengths = ['128-bit', '160-bit', '192-bit', '224-bit', '256-bit']

# Base directory where your files are located.
base_dir = "./results/mul_key/"

# ---------------------------
# Plain (no_cipher) files for packet processing time tests (Switch 1 and Switch 2)
# ---------------------------
plain_read_file_s1 = os.path.join(
    base_dir, "no_cipher", "results_s1_no_cipher_read_packet_processing_time.txt"
)
plain_read_file_s2 = os.path.join(
    base_dir, "no_cipher", "results_s2_no_cipher_read_packet_processing_time.txt"
)
plain_write_file_s1 = os.path.join(
    base_dir, "no_cipher", "results_s1_no_cipher_write_packet_processing_time.txt"
)
plain_write_file_s2 = os.path.join(
    base_dir, "no_cipher", "results_s2_no_cipher_write_packet_processing_time.txt"
)

# Read and filter the plain data.
plain_read_s1 = read_and_filter(plain_read_file_s1)
plain_read_s2 = read_and_filter(plain_read_file_s2)
plain_write_s1 = read_and_filter(plain_write_file_s1)
plain_write_s2 = read_and_filter(plain_write_file_s2)

mean_plain_read_s1 = np.mean(plain_read_s1) if plain_read_s1 else 0
mean_plain_read_s2 = np.mean(plain_read_s2) if plain_read_s2 else 0
mean_plain_write_s1 = np.mean(plain_write_s1) if plain_write_s1 else 0
mean_plain_write_s2 = np.mean(plain_write_s2) if plain_write_s2 else 0

# ---------------------------
# Modbus in-switch encryption (cipher) files for packet processing time tests
# (Switch 1 and Switch 2 for each key length)
# ---------------------------
cipher_read_s1 = {}
cipher_read_s2 = {}
cipher_write_s1 = {}
cipher_write_s2 = {}

for kl in key_lengths:
    read_s1_file = os.path.join(
        base_dir, "cipher",
        f"results_s1_cipher_read_packet_processing_time_{kl}.txt"
    )
    read_s2_file = os.path.join(
        base_dir, "cipher",
        f"results_s2_cipher_read_packet_processing_time_{kl}.txt"
    )
    write_s1_file = os.path.join(
        base_dir, "cipher",
        f"results_s1_cipher_write_packet_processing_time_{kl}.txt"
    )
    write_s2_file = os.path.join(
        base_dir, "cipher",
        f"results_s2_cipher_write_packet_processing_time_{kl}.txt"
    )
    
    cipher_read_s1[kl] = read_and_filter(read_s1_file)
    cipher_read_s2[kl] = read_and_filter(read_s2_file)
    cipher_write_s1[kl] = read_and_filter(write_s1_file)
    cipher_write_s2[kl] = read_and_filter(write_s2_file)

mean_cipher_read_s1 = {}
mean_cipher_read_s2 = {}
mean_cipher_write_s1 = {}
mean_cipher_write_s2 = {}

for kl in key_lengths:
    mean_cipher_read_s1[kl] = np.mean(cipher_read_s1[kl]) if cipher_read_s1[kl] else 0
    mean_cipher_read_s2[kl] = np.mean(cipher_read_s2[kl]) if cipher_read_s2[kl] else 0
    mean_cipher_write_s1[kl] = np.mean(cipher_write_s1[kl]) if cipher_write_s1[kl] else 0
    mean_cipher_write_s2[kl] = np.mean(cipher_write_s2[kl]) if cipher_write_s2[kl] else 0

# ---------------------------
# Modbus TLS files for packet processing time tests (Switch 1 and Switch 2)
# ---------------------------
# tls_read_file_s1 = os.path.join(
#     base_dir, "modbus_tls", "results_s1_tls_read_packet_processing_time.txt"
# )
# tls_read_file_s2 = os.path.join(
#     base_dir, "modbus_tls", "results_s2_tls_read_packet_processing_time.txt"
# )
# tls_write_file_s1 = os.path.join(
#     base_dir, "modbus_tls", "results_s1_tls_write_packet_processing_time.txt"
# )
# tls_write_file_s2 = os.path.join(
#     base_dir, "modbus_tls", "results_s2_tls_write_packet_processing_time.txt"
# )

# tls_read_s1 = read_and_filter(tls_read_file_s1)
# tls_read_s2 = read_and_filter(tls_read_file_s2)
# tls_write_s1 = read_and_filter(tls_write_file_s1)
# tls_write_s2 = read_and_filter(tls_write_file_s2)

# mean_tls_read_s1 = np.mean(tls_read_s1) if tls_read_s1 else 0
# mean_tls_read_s2 = np.mean(tls_read_s2) if tls_read_s2 else 0
# mean_tls_write_s1 = np.mean(tls_write_s1) if tls_write_s1 else 0
# mean_tls_write_s2 = np.mean(tls_write_s2) if tls_write_s2 else 0

# ---------------------------
# Print computed means for verification.
# ---------------------------
print("===== READ PACKET PROCESSING TIMES =====")
# print("No encryption S1: Mean =", mean_plain_read_s1)
# print("No encryption S2: Mean =", mean_plain_read_s2)
print("No encryption S1+S2: Mean =", mean_plain_read_s1+mean_plain_read_s2)
# print("Modbus TLS S1: Mean =", mean_tls_read_s1)
# print("Modbus TLS S2: Mean =", mean_tls_read_s2)
for kl in key_lengths:
    # print(f"Modbus in-switch encryption {kl} S1: Mean = {mean_cipher_read_s1[kl]}")
    # print(f"Modbus in-switch encryption {kl} S2: Mean = {mean_cipher_read_s2[kl]}")
    print(f"Modbus in-switch encryption {kl} S1+S2: Mean = ",
        mean_cipher_read_s1[kl]+mean_cipher_read_s2[kl])

print("\n===== WRITE PACKET PROCESSING TIMES =====")
# print("No encryption S1: Mean =", mean_plain_write_s1)
# print("No encryption S2: Mean =", mean_plain_write_s2)
print("No encryption S1+S2: Mean =", mean_plain_write_s1+mean_plain_write_s2)

# print("Modbus TLS S1: Mean =", mean_tls_write_s1)
# print("Modbus TLS S2: Mean =", mean_tls_write_s2)
for kl in key_lengths:
    print(f"Modbus in-switch encryption {kl} S1: Mean = {mean_cipher_write_s1[kl]}")
    print(f"Modbus in-switch encryption {kl} S2: Mean = {mean_cipher_write_s2[kl]}")
    print(f"Modbus in-switch encryption {kl} S2: Mean = ",
        mean_cipher_write_s1[kl]+mean_cipher_write_s2[kl])

print("\n===== PERCENTAGE DIFFERENCES FOR READ PACKET PROCESSING =====")
print("(Showing how much longer encryption takes compared to plain data)")

# Calculate combined plain read value for convenience
combined_plain_read = mean_plain_read_s1 + mean_plain_read_s2

# print("\nSwitch 1:")
# for kl in key_lengths:
#     pct_diff_s1 = ((mean_cipher_read_s1[kl] - mean_plain_read_s1) / mean_plain_read_s1) * 100
#     print(f"  {kl}: {pct_diff_s1:.2f}%")

# print("\nSwitch 2:")
# for kl in key_lengths:
#     pct_diff_s2 = ((mean_cipher_read_s2[kl] - mean_plain_read_s2) / mean_plain_read_s2) * 100
#     print(f"  {kl}: {pct_diff_s2:.2f}%")

print("\nCombined (S1+S2):")
for kl in key_lengths:
    combined_cipher_read = mean_cipher_read_s1[kl] + mean_cipher_read_s2[kl]
    pct_diff_combined = ((combined_cipher_read - combined_plain_read) / combined_plain_read) * 100
    print(f"  {kl}: {pct_diff_combined:.2f}%")

print("\n===== PERCENTAGE DIFFERENCES FOR WRITE PACKET PROCESSING =====")
print("(Showing how much longer encryption takes compared to plain data)")

# Calculate combined plain write value for convenience
combined_plain_write = mean_plain_write_s1 + mean_plain_write_s2

# print("\nSwitch 1:")
# for kl in key_lengths:
#     pct_diff_s1 = ((mean_cipher_write_s1[kl] - mean_plain_write_s1) / mean_plain_write_s1) * 100
#     print(f"  {kl}: {pct_diff_s1:.2f}%")

# print("\nSwitch 2:")
# for kl in key_lengths:
#     pct_diff_s2 = ((mean_cipher_write_s2[kl] - mean_plain_write_s2) / mean_plain_write_s2) * 100
#     print(f"  {kl}: {pct_diff_s2:.2f}%")

print("\nCombined (S1+S2):")
for kl in key_lengths:
    combined_cipher_write = mean_cipher_write_s1[kl] + mean_cipher_write_s2[kl]
    pct_diff_combined = ((combined_cipher_write - combined_plain_write) / combined_plain_write) * 100
    print(f"  {kl}: {pct_diff_combined:.2f}%")

# ---------------------------
# Prepare data arrays for the Stacked Bar Charts.
#
# The order is:
#    1. No encryption
#    2. Modbus TLS
#    3. Modbus in-switch encryption <key-length> (for each key)
# ---------------------------
categories = [
    "Modbus",
    # "Modbus TLS",
    "Modbus\nIn-Network\nEncryption\n128-bit",
    "Modbus\nIn-Network\nEncryption\n160-bit",
    "Modbus\nIn-Network\nEncryption\n192-bit",
    "Modbus\nIn-Network\nEncryption\n224-bit",
    "Modbus\nIn-Network\nEncryption\n256-bit",
]

x = np.arange(len(categories))
width = 0.5

# ----- READ Packet Processing Time Stacked Bar Chart -----
# read_s1_means = (
#     [mean_plain_read_s1, mean_tls_read_s1] +
#     [mean_cipher_read_s1[kl] for kl in key_lengths]
# )
# read_s2_means = (
#     [mean_plain_read_s2, mean_tls_read_s2] +
#     [mean_cipher_read_s2[kl] for kl in key_lengths]
# )

read_s1_means = (
    [mean_plain_read_s1] +
    [mean_cipher_read_s1[kl] for kl in key_lengths]
)
read_s2_means = (
    [mean_plain_read_s2] +
    [mean_cipher_read_s2[kl] for kl in key_lengths]
)

fig, ax = plt.subplots(figsize=(15, 12))
bar_s1 = ax.bar(x, read_s1_means, width, label='Switch 1',
                color='tab:blue')
bar_s2 = ax.bar(x, read_s2_means, width, bottom=read_s1_means,
                label='Switch 2', color='tab:orange')

ax.set_ylabel('Avg Packet Processing Time (μs)', fontsize=14)
ax.set_title('Read Performance', fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=12, rotation=15)
ax.legend(fontsize=12, loc='upper right')
plt.tight_layout()
plt.show()

# ----- WRITE Packet Processing Time Stacked Bar Chart -----
# write_s1_means = (
#     [mean_plain_write_s1, mean_tls_write_s1] +
#     [mean_cipher_write_s1[kl] for kl in key_lengths]
# )
# write_s2_means = (
#     [mean_plain_write_s2, mean_tls_write_s2] +
#     [mean_cipher_write_s2[kl] for kl in key_lengths]
# )

write_s1_means = (
    [mean_plain_write_s1] +
    [mean_cipher_write_s1[kl] for kl in key_lengths]
)
write_s2_means = (
    [mean_plain_write_s2] +
    [mean_cipher_write_s2[kl] for kl in key_lengths]
)

fig, ax = plt.subplots(figsize=(15, 12))
bar_s1 = ax.bar(x, write_s1_means, width, label='Switch 1',
                color='tab:blue')
bar_s2 = ax.bar(x, write_s2_means, width, bottom=write_s1_means,
                label='Switch 2', color='tab:orange')

ax.set_ylabel('Avg Packet Processing Time (μs)', fontsize=14)
ax.set_title('Write Performance', fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=12, rotation=15)
ax.legend(fontsize=12, loc='upper right')
plt.tight_layout()
plt.show()
