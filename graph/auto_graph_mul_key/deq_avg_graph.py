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

# List of encryption key lengths for the cipher tests
key_lengths = ['128-bit', '160-bit', '192-bit', '224-bit', '256-bit']

# Base directory where your files are located.
base_dir = "./results/mul_key/"

# ---------------------------
# Plain (no cipher) files for read and write tests (S1 and S2)
# ---------------------------
plain_read_file_s1 = os.path.join(
    base_dir, "results_s1_no_chiper_read_packet_dequeuing_timedelta_array.txt"
)
plain_read_file_s2 = os.path.join(
    base_dir, "results_s2_no_chiper_read_packet_dequeuing_timedelta_array.txt"
)
plain_write_file_s1 = os.path.join(
    base_dir, "results_s1_no_chiper_write_packet_dequeuing_timedelta_array.txt"
)
plain_write_file_s2 = os.path.join(
    base_dir, "results_s2_no_chiper_write_packet_dequeuing_timedelta_array.txt"
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
# Cipher files for each key length (for both read and write tests)
# ---------------------------
cipher_read_s1 = {}
cipher_read_s2 = {}
cipher_write_s1 = {}
cipher_write_s2 = {}

for kl in key_lengths:
    read_s1_file = os.path.join(
        base_dir, f"results_s1_cipher_read_packet_dequeuing_timedelta_array_{kl}.txt"
    )
    read_s2_file = os.path.join(
        base_dir, f"results_s2_cipher_read_packet_dequeuing_timedelta_array_{kl}.txt"
    )
    write_s1_file = os.path.join(
        base_dir, f"results_s1_cipher_write_packet_dequeuing_timedelta_array_{kl}.txt"
    )
    write_s2_file = os.path.join(
        base_dir, f"results_s2_cipher_write_packet_dequeuing_timedelta_array_{kl}.txt"
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
    mean_cipher_read_s1[kl] = (np.mean(cipher_read_s1[kl])
                                 if cipher_read_s1[kl] else 0)
    mean_cipher_read_s2[kl] = (np.mean(cipher_read_s2[kl])
                                 if cipher_read_s2[kl] else 0)
    mean_cipher_write_s1[kl] = (np.mean(cipher_write_s1[kl])
                                  if cipher_write_s1[kl] else 0)
    mean_cipher_write_s2[kl] = (np.mean(cipher_write_s2[kl])
                                  if cipher_write_s2[kl] else 0)

# Print out the computed means for verification.
print("===== READ TIMES =====")
print("Plain S1: Mean =", mean_plain_read_s1)
print("Plain S2: Mean =", mean_plain_read_s2)
for kl in key_lengths:
    print(f"Cipher {kl} S1: Mean = {mean_cipher_read_s1[kl]}")
    print(f"Cipher {kl} S2: Mean = {mean_cipher_read_s2[kl]}")

print("\n===== WRITE TIMES =====")
print("Plain S1: Mean =", mean_plain_write_s1)
print("Plain S2: Mean =", mean_plain_write_s2)
for kl in key_lengths:
    print(f"Cipher {kl} S1: Mean = {mean_cipher_write_s1[kl]}")
    print(f"Cipher {kl} S2: Mean = {mean_cipher_write_s2[kl]}")

# ---------------------------
# Plotting Stacked Bar Charts
# ---------------------------

# Categories for the x-axis: "Plain" followed by each key length.
categories = ['Plain'] + key_lengths
x = np.arange(len(categories))
width = 0.5

# ----- Read Times Stacked Bar Chart -----
# Prepare the means such that S1 is the bottom stack (orange)
# and S2 is stacked on top (blue)
read_s1_means = [mean_plain_read_s1] + [
    mean_cipher_read_s1[kl] for kl in key_lengths
]
read_s2_means = [mean_plain_read_s2] + [
    mean_cipher_read_s2[kl] for kl in key_lengths
]

fig, ax = plt.subplots(figsize=(10, 6))
bar_s1 = ax.bar(x, read_s1_means, width, label='Switch 1',
                color='tab:orange')
bar_s2 = ax.bar(x, read_s2_means, width, bottom=read_s1_means,
                label='Switch 2', color='tab:blue')

ax.set_ylabel('Avg Packet Dequeuing Time (μs)', fontsize=14)
ax.set_title('Stacked Read Times', fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=12)
ax.legend(fontsize=12)
plt.tight_layout()
plt.show()

# ----- Write Times Stacked Bar Chart -----
write_s1_means = [mean_plain_write_s1] + [
    mean_cipher_write_s1[kl] for kl in key_lengths
]
write_s2_means = [mean_plain_write_s2] + [
    mean_cipher_write_s2[kl] for kl in key_lengths
]

fig, ax = plt.subplots(figsize=(10, 6))
bar_s1 = ax.bar(x, write_s1_means, width, label='Switch 1',
                color='tab:orange')
bar_s2 = ax.bar(x, write_s2_means, width, bottom=write_s1_means,
                label='Switch 2', color='tab:blue')

ax.set_ylabel('Avg Packet Dequeuing Time (μs)', fontsize=14)
ax.set_title('Stacked Write Times', fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=12)
ax.legend(fontsize=12)
plt.tight_layout()
plt.show()
