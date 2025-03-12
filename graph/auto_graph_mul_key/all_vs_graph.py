#!/usr/bin/python3
import math
import numpy as np
import matplotlib.pyplot as plt

# ------------------------------
# 1. Helper function: Process a list of numbers
#    (truncate to 9 decimals and convert seconds to milliseconds)
# ------------------------------
def process_list(data_list):
    factor = 10.0 ** 9  # for truncation to nine decimals
    for i in range(len(data_list)):
        data_list[i] = math.trunc(data_list[i] * factor) / factor
        data_list[i] = data_list[i] * 1000  # convert to milliseconds
    return data_list

# ------------------------------
# 2. Read Aggregated Data for Plain (Modbus) and TLS
# ------------------------------
# Plain (no encryption) from the no_cipher folder
r_no_cipher = []
w_no_cipher = []
no_cipher_read_file  = "./results/mul_key/no_cipher/results_10*10000_no_cipher_read.txt"
no_cipher_write_file = "./results/mul_key/no_cipher/results_10*10000_no_cipher_write.txt"

with open(no_cipher_read_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            r_no_cipher.append(float(line))
with open(no_cipher_write_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            w_no_cipher.append(float(line))

# TLS data from the modbus_tls folder
r_tls = []
w_tls = []
tls_read_file  = "./results/mul_key/modbus_tls/results_10*10000_tls_read.txt"
tls_write_file = "./results/mul_key/modbus_tls/results_10*10000_tls_write.txt"

with open(tls_read_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            r_tls.append(float(line))
with open(tls_write_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            w_tls.append(float(line))

# Process aggregated plain and TLS data.
r_no_cipher = process_list(r_no_cipher)
w_no_cipher = process_list(w_no_cipher)
r_tls       = process_list(r_tls)
w_tls       = process_list(w_tls)

# ------------------------------
# 3. Read In-Network Encryption Data (cipher) per Key Length
# ------------------------------
# Define key lengths for in-network encryption.
key_lengths = ['128-bit', '160-bit', '192-bit', '224-bit', '256-bit']

# Dictionaries to store read and write data per key.
r_cipher_keys = {kl: [] for kl in key_lengths}
w_cipher_keys = {kl: [] for kl in key_lengths}

for kl in key_lengths:
    # For file naming, extract only the numeric part (e.g. "128") from "128-bit"
    kl_filename = kl.split('-')[0]
    
    # Build file paths for read and write files in the cipher folder.
    read_file_path  = (
        f"./results/mul_key/cipher/results_10*10000_cipher_read_{kl_filename}_key.txt"
    )
    write_file_path = (
        f"./results/mul_key/cipher/results_10*10000_cipher_write_{kl_filename}_key.txt"
    )
    
    # Read the "read" data.
    try:
        with open(read_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    r_cipher_keys[kl].append(float(line))
    except Exception as e:
        print(f"Error reading {read_file_path}: {e}")
    
    # Read the "write" data.
    try:
        with open(write_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    w_cipher_keys[kl].append(float(line))
    except Exception as e:
        print(f"Error reading {write_file_path}: {e}")

# Process the per-key data.
for kl in key_lengths:
    r_cipher_keys[kl] = process_list(r_cipher_keys[kl])
    w_cipher_keys[kl] = process_list(w_cipher_keys[kl])

# ------------------------------
# 4. Compute Statistics (Mean and Standard Deviation)
# ------------------------------
# Aggregated statistics for Plain (Modbus) and TLS.
mean_r_no   = np.mean(r_no_cipher) if r_no_cipher else 0
std_r_no    = np.std(r_no_cipher)  if r_no_cipher else 0
mean_w_no   = np.mean(w_no_cipher) if w_no_cipher else 0
std_w_no    = np.std(w_no_cipher)  if w_no_cipher else 0

mean_r_tls  = np.mean(r_tls)  if r_tls else 0
std_r_tls   = np.std(r_tls)   if r_tls else 0
mean_w_tls  = np.mean(w_tls)  if w_tls else 0
std_w_tls   = np.std(w_tls)   if w_tls else 0

# Compute statistics for in-network encryption per key.
mean_r_cipher_keys = {}
std_r_cipher_keys  = {}
mean_w_cipher_keys = {}
std_w_cipher_keys  = {}

for kl in key_lengths:
    if r_cipher_keys[kl]:
        mean_r_cipher_keys[kl] = np.mean(r_cipher_keys[kl])
        std_r_cipher_keys[kl]  = np.std(r_cipher_keys[kl])
    else:
        mean_r_cipher_keys[kl] = 0
        std_r_cipher_keys[kl]  = 0
    if w_cipher_keys[kl]:
        mean_w_cipher_keys[kl] = np.mean(w_cipher_keys[kl])
        std_w_cipher_keys[kl]  = np.std(w_cipher_keys[kl])
    else:
        mean_w_cipher_keys[kl] = 0
        std_w_cipher_keys[kl]  = 0

# ------------------------------
# 4.1 Print the computed means
# ------------------------------
print("=== Aggregated Means ===")
print("Modbus (No cipher) - Read: {:.9f} ms, Write: {:.9f} ms"
      .format(mean_r_no, mean_w_no))
print("Modbus TLS - Read: {:.9f} ms, Write: {:.9f} ms"
      .format(mean_r_tls, mean_w_tls))

print("\n=== In-Network (cipher) Means per Key ===")
for kl in key_lengths:
    print("In-Network {} - Read: {:.9f} ms, Write: {:.9f} ms"
          .format(kl, mean_r_cipher_keys[kl], mean_w_cipher_keys[kl]))


# ------------------------------
# 4.2 Print percentage differences (compared to No cipher)
# ------------------------------
print("\n=== Percentage Differences (compared to Modbus without encryption) ===")
# TLS percentage difference
# read_tls_diff_pct = ((mean_r_tls - mean_r_no) / mean_r_no) * 100
# write_tls_diff_pct = ((mean_w_tls - mean_w_no) / mean_w_no) * 100
# print("Modbus TLS - Read: {:.2f}%, Write: {:.2f}%"
#       .format(read_tls_diff_pct, write_tls_diff_pct))

# In-Network encryption percentage differences
for kl in key_lengths:
    # Calculate percentage difference for read operations
    read_diff_pct = ((mean_r_cipher_keys[kl] - mean_r_no) / mean_r_no) * 100
    # Calculate percentage difference for write operations
    write_diff_pct = ((mean_w_cipher_keys[kl] - mean_w_no) / mean_w_no) * 100
    
    print("In-Network {} - Read: {:.2f}%, Write: {:.2f}%"
          .format(kl, read_diff_pct, write_diff_pct))



# ------------------------------
# 5. Organize Data for the Final Plots
# ------------------------------
# The final x-axis ordering:
#   0: "Modbus" (Plain / No encryption)
#   1: "Modbus TLS"
#   2: "In-Network 128-bit"
#   3: "In-Network 160-bit"
#   4: "In-Network 192-bit"
#   5: "In-Network 224-bit"
#   6: "In-Network 256-bit"
x_labels = [
    "Modbus",
    # "Modbus TLS",
    "In-Network 128-bit",
    "In-Network 160-bit",
    "In-Network 192-bit",
    "In-Network 224-bit",
    "In-Network 256-bit",
]

# Build arrays for read data.
# read_means = [mean_r_no, mean_r_tls] + [
#     mean_r_cipher_keys[kl] for kl in key_lengths
# ]
# read_std = [std_r_no, std_r_tls] + [
#     std_r_cipher_keys[kl] for kl in key_lengths
# ]

read_means = [mean_r_no] + [
    mean_r_cipher_keys[kl] for kl in key_lengths
]

read_std = [std_r_no] + [
    std_r_cipher_keys[kl] for kl in key_lengths
]


# Build arrays for write data.
# write_means = [mean_w_no, mean_w_tls] + [
#     mean_w_cipher_keys[kl] for kl in key_lengths
# ]
# write_std = [std_w_no, std_w_tls] + [
#     std_w_cipher_keys[kl] for kl in key_lengths
# ]

write_means = [mean_w_no] + [  # Remove mean_w_tls from here
    mean_w_cipher_keys[kl] for kl in key_lengths
]
write_std = [std_w_no] + [  # Remove std_w_tls from here
    std_w_cipher_keys[kl] for kl in key_lengths
]


# ------------------------------
# 6. Define Colors for Each Category
# ------------------------------
colors = [
    "tab:blue",        # Modbus (plain)
    "tab:green",       # Modbus TLS
    "crimson",         # In-Network 128-bit
    "darkorange",      # In-Network 160-bit
    "mediumorchid",    # In-Network 192-bit
    "gold",            # In-Network 224-bit
    "chocolate",       # In-Network 256-bit
]

# ------------------------------
# 7. Plot the Read Data (Bars Touching, No Space in Between)
# ------------------------------
n_read = len(read_means)
x_read = np.arange(n_read)
bar_width = 1.0

fig, ax = plt.subplots(figsize=(12, 7))
bars = ax.bar(x_read, read_means, width=bar_width, yerr=read_std,
              align="edge", capsize=4, color=colors)
ax.set_xticks(x_read + bar_width / 2)
ax.set_xticklabels(x_labels, fontsize=14, rotation=15)
ax.set_ylabel("Avg Read Time (ms)", fontsize=16)
ax.set_title("Read Performance by Encryption Mode", fontsize=18)
plt.tight_layout()
plt.show()

# ------------------------------
# 8. Plot the Write Data (Bars Touching, No Space in Between)
# ------------------------------
n_write = len(write_means)
x_write = np.arange(n_write)

fig, ax = plt.subplots(figsize=(12, 7))
bars = ax.bar(x_write, write_means, width=bar_width, yerr=write_std,
              align="edge", capsize=4, color=colors)
ax.set_xticks(x_write + bar_width / 2)
ax.set_xticklabels(x_labels, fontsize=14, rotation=15)
ax.set_ylabel("Avg Write Time (ms)", fontsize=16)
ax.set_title("Write Performance by Encryption Mode", fontsize=18)
plt.tight_layout()
plt.show()
