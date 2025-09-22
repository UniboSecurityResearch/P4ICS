#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt

order = [
    ("Plaintext", "rtt_plaintext_no_switch.txt"),
    ("128 bit\nkey", "rtt_128.txt"),
    ("192 bit\nkey", "rtt_192.txt"),
    ("256 bit\nkey", "rtt_256.txt"),
    ("TLS", "rtt_tls.txt"),
]

def load_vals(path):
    with open(path, "r") as f:
        return np.array([float(line.strip()) for line in f if line.strip()])

def remove_outliers_percentile(arr, upper=99):
    """Rimuove i valori oltre il percentile specificato (default: 99°)."""
    cutoff = np.percentile(arr, upper)
    return arr[arr <= cutoff]

labels = []
means_ms = []
stds_ms = []

for label, filename in order:
    vals = load_vals(filename)

    # Scarta solo l'1% più alto per 128/192/256/TLS
    if label in ["128 bit\nkey", "192 bit\nkey", "256 bit\nkey", "TLS"]:
        vals = remove_outliers_percentile(vals, upper=98.995)

    labels.append(label)
    means_ms.append(np.mean(vals) * 1000.0)          # s → ms
    stds_ms.append(np.std(vals, ddof=1) * 1000.0)    # s → ms

means_ms = np.array(means_ms)
stds_ms = np.array(stds_ms)

plt.figure(figsize=(9, 5.5))
bar_colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d6ca27", "#793C00"]
x = np.arange(len(labels))

# Colonne con errore
error_kw = dict(elinewidth=1, ecolor="red", capsize=2)
plt.bar(x, means_ms, color=bar_colors, error_kw=error_kw, zorder=-2)

# Barre d'errore + marker
plt.errorbar(
    x, means_ms, yerr=stds_ms,
    fmt='o', color='red', mfc='white', zorder=1,
    ecolor='red', elinewidth=2, capsize=6, markersize=6
)

plt.ylabel("Avg Time (ms)", fontsize=20)
plt.yticks(fontsize=18)
plt.xlabel("")
plt.xticks(x, labels, rotation=0, fontsize=18)

for xm, mean, std in zip(x, means_ms, stds_ms):
    y_text = mean + (0.02 * float(np.max(means_ms + stds_ms)))
    plt.text(xm + 0.05, y_text, f"{mean:.3f}", ha="left", va="bottom", fontsize=18)

plt.tight_layout()
plt.savefig("rtt_mqtt.pdf")
print("Grafico salvato come rtt_mqtt.pdf")
