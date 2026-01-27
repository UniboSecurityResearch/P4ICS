#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt
import math

# --- 1. CARICAMENTO E ELABORAZIONE DATI (Logica originale mantenuta) ---

conn = []
tls_conn = []
DH = []

# Caricamento dati (assicurati che i percorsi siano corretti rispetto a dove esegui lo script)
try:
    with open("../connection/results_conn.txt", 'r') as file:
        conn = [float(line.strip()) for line in file if line.strip()]
    
    with open("../connection/results_conn_tls.txt", 'r') as file:
        tls_conn = [float(line.strip()) for line in file if line.strip()]
    
    with open("../connection/results_DH.txt", 'r') as file:
        DH = [float(line.strip()) for line in file if line.strip()]
except FileNotFoundError as e:
    print(f"Errore: File non trovato. {e}")

# Trunc all values to 9 decimal places and convert to ms
factor = 10**9
conn = [math.trunc(element * factor) / factor * 1000 for element in conn]
tls_conn = [math.trunc(element * factor) / factor * 1000 for element in tls_conn]
DH = [math.trunc(element * factor) / factor * 1000 for element in DH]

# Calcolo medie e std originali
conn_avg = np.mean(conn)
tls_conn_avg = np.mean(tls_conn)

conn_DH = []
# Assumiamo che conn e DH abbiano la stessa lunghezza come nello script originale
min_len = min(len(conn), len(DH))
for i in range(min_len):
    conn_DH.append(conn[i] + DH[i])
DH_avg = np.mean(conn_DH)

# Calcolo deviazioni standard
conn_std = np.std(conn, ddof=1) # ddof=1 è standard per campioni statistici
tls_conn_std = np.std(tls_conn, ddof=1)
DH_std = np.std(conn_DH, ddof=1)

# Preparazione liste per il plot
means = [conn_avg, tls_conn_avg, DH_avg]
stds = [conn_std, tls_conn_std, DH_std]
labels = ['Modbus \nConnection', 'Modbus TLS\nConnection', 'Connection \nwith DH']


# --- 2. PLOTTING (Nuovo stile applicato) ---

plt.figure(figsize=(9, 5.5))

# Palette colori presa dallo script di riferimento (prime 3)
bar_colors = ["#1f77b4", "#ff7f0e", "#2ca02c"] 
x = np.arange(len(labels))

# Disegno le barre principali
# zorder=-2 mette le barre dietro agli altri elementi grafici
plt.bar(x, means, color=bar_colors, zorder=-2)

# Disegno le barre di errore con lo stile specifico (cerchio bianco con bordo rosso)
plt.errorbar(x, means, yerr=stds, fmt='o', color='red', mfc='white', zorder=1, 
             ecolor='red', elinewidth=2, capsize=6, markersize=6)

# Formattazione assi e label
plt.ylabel('Avg Time (ms)', fontsize=20)
plt.yticks(fontsize=18)
plt.xticks(x, labels, fontsize=18)

# Aggiunta valori sopra le barre
# Calcolo un offset dinamico basato sull'altezza massima del grafico
max_height = np.max(np.array(means) + np.array(stds))
offset = 0.02 * max_height

for xm, mean, std in zip(x, means, stds):
    # Posiziona il testo un po' sopra la barra di errore superiore
    y_text = mean + offset
    
    plt.text(xm + 0.05, y_text, f"{mean:.3f}", ha="left", va="bottom", fontsize=18)

# Salvataggio e visualizzazione
plt.tight_layout()
output_filename = "rtt_comparison_styled.pdf"
plt.savefig(output_filename)
print(f"Grafico salvato come {output_filename}")
plt.show()