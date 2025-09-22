#!/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt
import math

# Inizializza le liste per i dati
conn = []
tls_conn = []
DH = []

# Specifica il percorso del file di testo
file_path = "./results/connection/results_conn.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line:
            conn.append(float(line))

file_path = "./results/connection/results_conn_tls.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            tls_conn.append(float(line))

file_path = "./results/connection/results_DH.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            DH.append(float(line))

# Trunc all values to 9 decimal places
factor = 10**9
conn = [math.trunc(element * factor) / factor for element in conn]
conn = [element * 1000 for element in conn]
tls_conn = [math.trunc(element * factor) / factor for element in tls_conn]
tls_conn = [element * 1000 for element in tls_conn]
DH = [math.trunc(element * factor) / factor for element in DH]
DH = [element * 1000 for element in DH]

# Calcola la media dei valori
conn_avg = np.mean(conn)
tls_conn_avg = np.mean(tls_conn)

conn_DH = []
for i in range(len(conn)):
    conn_DH.append(conn[i] + DH[i])
DH_avg = np.mean(conn_DH)

# Stampa le medie
print("Avg conn: ", conn_avg)
print("Avg tls_conn: ", tls_conn_avg)
print("Avg conn_DH: ", DH_avg)
print("Avg DH: ", np.mean(DH))

# Calcola la deviazione standard
conn_std = np.std(conn)
tls_conn_std = np.std(tls_conn)
DH_std = np.std(conn_DH)

# Crea una lista con le medie
avg = [conn_avg, tls_conn_avg, DH_avg]
# Crea una lista con le deviazioni standard
std = [conn_std, tls_conn_std, DH_std]

# Crea una lista di stringhe per i valori sull'asse delle x
x_val = ['Modbus \nConnection', 'Modbus TLS\nConnection', 'Connection \nwith DH']

# Crea un grafico a barre
plt.bar(x_val, avg, color='tab:blue', yerr=std, ecolor='red', capsize=5)

#Aggiungi label sull'asse y
plt.ylabel('Avg Time (ms)', fontsize=18)

plt.xticks(fontsize=18)  # Imposta la dimensione dei numeri sull'asse delle x a 18
plt.yticks(fontsize=18)  # Imposta la dimensione dei numeri sull'asse delle y a 18

# Mostra il grafico
plt.show()