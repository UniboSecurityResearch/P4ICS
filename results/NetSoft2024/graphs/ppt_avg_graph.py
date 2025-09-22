#!/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt
import math

# Inizializza le liste per i dati
r_s1 = []
r_s2 = []
r_encrypt_s1 = []
r_encrypt_s2 = []
# r_tls_s1 = []
# r_tls_s2 = []

# Specifica il percorso del file di testo
file_path = "./results/switch/results_s1_read_packet_processing_time.txt"
# Leggi i dati dal file, prendendo solo una riga ogni 4
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line:
            r_s1.append(float(line))
# Rimuovi i valori anomali
Q3, Q1 = np.percentile(r_s1, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in r_s1:
    if el < upper_bound and el > lower_bound:
        r_s1.remove(el)

file_path = "./results/switch/results_s2_read_packet_processing_time.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            r_s2.append(float(line))
Q3, Q1 = np.percentile(r_s2, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in r_s2:
    if el < upper_bound and el > lower_bound:
        r_s2.remove(el)



file_path = "./results/switch/results_s1_cipher_read_packet_processing_time.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            r_encrypt_s1.append(float(line))
Q3, Q1 = np.percentile(r_encrypt_s1, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in r_encrypt_s1:
    if el < upper_bound and el > lower_bound:
        r_encrypt_s1.remove(el)

file_path = "./results/switch/results_s2_cipher_read_packet_processing_time.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            r_encrypt_s2.append(float(line))
Q3, Q1 = np.percentile(r_encrypt_s2, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in r_encrypt_s2:
    if el < upper_bound and el > lower_bound:
        r_encrypt_s2.remove(el)

# file_path = "./results/switch/results_s1_tls_read_packet_processing_time.txt"
# with open(file_path, 'r') as file:
#     for line in file:
#         line = line.strip()
#         if line:
#             r_tls_s1.append(float(line))
# Q3, Q1 = np.percentile(r_tls_s1, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in r_tls_s1:
#     if el < upper_bound and el > lower_bound:
#         r_tls_s1.remove(el)

# file_path = "./results/switch/results_s2_tls_read_packet_processing_time.txt"
# with open(file_path, 'r') as file:
#     for line in file:
#         line = line.strip()
#         if line:
#             r_tls_s2.append(float(line))
# Q3, Q1 = np.percentile(r_tls_s2, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in r_tls_s2:
#     if el < upper_bound and el > lower_bound:
#         r_tls_s2.remove(el)

# Calcola la media
mean_r_s1 = np.mean(r_s1)
mean_r_s2 = np.mean(r_s2)
mean_r_encrypt_s1 = np.mean(r_encrypt_s1)
mean_r_encrypt_s2 = np.mean(r_encrypt_s2)
# mean_r_tls_s1 = np.mean(r_tls_s1)
# mean_r_tls_s2 = np.mean(r_tls_s2)

# stampa le medie
print("mean_r_s1: ", mean_r_s1)
print("mean_r_s2: ", mean_r_s2)
print("mean_r_encrypt_s1: ", mean_r_encrypt_s1)
print("mean_r_encrypt_s2: ", mean_r_encrypt_s2)
# print("mean_r_tls_s1: ", mean_r_tls_s1)
# print("mean_r_tls_s2: ", mean_r_tls_s2)

# Calcola la deviazione standard
std_dev_r_s1 = np.std(r_s1)
std_dev_r_s2 = np.std(r_s2)
std_dev_r_encrypt_s1 = np.std(r_encrypt_s1)
std_dev_r_encrypt_s2 = np.std(r_encrypt_s2)
# std_dev_r_tls_s1 = np.std(r_tls_s1)
# std_dev_r_tls_s2 = np.std(r_tls_s2)

# Inizializza le liste per i dati
w_s1 = []
w_s2 = []
w_encrypt_s1 = []
w_encrypt_s2 = []
# w_tls_s1 = []
# w_tls_s2 = []

# Specifica il percorso del file di testo
file_path = "./results/switch/results_s1_write_packet_processing_time.txt"
# Leggi i dati dal file, prendendo solo una riga ogni 4
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line:
            w_s1.append(float(line))
# Rimuovi i valori anomali
Q3, Q1 = np.percentile(w_s1, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in w_s1:
    if el < upper_bound and el > lower_bound:
        w_s1.remove(el)

file_path = "./results/switch/results_s2_write_packet_processing_time.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            w_s2.append(float(line))
Q3, Q1 = np.percentile(w_s2, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in w_s2:
    if el < upper_bound and el > lower_bound:
        w_s2.remove(el)



file_path = "./results/switch/results_s1_cipher_write_packet_processing_time.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            w_encrypt_s1.append(float(line))
Q3, Q1 = np.percentile(w_encrypt_s1, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in w_encrypt_s1:
    if el < upper_bound and el > lower_bound:
        w_encrypt_s1.remove(el)

file_path = "./results/switch/results_s2_cipher_write_packet_processing_time.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            w_encrypt_s2.append(float(line))
Q3, Q1 = np.percentile(w_encrypt_s2, [75, 25])
IQR = Q3 - Q1
upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR
for el in w_encrypt_s2:
    if el < upper_bound and el > lower_bound:
        w_encrypt_s2.remove(el)

# file_path = "./results/switch/results_s1_tls_write_packet_processing_time.txt"
# with open(file_path, 'r') as file:
#     for line in file:
#         line = line.strip()
#         if line:
#             w_tls_s1.append(float(line))
# Q3, Q1 = np.percentile(w_tls_s1, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in w_tls_s1:
#     if el < upper_bound and el > lower_bound:
#         w_tls_s1.remove(el)

# file_path = "./results/switch/results_s2_tls_write_packet_processing_time.txt"
# with open(file_path, 'r') as file:
#     for line in file:
#         line = line.strip()
#         if line:
#             w_tls_s2.append(float(line))
# Q3, Q1 = np.percentile(w_tls_s2, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in w_tls_s2:
#     if el < upper_bound and el > lower_bound:
#         w_tls_s2.remove(el)

# Calcola la media
mean_w_s1 = np.mean(w_s1)
mean_w_s2 = np.mean(w_s2)
mean_w_encrypt_s1 = np.mean(w_encrypt_s1)
mean_w_encrypt_s2 = np.mean(w_encrypt_s2)
# mean_w_tls_s1 = np.mean(w_tls_s1)
# mean_w_tls_s2 = np.mean(w_tls_s2)

# stampa le medie
print("mean_w_s1: ", mean_w_s1)
print("mean_w_s2: ", mean_w_s2)
print("mean_w_encrypt_s1: ", mean_w_encrypt_s1)
print("mean_w_encrypt_s2: ", mean_w_encrypt_s2)
# print("mean_w_tls_s1: ", mean_w_tls_s1)
# print("mean_w_tls_s2: ", mean_w_tls_s2)

# Calcola la deviazione standard
std_dev_w_s1 = np.std(w_s1)
std_dev_w_s2 = np.std(w_s2)
std_dev_w_encrypt_s1 = np.std(w_encrypt_s1)
std_dev_w_encrypt_s2 = np.std(w_encrypt_s2)
# std_dev_w_tls_s1 = np.std(w_tls_s1)
# std_dev_w_tls_s2 = np.std(w_tls_s2)

# Crea una lista con le medie
y_val_s1 = [mean_r_s1, mean_r_encrypt_s1, mean_w_s1, mean_w_encrypt_s1]#, mean_r_tls_s1]
y_val_s2 = [mean_r_s2, mean_r_encrypt_s2, mean_w_s2, mean_w_encrypt_s2]#, mean_r_tls_s2]

# Crea una lista di stringhe per i valori sull'asse delle x
x_val = ['Modbus\nRead', 'Modbus Read\nin-switch\nencryption', 'Modbus\nWrite', 'Modbus Write\nin-switch\nencryption']#, 'Modbus Read TLS']

# Crea un grafico a barre
plt.bar(x_val, y_val_s1, color='tab:blue', label='Switch 1', width=0.5)#, yerr=[std_dev_r_s1, std_dev_r_encrypt_s1], ecolor='red', capsize=5)
#plt.bar(x_val, y_val_s1, color='tab:blue', label='Switch 1', yerr=[std_dev_r_s1, std_dev_r_encrypt_s1, std_dev_r_tls_s1], ecolor='red', capsize=5)

plt.bar(x_val, y_val_s2, color='tab:orange', label='Switch 2', bottom=y_val_s1, width=0.5)#, yerr=[std_dev_r_s2, std_dev_r_encrypt_s2], ecolor='black', capsize=5)
#plt.bar(x_val, y_val_s2, color='tab:orange', label='Switch 2', bottom=y_val_s1, yerr=[std_dev_r_s2, std_dev_r_encrypt_s2, std_dev_r_tls_s2], ecolor='black', capsize=5)

#Aggiungi label sull'asse y
plt.ylabel('Avg Packet Processing Time (ms)', fontsize=13)

# Modifica la dimensione dei numeri sull'asse delle x e delle y
plt.xticks(fontsize=13)  # Imposta la dimensione dei numeri sull'asse delle x a 13
plt.yticks(fontsize=13)  # Imposta la dimensione dei numeri sull'asse delle y a 13

# Aggiungi una legenda
plt.legend(fontsize=12, loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=2, fancybox=True, shadow=True)

plt.subplots_adjust(left=0.12, bottom=0.15, right=0.996, top=0.9)

# Mostra il grafico
plt.show()