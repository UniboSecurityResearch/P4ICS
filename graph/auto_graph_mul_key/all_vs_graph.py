#!/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt
import math

# Inizializza le liste per i dati
r_cipher = []
r_no_cipher = []
w_cipher = []
w_no_cipher = []
r_tls = []
w_tls = []

# Specifica il percorso del file di testo
file_path = "./results/results_10*10000_chiper_read.txt"

# Leggi i dati dal file, prendendo solo una riga ogni 4
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            r_cipher.append(float(line))


file_path = "./results/mul_key/no_cipher/results_10*10000_no_cipher_read.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            r_no_cipher.append(float(line))

file_path = "./results/results_10*10000_chiper_write.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            w_cipher.append(float(line))

file_path = "./results/mul_key/no_cipher/results_10*10000_no_cipher_write.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            w_no_cipher.append(float(line))

file_path = "./results/mul_key/modbus_tls/results_10*10000_tls_read.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            r_tls.append(float(line))

file_path = "./results/mul_key/modbus_tls/results_10*10000_tls_write.txt"
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            w_tls.append(float(line))

#round all values to 9 decimal places
factor = 10.0 ** 9
for i in range(len(r_cipher)):
    r_cipher[i] = math.trunc(r_cipher[i] * factor) / factor
    r_cipher[i] = r_cipher[i] * 1000
    r_tls[i] = math.trunc(r_tls[i] * factor) / factor
    r_tls[i] = r_tls[i] * 1000
    w_cipher[i] = math.trunc(w_cipher[i] * factor) / factor
    w_cipher[i] = w_cipher[i] * 1000
    w_tls[i] = math.trunc(w_tls[i] * factor) / factor
    w_tls[i] = w_tls[i] * 1000
    r_no_cipher[i] = math.trunc(r_no_cipher[i] * factor) / factor
    r_no_cipher[i] = r_no_cipher[i] * 1000
    w_no_cipher[i] = math.trunc(w_no_cipher[i] * factor) / factor
    w_no_cipher[i] = w_no_cipher[i] * 1000

#Rimuovi i valori anomali
# Q3, Q1 = np.percentile(r_cipher, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in r_cipher:
#     if el < upper_bound and el > lower_bound:
#         r_cipher.remove(el)

# Q3, Q1 = np.percentile(r_tls, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in r_tls:
#     if el < upper_bound and el > lower_bound:
#         r_tls.remove(el)

# Q3, Q1 = np.percentile(w_cipher, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in w_cipher:
#     if el < upper_bound and el > lower_bound:
#         w_cipher.remove(el)

# Q3, Q1 = np.percentile(w_tls, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in w_tls:
#     if el < upper_bound and el > lower_bound:
#         w_tls.remove(el)

# Q3, Q1 = np.percentile(r_no_cipher, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in r_no_cipher:
#     if el < upper_bound and el > lower_bound:
#         r_no_cipher.remove(el)

# Q3, Q1 = np.percentile(w_no_cipher, [75, 25])
# IQR = Q3 - Q1
# upper_bound = Q3 + 1.5 * IQR
# lower_bound = Q1 - 1.5 * IQR
# for el in w_no_cipher:
#     if el < upper_bound and el > lower_bound:
#         w_no_cipher.remove(el)

# Calcola la media
mean_r_cipher = np.mean(r_cipher)
mean_r_cipher = math.trunc(mean_r_cipher * factor) / factor
mean_r_tls = np.mean(r_tls)
mean_r_tls = math.trunc(mean_r_tls * factor) / factor
mean_w_cipher = np.mean(w_cipher)
mean_w_cipher = math.trunc(mean_w_cipher * factor) / factor
mean_w_tls = np.mean(w_tls)
mean_w_tls = math.trunc(mean_w_tls * factor) / factor
mean_r_no_cipher = np.mean(r_no_cipher)
mean_r_no_cipher = math.trunc(mean_r_no_cipher * factor) / factor
mean_w_no_cipher = np.mean(w_no_cipher)
mean_w_no_cipher = math.trunc(mean_w_no_cipher * factor) / factor

# Stampa le medie
print("Mean read without encryption: ", mean_r_no_cipher)
print("Mean read with encryption: ", mean_r_cipher)
print("Mean read with TLS: ", mean_r_tls)
print("Mean write without encryption: ", mean_w_no_cipher)
print("Mean write with encryption: ", mean_w_cipher)
print("Mean write with TLS: ", mean_w_tls)

# Calcola la deviazione standard
std_dev_r_chipher = np.std(r_cipher)
std_dev_r_chipher = math.trunc(std_dev_r_chipher * factor) / factor
std_dev_r_tls = np.std(r_tls)
std_dev_r_tls = math.trunc(std_dev_r_tls * factor) / factor
std_dev_w_chipher = np.std(w_cipher)
std_dev_w_chipher = math.trunc(std_dev_w_chipher * factor) / factor
std_dev_w_tls = np.std(w_tls)
std_dev_w_tls = math.trunc(std_dev_w_tls * factor) / factor
std_dev_r_no_chipher = np.std(r_no_cipher)
std_dev_r_no_chipher = math.trunc(std_dev_r_no_chipher * factor) / factor
std_dev_w_no_chipher = np.std(w_no_cipher)
std_dev_w_no_chipher = math.trunc(std_dev_w_no_chipher * factor) / factor

# Crea una lista con le medie di read
no_cipher_means = [mean_r_no_cipher, mean_w_no_cipher]
cipher_means = [mean_r_cipher, mean_w_cipher]
tls_means = [mean_r_tls, mean_w_tls]
x_labels = ['Read', 'Write']
width = 0.3


# Crea una lista di stringhe per i valori sull'asse delle x
x_val = np.arange(len(x_labels))

fig, ax = plt.subplots()
rects1 = ax.bar(x_val - width, no_cipher_means, width, label='Modbus')
rects2 = ax.bar(x_val, cipher_means, width, label='In-Network Encryption')
rects3 = ax.bar(x_val + width, tls_means, width, label='Modbus TLS')

ax.errorbar(x_val - width, no_cipher_means, yerr=[std_dev_r_no_chipher, std_dev_w_no_chipher], fmt='none', ecolor='black', capsize=3)
ax.errorbar(x_val, cipher_means, yerr=[std_dev_r_chipher, std_dev_w_chipher], fmt='none', ecolor='black', capsize=3)
ax.errorbar(x_val + width, tls_means, yerr=[std_dev_r_tls, std_dev_w_tls], fmt='none', ecolor='black', capsize=3)

ax.set_xticks(x_val)
ax.set_xticklabels(x_labels)
ax.legend()
# Metti la legenda su una sola linea
plt.legend(fontsize=15, loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=3, fancybox=True, shadow=True)

# Aggiungi barre di errore
#plt.errorbar(x_val, y_val, yerr=[std_dev_r_chipher, std_dev_r_tls, std_dev_w_chipher, std_dev_w_tls], fmt='none', ecolor='red', capsize=3)

#Aggiungi label sull'asse y
plt.ylabel('Avg Time (ms)', fontsize=20)

# Modifica la dimensione dei numeri sull'asse delle x e delle y
plt.xticks(fontsize=20)  # Imposta la dimensione dei numeri sull'asse delle x a 20
plt.yticks(fontsize=20)  # Imposta la dimensione dei numeri sull'asse delle y a 20

# Mostra il grafico
plt.show()