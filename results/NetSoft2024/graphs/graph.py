#!/usr/bin/python3
import numpy as np
import sys
import matplotlib.pyplot as plt
import math
import random

# Inizializza le liste per i dati x e y
x = []
y = []
data = []

# Specifica il percorso del file di testo
file_path = "./results/results_10*10000_chiper_write.txt"

# Leggi i dati dal file, prendendo solo una riga ogni 4
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()  # Rimuovi spazi bianchi e caratteri di nuova riga
        if line: 
            y.append(float(line))

#round all y values to 9 decimal places
factor = 10.0 ** 9
for i in range(len(y)):
    y[i] = math.trunc(y[i] * factor) / factor
    y[i] = y[i] * 1000

Q3, Q1 = np.percentile(y, [75, 25])
IQR = Q3 - Q1

upper_bound = Q3 + 1.5 * IQR
lower_bound = Q1 - 1.5 * IQR

for el in y:
    if el < upper_bound and el > lower_bound:
        data.append(el)

data = data[0:10000]
x = range(0, 10000)


# Calcola la media
mean_no_metrics = np.mean(data)
mean_no_metrics = math.trunc(mean_no_metrics * factor) / factor

# Calcola la deviazione standard
std_dev = np.std(data)
std_dev = math.trunc(std_dev * factor) / factor

# Calcola il massimo e il minimo
max_value = max(data)
max_value = math.trunc(max_value * factor) / factor
min_value = min(data)
min_value = math.trunc(min_value * factor) / factor

# Calcola la mediana
median = np.median(data)
median = math.trunc(median * factor) / factor

# Calcola il range (differenza tra il massimo e il minimo)
data_range = max_value - min_value
data_range = math.trunc(data_range * factor) / factor

# Calcola la varianza
variance = math.trunc(np.var(data) * factor) / factor

# Stampa i risultati
print("Media no metriche:", mean_no_metrics)
print("Deviazione Standard:", std_dev)
print("Varianza:", variance)
print("Massimo:", max_value)
print("Minimo:", min_value)
print("Range:", data_range)
print("Mediana:", median)

# Crea il grafico a punti
plt.scatter(x, data, s=1, color='tab:blue')
plt.xlabel('Modbus Register Write Number')
plt.ylabel('Modbus Register Write Time (ms)')
# Valori sull'asse y tra 0 e 2
plt.ylim(0, 4)

plt.axhline(mean_no_metrics, color='r', linestyle=(0, (5, 1)))

# Modifica la dimensione dei numeri sull'asse delle x e delle y
plt.xticks(fontsize=12)  # Imposta la dimensione dei numeri sull'asse delle x a 12
plt.yticks(fontsize=12)  # Imposta la dimensione dei numeri sull'asse delle y a 12

# Mostra il grafico
plt.show()