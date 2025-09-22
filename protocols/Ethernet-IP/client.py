import time
from cpppo.server.enip import client

HOST = "192.168.100.102"   # IP del server EtherNet/IP
TAG_NAME = "Sensor"        # Nome del tag da leggere (tipo INT)

with client.connector(host=HOST) as conn:              # Connessione al server CIP (porta 44818 di default)
    with open("times.txt", "w") as f:                  # File di output per i tempi
        for i in range(100000):
            # Prepara l'operazione di lettura del tag (parsing del nome tag in un comando CIP)
            operations = client.parse_operations([TAG_NAME])

            t0 = time.perf_counter()                  # tempo iniziale ad alta risoluzione
            # Esegue la richiesta di lettura (Get Attribute/Read Tag CIP)
            for idx, descr, op, reply, status, value in conn.synchronous(operations=operations):
                # 'value' contiene la risposta (lista con valore del tag, es. [0])
                sensor_value = value
            t1 = time.perf_counter()                  # tempo dopo aver ricevuto la risposta
            elapsed = t1 - t0
            f.write(f"{elapsed:.6f}\n")               # Salva il tempo in secondi (float) su file
