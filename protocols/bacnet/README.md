# BACnet
Abbiamo sviluppato i nostri client e server implemmentando il protocollo BACnet.


## ⚠️⚠️⚠️Scaricare lo Stack BACnet da GitHub⚠️⚠️⚠️

Per clonare lo stack BACnet dal repository ufficiale GitHub, esegui questo comando nel terminale:

```bash
git clone https://github.com/bacnet-stack/bacnet-stack.git
```
Sostituire le cartelle server-basic e server client presenti nello stack scaricato con quelle presenti in questa repo.

# Indice

- [src_client.c](#src_client.c)
- [server_es.c](#server_es.c)
- [makefile](#makeFile)
- [Esecuzione](#Esecuzione)

# src_client.c

Contiene il main del client, permette di connettersi al server, permette di inviare le varie richieste al server come, eseguire un ping, farsi ritornare un valore di un dispositivo o impostare una temperatura ad un dispositivo.

# server_es.c

Crea il server, lo mette in ascolto sulla porta 47808 (di default), accetta tutte le richieste che provengono dai client e le soddisfa.

# makeFile


Utilizzato per compilare sia i file nella cartella server-basic che in server-client, presente in entrambe, crea gli eseguibili dei file.

# Esecuzione
Dopo aver sostituito le cartelle specificate sopra, copia questo comando nella cartella generale del progetto.

```bash
make
```
Ti permette di compilare tutti i file presenti nello stack, compresi quelli aggiunti manualmente e crea gli eseguibili, tramite il file 'makeFile'.

Dopo aver creato gli eseguibili, in due terminali distinti eseguire:

Per il server
```bash
cd apps/server-basic
```

Per il client
```bash
cd apps/server-client
```
Dentro le rispettive cartelle ora possiamo far partire il client e il server tramite gli eseguibili creati precedentemente:

Per il server (argomenti opzionali)
```bash
./server [device-id] [device-name]
```
Per il client (argomenti obbligatori)
```bash
./client [device-id] [object-type] [object-instance]
```

