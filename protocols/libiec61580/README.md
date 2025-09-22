# Libiec61850
Abbiamo sviluppato i nostri client e server implemmentando il protocollo iec-61850.

# Indice

- [client.c](#client.c)
- [function_client.c/function_client.h](#function_client.c/function_client.h)
- [server.c](#server.c)
- [function_server.c/function_server.h](#function_server.c/function_server.h)
- [static_model.c](#static_model.c)
- [Esecuzione](#Esecuzione)

# client.c

Contiene il main del client, permette di connettersi al server e importando i file function_client.h permette di richiamare i metodi implementati in quest ultimi, come visualizzare tutti i dispositivi presenti nel model, leggere il valore float 'mag.f' del dispositivo analogico 'GGI01.AnIn1' e ON/OFF del dispositivo digitale 'GGI01.SPCS01'

# function_client.c/function_client.h

## function_client.c

Implementa tutte le funzioni per visualizzare la lista dei dispositivi presenti del model.

## function_client.h

Dichiara tutte le funzioni per visualizzare la lista dei dispositivi presenti nel model e le rende utilizzabili al client tramite un 'include'.

# server.c

Crea il server, lo mette in ascolto sulla porta 8104 (di default il protocollo è in ascolto sulla porta 104, per comodita in fase di sviluppo abbiamo utilizzato la porta 8104), accetta tutte le richieste che provengono dai client e le soddisfa.

# function_server.c/function_server.h

## function_server.c

Implementa la funzione per la gestione ON/OFF dei dispositivi digitali presenti nel model.

## function_server.h 

Dichiara tutte le funzioni per la gestione ON/OFF dei dispositivi digitali presenti nel model e le rende utilizzabili al server tramite un 'include'.

# static_model.c

Implementa il DataModel

# Esecuzione
È presente un MAKEFILE con le istruzioni per poter compilare i file necessari per la creazione degli eseguibili.

Assicurarsi di avere nella cartella del progetto il file libiec61850.a, si tratta della libreria necessaria per la compilazione dei file sorgenti

(⚠️ATTENZIONE: Il file libiec61850.a presente in questo repo git è valido solo per Linux, per altri sistemi operativi dovrà essere aggiunto manualmente). 

Sarà necessario eseguire 'make' da terminale nella cartella /libiec61850 ed eseguire con ./server e ./client i due eseguibili creati.  
