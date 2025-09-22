# Profinet
Abbiamo sviluppato i nostri client e server implemmentando il protocollo profinet.

# Indice

- [src_client.py](#src_client.py)
- [src_server.py](#src_server.py)
- [librerie utili](#librerie_utili)
- [Esecuzione](#Esecuzione)

# src_client.py

Contiene il main del client, permette di comunicare al server e importando i file dcp.py e rpc.py permette di richiamare i metodi implementati in quest ultimi,per inviare e ricevere pacchetti. Inizialmente il client tramite il protocollo dcp, per mezzo di un ethernet socket, riceverà le informazioni (MAC,Name,IP,ID,Subnet;Gateway) inerenti un dispositivo collegato in rete e simulato dal nostro server. Successivamnete tramite protocollo rpc che utilizza una socket udp potrà comunicare con tale dispositivo potendo leggere un valore o scriverne uno.

# src_server.py

Crea il server. Inizialmente tramite protocollo e socket ethernet ricevere la richiesta del client e risponde con le informazioni (MAC,Name,IP,ID,Subnet;Gateway) simulando un dispositivo in rete. Successivamente tramite protocollo rpc e socket udp accetta e soddisfa le richieste del client. La socket ethernet è collegata all'interfaccia di rete lo di loopback mentre la socket udp è in asoclto sulla porta 8080.

# librerie_utili
## rcp.py dcp.py 
In questi due file sono presenti le funzioni per comunicare tramite proocollo rpc e dcp
## protocol.py 
Questo file specifica come sono composti i pacchetti per poter comunicare con rpc e dcp
## util.py
Questo file contiene una raccolta di funzioni utili alla creazione del codice, come per esempio funzioni per convertire l'indirizzo mac in stirnga e viceversa oppure per la creazione delle socket.

# Esecuzione
Per poter eseguire il server basterà scrivere su terminale il seguente comando "sudo python3 src_server.py lo" mentre per il client "sudo python3 src_client.py lo". ⚠️ATTENZIONE⚠️ il codice è eseguibile solo su macchine Linux in quanto l'ethernet socket utilizzata non è compatibile con altri sistemi operativi.
