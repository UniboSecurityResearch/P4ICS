from collections import namedtuple


from util import *


# ----------------------------------------------------------------------------------------------
#
#     DCP
#

EthernetHeader = make_packet("EthernetHeader", (
        ("dst",  ("6s", mac2s)),
        ("src",  ("6s", mac2s)),
        ("type", ("H", "0x%04X"))
))

EthernetVLANHeader = make_packet("EthernetHeader", (
        ("dst",  ("6s", mac2s)),
        ("src",  ("6s", mac2s)),
        ("tpid", ("H", "0x%04X")),
        ("tci",  ("H", "0x%04X")),
        ("type", ("H", "0x%04X"))
))

PNDCPHeader = make_packet("PNDCPHeader", (
    ("frame_id",     ("H", "0x%04X")),
    ("service_id",   "B"),
    ("service_type", "B"),
    ("xid",          ("I", "0x%08X")),
    ("resp",         "H"),
    ("length",       "H")
), statics={
    "ETHER_TYPE": 0x8892,
    "GET": 3,
    "SET": 4,
    "IDENTIFY": 5,
    "REQUEST": 0,
    "RESPONSE": 1
})

class IPConfiguration(namedtuple("IPConfiguration", ["address", "netmask", "gateway"])):
    def __str__(self):
        return ("IP configuration\n"
                "Address: %s\n"
                "Netmask: %s\n"
                "Gateway: %s\n") % (self.address, self.netmask, self.gateway)

class PNDCPBlockRequest(make_packet("PNDCPBlockRequest", (
    ("option",    "B"),
    ("suboption", "B"),
    ("length",    "H")
), payload_size_field="length")):
    def parse_ip(self):
        return IPConfiguration(s2ip(self.payload[0:4]), s2ip(self.payload[4:8]), s2ip(self.payload[8:12]))

class PNDCPBlock(make_packet("PNDCPBlockRequest", (
    ("option",    "B"),
    ("suboption", "B"),
    ("length",    "H"),
    ("status",    "H"),
), payload_size_field="length", payload_offset=-2)):

    IP_ADDRESS = (1, 2)
    NAME_OF_STATION = (2, 2)
    DEVICE_ID = (2, 3)
    ALL = (0xFF, 0xFF)
    
    def parse_ip(self):
        return IPConfiguration(s2ip(self.payload[0:4]), s2ip(self.payload[4:8]), s2ip(self.payload[8:12]))




# ----------------------------------------------------------------------------------------------
#
#     RPC
#

_UUID = [0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D]

PNRPCHeader = make_packet("PNRPCHeader", (
    ("version",           "B"), #versione del protocollo
    ("packet_type",       "B"), #tipo di pacchetto
    ("flags1",            "B"), #flag di controllo
    ("flags2",            "B"), #flag di controllo
    ("drep",              "3s"), #rappresentazione dei dati
    ("serial_high",       "B"), #parte alta del numero seriale
    ("object_uuid",       "16s"), #uuid dell'oggetto
    ("interface_uuid",    "16s"), #uuid dell'interfaccia
    ("activity_uuid",     "16s"), #uuid dell'attività
    ("server_boot_time",  "I"), #tempo di avvio del server
    ("interface_version", "I"), #versione dell'interfaccia
    ("sequence_number",   "I"), #numero di sequenza del pacchetto
    ("operation_number",  "H"), #numero dell'operazione
    ("interface_hint",    "H"), #suggerimento sull'interfaccia
    ("activity_hint",     "H"), #suggerimento sull'attività
    ("length_of_body",    "H"), #lunghezza del corpo del messaggio
    ("fragment_number",   "H"), #numero di frammento
    ("authentication_protocol", "B"), #tipo di autenticazione utilizzato
    ("serial_low", "B") #parte bassa del numero seriale
), statics={
    "REQUEST": 0x00, #richiesta
    "PING": 0x01, #controllo connessione
    "RESPONSE": 0x02, #risposta
    "FAULT": 0x03, #errore
    "WORKING": 0x04, #indica attività
    "PONG": 0x05, #risposta ad un ping
    "REJECT": 0x06, #rifiuto richiesta
    "ACK": 0x07, #conferma di ricezione
    "CANCEL": 0x08, #cancellazione di un operazione
    "FRAG_ACK": 0x09, #conferma di ricezione di un frammento
    "CANCEL_ACK": 0xA, #conferma di cancellazione
    #operazioni profinet rpc
    "CONNECT": 0x00, #connessione a un dispositivo
    "RELEASE": 0x01, #rilascio connessione
    "READ": 0x02, #lettura dati da un dispositivo
    "WRITE": 0x03, #scrittura dati su un dispositivo
    "CONTROL": 0x04, #controllo del dispositivo
    "IMPLICIT_READ": 0x05, #lettura implicita
    #uuid interface: servono a identificare le entità del sistema profinet
    "IFACE_UUID_DEVICE": bytes([0xDE, 0xA0, 0x00, 0x01] + _UUID), #dispositivo profinet
    "IFACE_UUID_CONTROLLER": bytes([0xDE, 0xA0, 0x00, 0x02] + _UUID), #controller profinet
    "IFACE_UUID_SUPERVISOR": bytes([0xDE, 0xA0, 0x00, 0x03] + _UUID), #supervisore
    "IFACE_UUID_PARAMSERVER": bytes([0xDE, 0xA0, 0x00, 0x04] + _UUID), #server di parametri
    #prefisso per identificare gli oggetti univocamente
    "OBJECT_UUID_PREFIX": bytes([0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71])
})

#operazioni di lettura dati
PNNRDData = make_packet("PNNRDData", (
        ("args_maximum_status", "I"), #stato massimo degli argomenti (codice di stato/errore)
        ("args_length",         "I"), #lunghezza argomenti
        ("maximum_count",       "I"), #massimo di elementi che possono esssere letti (che il client può ricevre in una risposta)
        ("offset",              "I"), #offset dei dati letti nel buffer (posizione nei dati da cui inizia la lettura)
        ("actual_count",        "I") #numero effettivo di elementi letti (numero effettivo di dati inviati nella risposta)
))

#trasferimento dati tra il controller e dispositivi i/o
PNIODHeader = make_packet("PNIODHeader", (
    ("block_header",    "6s"), #intestazione del blocco
    ("sequence_number", "H"), #numero di sequenza del pacchetto
    ("ar_uuid",         "16s"), #uuid dell'application relation (connesione tra il controller e dispositivo)
    ("api",             "I"), #rappresenta un processo specifico nel dispositivo 
    ("slot",            "H"), #slot nel modulo fisico nel dispositivo profinet
    ("subslot",         "H"), #subslot specifico per la comunicazione IO
    ("padding1",        "H"), #padding per allineare la struttura in memoria
    ("index",           "H"), #indice della variabile o del parametro da leggere/scrivere
    ("length",          "I"), #lunghezza dei dati trasmessi nel pacchetto
    ("target_ar_uuid",  "16s"), #uuid della connessione target
    ("padding2",        "8s") #ulteriore padding per allineare il pcchetto in memoria
))

#intestazione pacchetti profinet
PNBlockHeader = make_packet("PNBlockHeader", (
    ("block_type",         "H"), #identifica il tipo di blocco
    ("block_length",       "H"), #lunghezza blocco escluso l'header
    ("block_version_high", "B"), #versione alta del blocco 
    ("block_version_low",  "B") #versione bassa del blocco
), payload=False, statics={
    "IDOReadRequestHeader": 0x0009, #richiesta di lettura
    "IODReadResponseHeader": 0x8009, #risposta a lettura
    "InM0": 0x0020, #blocco di dati input module 0
    "InM0FilterDataSubModul": 0x0030, #filtro dati su un submodulo inM0
    "InM0FilterDataModul": 0x0031, #diltro dati su un modulo inM0
    "InM0FilterDataDevice": 0x0032 #filtro dei dati per un intero dispositivo inM0
})
#richiesta di connessione profinet
PNARBlockRequest = make_packet("PNARBlockRequest", (
    ("block_header", "6s"), #intestazione del blocco (tipo di PNBlockHeader)
    ("ar_type", "H"), #tipo di application relation (es. I/O-Controller)
    ("ar_uuid", "16s"), #uuid univoco application relation
    ("session_key", "H"), #ciave di sessione per la connessione
    ("cm_initiator_mac_address", "6s"), #mac adderss del dispositivo che inizia la connessione
    ("cm_initiator_object_uuid", "16s"), #uuid dell'oggetto che inizializza la connesisone
    ("ar_properties", "I"), #proprieà dell'ar 
    ("cm_initiator_activity_timeout_factor", "H"), #timeout per l'attivita del communication manager
    ("initiator_udp_rtport", "H"), #porta udp per il real-time
    ("station_name_length", "H") #lunghezza del nome della stazione
), vlf="cm_initiator_station_name", vlf_size_field="station_name_length") #

#rilascio della connessione profinet
PNIODReleaseBlock = make_packet("IODReleaseBlock", (
    ("block_header", "6s"), #intestazione del blocco
    ("padding1",     "H"), #campodi riempimento
    ("ar_uuid",      "16s"), #uuid univoco per l'application relation
    ("session_key",  "H"), #chiave di sessione per identificare la connessione
    ("padding2",     "H"), #secondo campo di riempimento
    ("control_command", "H"), #comando di controllo per il rilascio della connessione
    ("control_block_properties", "H") #proprietà del blocco di controllo
))

#blocco informativo di manutenzione profinet (ottenere informazioni di identificazione di un dispositivo)
PNInM0 = make_packet("InM0", (
    ("block_header",             "6s"), #intestazione blocco
    ("vendor_id_high",           "B"), #parte alta dell'id del produttore
    ("vendor_id_low",            "B"), #parte bassa dell'id del produttore
    ("order_id",                 ("20s", decode_bytes)), #numero ordine del dispositivo
    ("im_serial_number",         ("16s", decode_bytes)), #numero di serie del dispositivo
    ("im_hardware_revision",     "H"), #versione hardware del dispositivo
    ("sw_revision_prefix",       "B"), #prefisso della versione software
    ("im_sw_revision_functional_enhancement", "B"), #aggiornamenti funzionali del firmware
    ("im_sw_revision_bug_fix",   "B"), #aggiornamenti per bug fix del firmware
    ("im_sw_revision_internal_change", "B"), #modifiche interne del firmware
    ("im_revision_counter",      "H"), #contatore delle revisioni del dispositivo
    ("im_profile_id",            "H"), #id per profilo profinet supportato
    ("im_profile_specific_type", "H"), #tipo specifico del profilo
    ("im_version",               "H"), #versione del dispositivo
    ("im_supported",             "H") #capacità supportate dal dispositivo
), payload=False, statics={ "IDX": 0xAFF0 })
#funzionalità di idetificazione e manutenzione di profinet
PNInM1 = make_packet("InM1", (
    ("block_header",             "6s"), #intestazione del blocco
    ("im_tag_function",          ("32s", decode_bytes)), #funzione del dispositivo
    ("im_tag_location",          ("22s", decode_bytes)), #posizione fisica del dispositivo
), payload=False, statics={ "IDX": 0xAFF1 })


