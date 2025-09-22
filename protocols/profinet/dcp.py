import argparse, time


from util import *
from protocol import *


params = {
    "name": PNDCPBlock.NAME_OF_STATION,
    "ip": PNDCPBlock.IP_ADDRESS
}


class DCPDeviceDescription:
    def __init__(self, mac, blocks):
        self.mac = mac2s(mac)
        self.name = blocks[PNDCPBlock.NAME_OF_STATION].decode()
        self.ip = s2ip(blocks[PNDCPBlock.IP_ADDRESS][0:4])
        self.netmask = s2ip(blocks[PNDCPBlock.IP_ADDRESS][4:8])
        self.gateway = s2ip(blocks[PNDCPBlock.IP_ADDRESS][8:12])
        self.vendorHigh, self.vendorLow, self.devHigh, self.devLow = unpack(">BBBB", blocks[PNDCPBlock.DEVICE_ID][0:4])


def get_param(s, src, target, param):
    dst = s2mac(target)
    
    if param not in params.keys():
        return
    
    param = params[param]
    
    block = PNDCPBlockRequest(param[0], param[1], 0, bytes())
    dcp   = PNDCPHeader(0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST, 0x012345, 0, 2, block)
    eth   = EthernetVLANHeader(dst, src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))
    
    return list(read_response(s, src, once=True).values())[0][param]

def set_param(s, src, target, param, value):
    dst = s2mac(target)
    
    if param not in params.keys():
        return
    
    param = params[param]
    
    block = PNDCPBlockRequest(param[0], param[1], len(value) + 2, bytes([0x00, 0x00]) + bytes(value, encoding='ascii'))
    dcp   = PNDCPHeader(0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST, 0x012345, 0, len(value) + 6 + (1 if len(value) % 2 == 1 else 0), block)
    eth   = EthernetVLANHeader(dst, src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))
    
    # ignore response
    s.recv(1522)
    
    time.sleep(2)


def send_discover(s, src):
    
    #01:0e:cf:00:00:00
    block = PNDCPBlockRequest(PNDCPBlock.ALL[0], PNDCPBlock.ALL[1], 0, bytes())
    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST, 0x012345, 0, len(block), block)
    eth   = EthernetVLANHeader(s2mac(src), s2mac(src), 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))


def send_request(s, src, t, value):
    
    block = PNDCPBlockRequest(t[0], t[1], len(value)+10, bytes(value))
    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST, 0x012345, 0, len(block), block)
    eth   = EthernetVLANHeader(s2mac(src), s2mac(src), 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))


def read_response(s, my_mac, to=2, once=False, debug=False):
    ret = {} #Dizionario vuota dove verranno memorizzate le risposte
    found = [] #Lista per memorizzare eventuali dispositivi già trovati
    s.settimeout(2) #Timeout ti 2 sec, se non arriva nulla solleva un errore
    parsed = {} #Dizionario che conterrà i dati analizzati
    try:
        with max_timeout(to) as t:
            while True:
                if t.timed_out:
                    break
                try:
                    data = s.recv(1522) #Riceve un pacchetto Ethernet
                except timeout:
                    continue

                #Decodifica il pacchetto per estrarne il contenuto
                eth = EthernetHeader(data)
                #Verifica che l'indirizzo mac sia quello giusto e che utilizzi il protocollo DCP
                if eth.dst != my_mac and eth.src != my_mac and eth.type != PNDCPHeader.ETHER_TYPE: 
                    continue
                #debug and print("MAC address:", mac2s(eth.src))
                #eth.type != PNDCPHeader.ETHER_TYPE
                #Decodifica il payload in una struttura PNDCPHeader
                pro = PNDCPHeader(eth.payload)
                if not (pro.service_type == PNDCPHeader.RESPONSE):
                    continue
                blocks = pro.payload #Estrae il payload contenente il blocco dati
                length = pro.length #Imposta la lunghezza del pacchetto
                
                while length > 6: #itera finchè non ci sono abbastanza dati per formare un blocco
                    block = PNDCPBlock(blocks) #Decodifica un blocco dati DCP
                    blockoption = (block.option, block.suboption) #Estrae option e suboption

                    print(f"Ricevuto blocco: option={block.option}, suboption={block.suboption}, payload={block.payload}") 

                    parsed[blockoption] = block.payload #Memorizza il payload del blocco nel dizionario
                    
                    block_len = block.length #Ottiene la lunghezza del blocco
                    if blockoption == PNDCPBlock.NAME_OF_STATION: #Estrare e memorizza il nome
                        debug and print("Name of Station: %s" % block.payload)
                        parsed["name"] = block.payload
                    elif blockoption == PNDCPBlock.IP_ADDRESS: #Estrare e converte l'indirizzo IP
                        debug and print(str(block.parse_ip()))
                        parsed["ip"] = block.payload[0:4]
                        parsed["subnet"] = block.payload[4:8]     # Subnet Mask
                        parsed["gateway"] = block.payload[8:12]
                    elif blockoption == PNDCPBlock.DEVICE_ID: #Estrae l'ID 
                        parsed["devId"] = block.payload
                    
                    # Padding:
                    if block_len % 2 == 1:
                        block_len += 1
                    
                    # geparsten Block entfernen
                    blocks = blocks[block_len+4:]
                    length -= 4 + block_len

                ret[eth.src] = parsed #aggiunge i dati al dizionario 
                
                if once:
                    break

    except TimeoutError:
        pass

    return ret
