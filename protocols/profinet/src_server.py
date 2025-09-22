from protocol import *
import dcp, rpc
import util
import socket
import argparse

valore = 0

def connect_response(rpc,client_address):
    nrd = PNNRDData(rpc.payload)
    ar = PNARBlockRequest(nrd.payload)
    print(ar.payload.decode("utf-8"))
    block = PNBlockHeader(0x0101, PNARBlockRequest.fmt_size - 2, 0x01, 0x00)
    payload = PNARBlockRequest(
        bytes(block),
        0x0006, # AR Type
        bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), # AR UUID
        0x1234, # Session key
        s2mac(src),
        PNRPCHeader.OBJECT_UUID_PREFIX,
        0x131, # AR Properties
        100, # Timeout factor
        0x1F90, # udp port?
        2,
        bytes(8), 
        payload=bytes( "Accettata connessione", encoding="utf-8")
    )
    nrd = PNNRDData(1500, len(payload), 1500, 0, len(payload), payload=payload)
    packet = PNRPCHeader(
        0x06, 
        PNRPCHeader.RESPONSE,
        0x20, # Flags1
        0x00, # Flags2
        bytes([0x00, 0x00, 0x00]), # DRep
        0x00, # Serial High
        PNRPCHeader.OBJECT_UUID_PREFIX,
        PNRPCHeader.IFACE_UUID_DEVICE,
        PNRPCHeader.OBJECT_UUID_PREFIX,
        0, # ServerBootTime
        1, # InterfaceVersion
        0, # SequenceNumber
        PNDCPHeader.RESPONSE, #es. PNRPCHeader.CONNECT
        0xFFFF, # InterfaceHint
        0xFFFF, # ActivityHint
        len(nrd),
        0, # FragmentNumber
        0, # AuthenticationProtocol
        0, # SerialLow
        payload=nrd
    )
    server_socket_udp.sendto(bytes(packet), client_address)

def read_response(rpc,client_address):
    global valore
    nrd = PNNRDData(rpc.payload)
    iod = PNIODHeader(nrd.payload)
    block = PNBlockHeader(iod.block_header)
    block = PNBlockHeader(PNBlockHeader.IODReadResponseHeader, 60, 0x01, 0x00)
    iod = PNIODHeader(bytes(block), 0, bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), int("11"), int("01"), int("001"), 0, int("111", 16), 4096, bytes(16), bytes(8), payload=bytes(valore.to_bytes(4, byteorder="big")))
    nrd = PNNRDData(1500, len(iod), 1500, 0, len(iod), payload=iod)
    packet = PNRPCHeader(
        0x04, 
        PNRPCHeader.RESPONSE,
        0x20, # Flags1
        0x00, # Flags2
        bytes([0x00, 0x00, 0x00]), # DRep
        0x00, # Serial High
        PNRPCHeader.OBJECT_UUID_PREFIX,
        PNRPCHeader.IFACE_UUID_DEVICE,
        bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        0, # ServerBootTime
        1, # InterfaceVersion
        0, # SequenceNumber
        PNRPCHeader.READ, #es. PNRPCHeader.CONNECT
        0xFFFF, # InterfaceHint
        0xFFFF, # ActivityHint
        len(nrd),
        0, # FragmentNumber
        0, # AuthenticationProtocol
        0, # SerialLow
        payload=nrd
    )
    server_socket_udp.sendto(bytes(packet),client_address)

def write_response(rpc,client_address):
    global valore
    nrd = PNNRDData(rpc.payload)
    iod = PNIODHeader(nrd.payload)
    block = PNBlockHeader(iod.block_header)
    valore = int.from_bytes(iod.payload,byteorder="big")
    print(valore)
    block = PNBlockHeader(PNBlockHeader.IODReadResponseHeader, 60, 0x01, 0x00)
    iod = PNIODHeader(bytes(block), 0, bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), int("11"), int("01"), int("001"), 0, int("111", 16), 4096, bytes(16), bytes(8), payload=bytes( "Il server ha salvato correttamente il valore scritto", encoding="utf-8"))
    nrd = PNNRDData(1500, len(iod), 1500, 0, len(iod), payload=iod)
    packet = PNRPCHeader(
        0x04, 
        PNRPCHeader.RESPONSE,
        0x20, # Flags1
        0x00, # Flags2
        bytes([0x00, 0x00, 0x00]), # DRep
        0x00, # Serial High
        PNRPCHeader.OBJECT_UUID_PREFIX,
        PNRPCHeader.IFACE_UUID_DEVICE,
        bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        0, # ServerBootTime
        1, # InterfaceVersion
        0, # SequenceNumber
        PNRPCHeader.WRITE, #es. PNRPCHeader.CONNECT
        0xFFFF, # InterfaceHint
        0xFFFF, # ActivityHint
        len(nrd),
        0, # FragmentNumber
        0, # AuthenticationProtocol
        0, # SerialLow
        payload=nrd
    )
    server_socket_udp.sendto(bytes(packet),client_address)

def read_request():
    data, client_address = server_socket_udp.recvfrom(4096)  # 4096 è la dimensione massima del pacchetto
    print(f"Ricevuto {len(data)} byte da {client_address}")
    # Se necessario, decodifica e interpreta i dati
    rpc = PNRPCHeader(data)
    if rpc.operation_number == PNRPCHeader.CONNECT:
        connect_response(rpc,client_address)
    elif rpc.operation_number == PNRPCHeader.READ:
        read_response(rpc,client_address)
    else:
        write_response(rpc,client_address)

if __name__ == "__main__":
    src = "02:42:ac:11:00:02" #finto indirizzo mac
    parser = argparse.ArgumentParser()
    parser.add_argument("interfaccia", type=str, help="interfaccia")
    args = parser.parse_args()   
    #Creazione socket UDP
    server_socket = util.ethernet_socket(args.interfaccia,3)
    
    server_socket_udp = socket.socket(AF_INET, SOCK_DGRAM)
    # Assegna l'indirizzo IP e la porta su cui il server deve ascoltare
    server_address = ("localhost",8080)  
    server_socket_udp.bind(server_address)
    print(f"Server partito in ascolto su {args.interfaccia}")
    server_socket.settimeout(2)
    try:
        with max_timeout(10) as t:
            while True:
                if t.timed_out:
                    break
                try:
                    data = server_socket.recv(1522) #Riceve un pacchetto Ethernet
                except timeout:
                    continue
                eth = EthernetHeader(data)
                if eth.dst == s2mac(src) and mac2s(eth.src) == src:
                    dcp = PNDCPHeader(eth.payload)
                    blocks = dcp.payload
                    block = PNDCPBlock(blocks) #Decodifica un blocco dati DCP
                    blockoption = (block.option, block.suboption) #Estrae option e suboption

                if blockoption == PNDCPBlock.ALL: #Estrae e memorizza il nome
                    print(block.payload.decode('utf-8'))
                    value = "Stazione1"
                    block = PNDCPBlockRequest(PNDCPBlock.NAME_OF_STATION[0], PNDCPBlock.NAME_OF_STATION[1], len(value), payload=bytes( value, encoding='utf-8'))
                    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.RESPONSE, 0x012345, 0, len(block), block)
                    eth   = EthernetVLANHeader(s2mac(src), s2mac(src), 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
                    server_socket.send(bytes(eth))
                    print("inviato Nome stazione\n")
                    
                    
                    value = "DeviceName1"
                    block = PNDCPBlockRequest(PNDCPBlock.DEVICE_ID[0], PNDCPBlock.DEVICE_ID[1], len(value)+100, b"DeviceName1")
                    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.RESPONSE, 0x012345, 0, len(block), block)
                    eth   = EthernetVLANHeader(s2mac(src), s2mac(src), 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
                    server_socket.send(bytes(eth))
                    print("inviato Device Id\n")
                    # Indirizzo IP, Subnet Mask e Gateway
                    ip_address = "127.0.0.1"
                    subnet_mask = "255.255.255.0"
                    gateway = "127.0.0.254"

                    # Converti gli indirizzi IP in byte (4 byte per ogni valore)
                    ip_bytes = socket.inet_aton(ip_address)
                    subnet_bytes = socket.inet_aton(subnet_mask)
                    gateway_bytes = socket.inet_aton(gateway)

                    # Costruisci il payload concatenando i tre indirizzi    
                    payload = ip_bytes + subnet_bytes + gateway_bytes  # Sarà lungo 12 byte
                    block = PNDCPBlockRequest(PNDCPBlock.IP_ADDRESS[0], PNDCPBlock.IP_ADDRESS[1], 50, payload)
                    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.RESPONSE, 0x012345, 0, len(block), block)
                    eth   = EthernetVLANHeader(s2mac(src), s2mac(src), 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
                    server_socket.send(bytes(eth))
                    print("inviato Ip\n")
                    break
    except TimeoutError:
        pass
    while True:
        #Riceve i dati e l'indirizzo del client
        message = read_request() 