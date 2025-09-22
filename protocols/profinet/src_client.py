from protocol import *
import dcp
from rpc import*
import util

import socket
import argparse
if __name__ == "__main__":
    # Creazione del socket RAW
    parser = argparse.ArgumentParser()
    parser.add_argument("interfaccia", type=str, help="interfaccia")
    args = parser.parse_args() 
    client_socket = util.ethernet_socket(args.interfaccia,3)
    src = "02:42:ac:11:00:02"  #finto indirizzo mac
    print("Client partito...")
    dcp.send_request(client_socket,src,PNDCPBlock.ALL, bytes("Richiesta Dispostivo",'utf-8'))
    #dcp.send_discover(client_socket,src)
    response = dcp.read_response(client_socket,src)
    print(response)
    for mac, data in response.items():
        print(f"MAC: {mac2s(mac)}, Name: {data.get('name', 'Nessun nome')}, Ip: {data.get('ip','Nessun ip')}, Subnet: {data.get('subnet','Nessun Subnet')}, Gateway: {data.get('gateway','Nessun gateway')}, Id: {data.get('devId', 'Nessun Id')}")
    blocks = {
        PNDCPBlock.NAME_OF_STATION: data.get('name'),  # nome della stazione in bytes
        PNDCPBlock.IP_ADDRESS: data.get('ip') + data.get('subnet') + data.get('gateway'),  # IP, netmask, gateway
        PNDCPBlock.DEVICE_ID: data.get('devId') # ID del dispositivo
    }

    resp = dcp.DCPDeviceDescription(s2mac(src),blocks)
    print("blok:" ," ",resp.name, " " , resp.mac, " " , resp.ip ," " , resp.netmask, " ", resp.gateway, " ", resp.devLow, " ", resp.devHigh, " ", resp.vendorLow, " " , resp.vendorHigh) 
    con = RPCCon(resp)
    while True:
        scelta = int(input("Menu: \n 1.Ping al server\n 2.Leggi valore\n 3.Scrivi valore\n 4.Esci\n"))
        if scelta == 1:
            print("Ping...")
            message  = con.connect(s2mac(src))
            print(message.payload.decode())
        elif scelta == 2: 
            response = int.from_bytes(con.read(api=int("11"), slot=int("01"), subslot=int("001"), idx=int("111", 16)).payload,byteorder="big")
            print(response)
        elif scelta == 3:
            num = int(input("Valore da scrivere: "))
            print(con.write(api=int("11"), slot=int("01"), subslot=int("001"), idx=int("111", 16),data=num.to_bytes(4,byteorder="big")).payload.decode())
        elif scelta == 4:
            print("Chiusura client...")
            client_socket.close()
            break
        else:
            print("Scelta non valida!!")
    




