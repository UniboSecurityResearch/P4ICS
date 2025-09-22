from scapy.all import Ether, IP, TCP, Raw, sendp
from scapy.contrib.modbus import ModbusADURequest

# sendp(Ether()/IP()/TCP(sport=1234,dport=502)/ModbusADURequest(transId=0x0001,protoId=0,len=19,unitId=1)/Raw(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"+b"\xff\xff"),iface="enp0s31f6",count=1000, inter=1)
sendp(Ether()/IP(dst="192.168.100.101", proto=6)/TCP(sport=1234,dport=502)/ModbusADURequest(transId=0x0001,protoId=0,len=17,unitId=1)/Raw(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"),iface="enp0s31f6",count=1000, inter=0.03)