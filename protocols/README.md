# Industrial protocol implementations

Clients and servers of industrial protocols, from which the testbed images in
[`../Dockerfile`](../Dockerfile) are built. The Modbus and MQTT clients and
servers live in [`../testbed`](../testbed) instead (pymodbus, paho-mqtt,
Mosquitto).

| Folder | Protocol | Transport | Language | Image | Testbed devices | Protected by P4ICS |
|---|---|---|---|---|---|---|
| [`dnp3/`](dnp3) | DNP3 ([stepfunc/dnp3](https://github.com/stepfunc/dnp3)) | TCP 20000 (TLS 20001) | Rust | `loriringhio97/dnp3` | `dnp3client`, `dnp3server` | yes (TCP 20000) |
| [`Ethernet-IP/`](Ethernet-IP) | EtherNet/IP, CIP ([cpppo](https://github.com/pjkundert/cpppo)) | TCP 44818 (TLS 2221) | Python | `loriringhio97/enip` | `enipclient`, `enipserver` | yes (TCP 44818) |
| [`bacnet/`](bacnet) | BACnet objects ([bacnet-stack](https://github.com/bacnet-stack/bacnet-stack)) with text commands | UDP 47808 | C | — | — | no: UDP |
| [`libiec61580/`](libiec61580) | IEC 61850 MMS ([libiec61850](https://libiec61850.com/)) | TCP 8104 | C | — | — | no: port not parsed |
| [`profinet/`](profinet) | Profinet DCP + RPC | Ethernet 0x8892, UDP 8080 | Python | — | — | no: not TCP |

"Protected" refers to the switch program of `testbed/`, which parses TCP
ports 502, 1883, 20000 and 44818 ([ARCHITECTURE §2](../docs/ARCHITECTURE.md#2-parser-which-packets-are-industrial)).
The other protocols cross the switches in clear. Supporting one takes the
steps in [DEVELOPMENT.md](../docs/DEVELOPMENT.md#adding-an-industrial-protocol).

## DNP3

Four crates: `server_tcp`, `client_tcp`, `server_tls`, `client_tls`.

* `server_tcp`: outstation on `0.0.0.0:20000` (link address 102, master 1)
  with one analog input.
* `client_tcp`: master doing Class-0 reads. `DNP3_ENDPOINT` (host:port),
  `DNP3_READS` (default 100 000), `DNP3_TIMES_FILE` (one time per line in
  microseconds, default `tempi_richieste.txt`).

```bash
cargo build --release --manifest-path server_tcp/Cargo.toml
cargo build --release --manifest-path client_tcp/Cargo.toml
```

The image (`Dockerfile/dnp3.Dockerfile`) contains the two TCP programs as
`dnp3_server` and `dnp3_client`. The TLS crates use the address
192.168.100.102 of the physical testbed and certificates that are not in the
repository.

## EtherNet/IP

* `server.py`: cpppo server with the INT tag `Sensor`, on `ENIP_ADDRESS`
  (host:port).
* `client.py`: reads `Sensor` `ENIP_READS` times (default 100 000) from
  `ENIP_HOST`, writing one time per line in seconds to `ENIP_TIMES_FILE`
  (default `times.txt`).

```bash
pip install cpppo==5.2.5
ENIP_ADDRESS=0.0.0.0:44818 python server.py
ENIP_HOST=127.0.0.1 ENIP_READS=1000 python client.py
```

The image (`Dockerfile/enip.Dockerfile`) copies the folder to `/enip`.
`server_tls.py` and `client_tls.py` put a TLS proxy (port 2221) in front of
the same server. They use the address 192.168.100.102 and need `cert.pem`
and `key.pem`, which are not in the repository.

## BACnet

A server holding BACnet objects of bacnet-stack (analog input 1, a simulated
temperature, and analog outputs 1–2), and an interactive client. They talk
through text commands on UDP 47808 (`PING`, `READ <device> analog-input <n>`,
`WRITE <device> analog-output <n> <value>`), not BACnet/IP APDUs. To build them, copy
`server-basic/` and `server-client/` into `apps/` of a bacnet-stack checkout
and run `make` there (see `bacnet/README.md`). The client addresses
127.0.0.1.

## IEC 61850

An MMS server (`server/`, model `simpleIO` generated from
`simpleIO_direct_control.cid`; it updates `GGIO1.AnIn1` every second and
accepts control of `SPCSO1`–`4`) and an interactive client (`client/`:
browse the model, read `GGIO1.AnIn1`, operate `SPCSO1`). Both link the
prebuilt static library `libiec61850.a` (Linux x86-64). The libiec61850
headers are not included: compile against a libiec61850 source tree. Usage:
`./server [port]` (default 8104), `./client [host] [port]`.

## Profinet

A DCP Identify exchange over raw Ethernet (EtherType 0x8892), then
connect/read/write over UDP, in Python with the standard library only. It
runs on one interface, as root:

```bash
sudo python3 src_server.py lo
sudo python3 src_client.py lo
```
