# The Kathara testbed

[`testbed/`](../testbed) is a [Kathara](https://www.kathara.org/) lab that
reproduces the P4ICS deployment: industrial clients and servers on two LANs,
joined by two P4ICS switches that protect everything between them.

## Topology

```
                    LAN A 195.11.14.0/24              LAN B               LAN C 200.1.1.0/24
  modbusclient  .5 ─┐                                                    ┌─ .7   modbusserver
  mqttclient    .6 ─┤                                                    ├─ .8   mqttbroker
  dnp3client    .7 ─┼─ eth0 [ s1 ] eth1 ════ protected ════ eth1 [ s2 ] eth0 ─┼─ .9   dnp3server
  enipclient   .10 ─┘   port 1     port 2               port 2     port 1   └─ .10  enipserver
                                          wireshark: A, B, C
```

| Device | Image | LAN | Address | Runs |
|---|---|---|---|---|
| `s1`, `s2` | `loriringhio97/p4` | A+B, C+B | — | bmv2 `simple_switch` with the P4ICS program |
| `modbusclient` | `loriringhio97/modbus` | A | 195.11.14.5 | Modbus clients (plain and TLS) |
| `modbusserver` | `loriringhio97/modbus` | C | 200.1.1.7 | Modbus servers: `server.py` (502), `server_tls.py` (TLS, 5020) |
| `mqttclient` | `loriringhio97/mqtt-client` | A | 195.11.14.6 | MQTT clients (plain and TLS) |
| `mqttbroker` | `loriringhio97/mqtt-broker` | C | 200.1.1.8 | Mosquitto (1883, TLS 8883) |
| `dnp3client` | `loriringhio97/dnp3` | A | 195.11.14.7 | DNP3 master (`dnp3_client`) |
| `dnp3server` | `loriringhio97/dnp3` | C | 200.1.1.9 | DNP3 outstation (`dnp3_server`, 20000) |
| `enipclient` | `loriringhio97/enip` | A | 195.11.14.10 | EtherNet/IP client (cpppo) |
| `enipserver` | `loriringhio97/enip` | C | 200.1.1.10 | EtherNet/IP server (cpppo, 44818) |
| `wireshark` | `lscr.io/linuxserver/wireshark` | A, B, C | — | packet capture, web UI on http://localhost:3000 |

The hosts use s1 (195.11.14.1) and s2 (200.1.1.1) as gateways with static
ARP entries. The switches route on the destination address
(`commands.txt`). MQTT, DNP3 and EtherNet/IP devices are commented out in
`testbed/lab.conf`: uncomment the ones you need. All images are on Docker
Hub for `linux/amd64` and `linux/arm64`. The ones built from this repository
can also be built locally (see [Images](#images)).

## Running it

```bash
cd testbed
kathara lstart                 # one terminal per device; --noterminals to skip them
...
kathara lclean                 # stop the lab and delete the key of this run
```

At start-up each switch compiles `industrial_aes.p4`, builds the extern
library, starts `simple_switch`, loads `commands.txt` and runs
`p4ics_setup.sh init`, which installs the key of the run. The switches and the
industrial hosts append their name to `shared/startup.temp` when they are ready. The lab directory
`testbed/shared/` is mounted as `/shared` in every device; s1 logs to
`shared/s1.log`.

Then, from the host:

```bash
kathara exec modbusclient -- python3 /modbus_client.py --rw
kathara exec dnp3client -- env DNP3_ENDPOINT=200.1.1.9:20000 DNP3_READS=1000 dnp3_client
kathara exec enipclient -- env ENIP_HOST=200.1.1.10 ENIP_READS=1000 python3 /enip/client.py
```

or the same commands in the device terminals (device files are in `/`).

## Clients

The plain variants use the ports the switches protect (502, 1883, 20000,
44818). The TLS variants use other ports (Modbus 5020, MQTT 8883) and are
the TLS baseline: the switches forward them untouched.

### Modbus (`modbusclient`, server 200.1.1.7)

`/modbus_client.py` (pymodbus 3.6) works on holding register 0 of unit 1:

| Option | Does | Writes |
|---|---|---|
| `--read`, `--write`, `--rw` | read; write 45; read, write, read | — |
| `--connect [--connect-times N]` | times N TCP connections | `/shared/results_conn.txt` |
| `--test-rtt-read MODE`, `--test-rtt-write MODE` | 10 × 10 000 timed reads or writes | `/shared/results_10*10000_cipher_<read\|write>_<MODE>_key.txt`, or `..._no_cipher_<read\|write>.txt` for `no-encryption` |
| `--test-read MODE`, `--test-write MODE` | 100 000 untimed operations, as load for the [measurements](#measurements) | — |

`MODE` (`no-encryption`, `128` … `256`) only names the output file, and must
follow the option directly (`--test-rtt-read 256`). The key size of the
switches is set separately, see [Keys](#keys-and-key-rotation). Times are in
seconds, one per line.

`/tls_client.py` does the same over TLS (port 5020) with one of
`--test-rtt-read`, `--test-rtt-write`, `--test-read`, `--test-write` (no
argument), writing `/shared/results_10*10000_tls_<read|write>.txt`.

### MQTT (`mqttclient`, broker 200.1.1.8)

Uncomment `mqttclient` and `mqttbroker` in `testbed/lab.conf` first.

```bash
python3 /mqtt_client.py [N]        # 100 000 QoS-1 publishes to encyclopedia/temperature, port 1883
python3 /mqtt_client_tls.py [N]    # the same over TLS, port 8883 (client certificate required)
bash /start.sh N                   # N+1 clients in parallel
```

Each client subscribes to `encyclopedia/#` and writes every publish-to-PUBACK
delay, in seconds, to `publish_times.txt` in its working directory.

### DNP3 (`dnp3client`, outstation 200.1.1.9:20000)

```bash
DNP3_ENDPOINT=200.1.1.9:20000 DNP3_READS=1000 DNP3_TIMES_FILE=/shared/dnp3.txt dnp3_client
```

Class-0 reads, one round-trip time per line in **microseconds**
(default file: `tempi_richieste.txt`). The outstation (stepfunc `dnp3`) has one
analog input. Its log is `shared/dnp3server.log`.

### EtherNet/IP (`enipclient`, server 200.1.1.10:44818)

```bash
cd /enip && ENIP_HOST=200.1.1.10 ENIP_READS=1000 ENIP_TIMES_FILE=/shared/enip.txt python client.py
```

CIP reads of the tag `Sensor` (cpppo), one time per line in **seconds**
(default file: `times.txt`). The server log is `shared/enipserver.log`.

The TLS certificates in `testbed/modbusclient`, `modbusserver`, `mqttclient`
and `mqttbroker` are a public pymodbus example pair: test material, not
secrets.

## Keys and key rotation

No key is stored in the repository.

* **Per run.** The first switch that starts writes a random 256-bit key to
  `shared/p4ics_key` (8 decimal words), and both switches install it.
  `kathara lclean` deletes it (`s1.shutdown`, `s2.shutdown`), so the next run
  uses a new key. A switch that restarts loses its anti-replay state: rotate
  the key afterwards.
* **Rotation without loss.** From `testbed/`, while the lab runs:

  ```bash
  ./rotate_keys.sh            # s1 and s2; ./rotate_keys.sh s1 s2 ... for more endpoints
  ```

  Each switch holds one key per key phase. The script installs a new key in
  the idle phase of every switch and only then switches them to it, so frames
  already in flight still verify. The current phase is in
  `shared/p4ics_phase`.
* **Key size.** `./change_key.sh <128|160|192|224|256>` inside a switch
  reloads the lab key truncated to that size; run it on both switches. To start
  a run with a given size, or without protection, write the mode before
  `kathara lstart`:

  ```bash
  echo 128 > shared/p4ics_mode            # 128, 160, 192, 224 or 256
  echo no-encryption > shared/p4ics_mode  # ics_sec emptied: plaintext baseline
  echo tls > shared/p4ics_mode            # same, for the TLS clients and servers
  ```

  Delete `shared/p4ics_mode` to go back to 256 bits.

`s1/p4ics_setup.sh` does all of this through `simple_switch_CLI`:

| Command | Effect |
|---|---|
| `p4ics_setup.sh init` | at start-up: key of the run (or empty `ics_sec` in the baseline modes), then activate |
| `p4ics_setup.sh key [BITS]` | reload the lab key, optionally truncated |
| `p4ics_setup.sh install PHASE FILE` | load the key in FILE into a key phase |
| `p4ics_setup.sh activate PHASE` | protect with that phase from now on |

## Switch state

Inside a switch, `simple_switch_CLI` shows what P4ICS is doing:

```bash
simple_switch_CLI <<< "counter_read MyIngress.p4ics_events 0"   # 0 protected, 1 unprotected,
                                                                # 2 rejected, 3 replay, 4 waiting
simple_switch_CLI <<< "table_dump ics_sec"                      # tunnel entries
simple_switch_CLI <<< "table_dump p4ics_local"                  # sender id, key phase, counter base
```

Each switch has its own sender id: the first argument of `set_local_sa` in
its `commands.txt` (s1: 1, s2: 2).

## Measurements

The switch records, for every protected or unprotected packet, its
processing time and its queue delay
([ARCHITECTURE §4](ARCHITECTURE.md#4-egress-and-checksums)). After a run,
inside a switch:

```bash
./retrieve_info.sh --ppt 256 -w    # processing times of a write test with 256-bit keys
./retrieve_info.sh --deq 256 -r    # queue delays of a read test
```

The mode argument (`no-encryption`, `tls`, `128` … `256`) and `-r`/`-w` only
name the output file, for example
`/shared/results_s1_cipher_write_packet_processing_time_256-bit.txt` (one
value in microseconds per line). The registers hold the first 100 000 packets
since the switch started.

## Optional: P4Runtime controller

`controller/lab/make_lab.sh <dir>` builds a copy of this lab in which s1 and
s2 run `simple_switch_grpc`, configured by the P4ICS controller over mutual
TLS instead of `simple_switch_CLI`. The controller's web GUI is published
on the host at `http://localhost:8080`. See
[controller/README.md](../controller/README.md#kathara-lab).

## Images

| Image | Dockerfile | Content |
|---|---|---|
| `loriringhio97/p4` | — | bmv2 1.15.0 and p4c 1.2.5.11 |
| `loriringhio97/modbus` | `Dockerfile/modbus.Dockerfile` | pymodbus clients and servers of `testbed/modbusclient`, `testbed/modbusserver` |
| `loriringhio97/dnp3` | `Dockerfile/dnp3.Dockerfile` | `dnp3_client`, `dnp3_server` from `protocols/dnp3` |
| `loriringhio97/enip` | `Dockerfile/enip.Dockerfile` | cpppo client and server from `protocols/Ethernet-IP` |
| `loriringhio97/mqtt-client`, `mqtt-broker` | `Dockerfile/mqtt-*.Dockerfile` | MQTT clients, Mosquitto |
| `loriringhio97/p4ics-controller` | `Dockerfile/controller.Dockerfile` | the optional controller and its web GUI (v2.1.0 or later) |

Build an image locally from the repository root, for example
`docker build -f Dockerfile/dnp3.Dockerfile -t loriringhio97/dnp3 .`.
`Dockerfile/publish.sh <tag>` builds the DNP3, EtherNet/IP, Modbus and
controller images for amd64 and arm64 and pushes them to Docker Hub.
