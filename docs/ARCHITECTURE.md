# How P4ICS works

P4ICS moves the protection of industrial traffic from the endpoints to the
network. Two P4 switches sit at the edges of an untrusted segment. The first
encrypts and authenticates the payload of every industrial message, the
second verifies it and restores the original packet. PLCs, HMIs and servers
are unchanged and keep speaking plain Modbus, DNP3, EtherNet/IP or MQTT.

```
  clients                                                             servers
  195.11.14.0/24                                                 200.1.1.0/24
  Modbus, MQTT,  ── port 1 [ s1 ] port 2 ══ protected ══ port 2 [ s2 ] port 1 ── Modbus, MQTT,
  DNP3, ENIP       decipher ←       → cipher        cipher ←       → decipher    DNP3, ENIP
```

Each switch decides what to do from the port the packet leaves on: towards the
protected segment it runs `cipher`, towards its own hosts it runs `decipher`.
Requests and responses take the same path in opposite directions, so every
message is protected on the s1–s2 link and in clear at both ends.

This document follows a packet through the switch program
([`testbed/s1/industrial_aes.p4`](../testbed/s1/industrial_aes.p4) and its
extern library [`testbed/s1/extern_lib/`](../testbed/s1/extern_lib)). The
bytes on the wire are specified in [`WIRE_FORMAT.md`](WIRE_FORMAT.md).

## 1. The switch target

The program is P4_16 for the v1model architecture, run by the bmv2
`simple_switch`. Encryption and authentication are not expressible in P4 on
a software switch, so they are two **extern functions** written in C++,
compiled into `definition.so` and loaded with
`simple_switch ... -- --load-modules=extern_lib/definition.so`:

| File | Content |
|---|---|
| `extern_lib/declaration.p4` | P4 signatures of `p4ics_cipher` and `p4ics_decipher` |
| `extern_lib/definition.cpp` | their bmv2 implementation: payload gather/scatter, key derivation, IV, CBC, MAC |
| `extern_lib/p4ics_crypto.h`, `p4ics_aes_tables.h` | AES (Nk = 4..8), SHA-256, HMAC, HKDF |
| `extern_lib/Makefile` | builds `definition.so` (`make`, at switch start-up) |

s1 and s2 run the same program. `testbed/s1` is the source;
`testbed/sync_switches.sh` copies it to `testbed/s2` (only `commands.txt`
differs).

## 2. Parser: which packets are industrial

```
ethernet → ipv4 ─(IHL 13)→ ipv4_options ─→ tcp ─→ tcp_options ─→ protocol header ─→ slices[] + tail
                └(IHL 5)──────────────────┘
```

* **IPv4.** IHL 5 is a plaintext packet, IHL 13 a protected one (the 32
  bytes of P4ICS fields follow the base header). Any other IHL is forwarded
  untouched.
* **TCP.** Options of any length are skipped. Segments without payload
  (handshakes, pure ACKs) stop here.
* **Protocol.** The destination port, or else the source port (so that
  responses match too), selects the protocol header:

  | Protocol | TCP port | Header kept in clear | Header |
  |---|---|---|---|
  | Modbus/TCP | 502 | MBAP | 7 B |
  | MQTT | 1883 | fixed header | 2 B |
  | EtherNet/IP (CIP) | 44818 | encapsulation header | 24 B |
  | DNP3 | 20000 | link-layer header | 10 B |

  A segment shorter than its protocol header plus one byte has nothing to
  protect and is forwarded as is.
* **Payload.** Everything after the protocol header, up to the end of the
  IPv4 packet, is the protected data (L bytes). p4c limits a field to 2048
  bits, so a parser loop extracts it into a header stack of 256-byte slices
  (`P4ICS_MAX_SLICES = 255`) plus a `varbit` tail for the last bytes: any
  IPv4 packet fits.

Other traffic (ARP, UDP, other TCP ports) is routed but never protected.
Other ICS protocols, such as BACnet/IP (UDP), Profinet or IEC 61850 MMS (TCP 102),
are not recognised.

## 3. Ingress: tables and actions

```
ipv4_lpm ──→ industrial payload? ──→ p4ics_local ──→ p4ics_keys ──→ ics_sec ──→ cipher | decipher | no_cipher | request_tunnel
```

| Table | Key | Actions | Purpose |
|---|---|---|---|
| `ipv4_lpm` | IPv4 destination (LPM) | `ipv4_forward(mac, port)`, `drop` | routing: next-hop MAC and egress port |
| `p4ics_local` | — (default action) | `set_local_sa(spi, tx_phase, epoch)` | this switch as a sender: id, key phase, counter base |
| `p4ics_keys` | key phase (bit 31 of the SPI, or `tx_phase` to send) | `set_key(key)` | one 256-bit key per phase |
| `ics_sec` | egress port, IPv4 source, IPv4 destination (ternary) | `cipher`, `decipher`, `no_cipher`, `request_tunnel` | what to do with the packet |

`ics_sec` is where tunnels are activated. In the testbed it holds one
wildcard entry per port (`decipher` on port 1, `cipher` on port 2). More
specific entries, for example per endpoint pair, take precedence (lower
`simple_switch_CLI` priority value).

**`cipher`** (plaintext → protected):

1. counts the packet (`p4ics_tx_count`) and builds the SPI (key phase,
   sender id) and the counter (`epoch` + packets sent);
2. calls `p4ics_cipher`: AES-CBC over the payload, then an HMAC tag over the
   ciphertext and the packet context (encrypt-then-MAC, see
   [WIRE_FORMAT §4](WIRE_FORMAT.md#4-per-packet-crypto-encrypt-then-mac));
3. adds the 32 bytes of P4ICS fields (IHL 5 → 13) and fixes the lengths.

It fails closed: a packet that cannot be protected (no key, no SPI, payload
too large) is dropped, never forwarded in clear. An already protected packet
is forwarded as is.

**`decipher`** (protected → plaintext):

1. picks the key of the packet's phase;
2. calls `p4ics_decipher`, which checks the tag **before** decrypting;
3. checks the counter against the sender's 64-packet anti-replay window
   (`p4ics_rx_last`, `p4ics_rx_window`, as IPsec ESP), updated only for
   authenticated packets;
4. removes the P4ICS fields and restores the original length.

Anything that fails (no key, bad tag, inconsistent lengths, replay, or a
plaintext packet arriving where protection is expected) is dropped.

**`request_tunnel`** drops the packet and sends a `p4ics_tunnel_request_t`
digest to a P4Runtime controller, which can then install the entries for
that endpoint pair (on-demand tunnels, [controller](../controller/README.md)).

`p4ics_events` counts what happened (`counter_read MyIngress.p4ics_events <i>`):

| i | Event |
|---|---|
| 0 | protected |
| 1 | unprotected (decrypted) |
| 2 | rejected: tag, lengths, not protected, no key |
| 3 | rejected: replay |
| 4 | dropped, waiting for an on-demand tunnel |

## 4. Egress and checksums

The egress records, for every packet that went through `cipher` or
`decipher`, the processing time (egress − ingress timestamp) and the queue
delay in two 100 000-entry registers, `packet_processing_time_array` and
`packet_dequeuing_timedelta_array`. `testbed/s1/retrieve_info.sh` dumps them
to `/shared` (see [TESTBED.md](TESTBED.md#measurements)).

The IPv4 checksum is recomputed over the whole header, P4ICS fields
included. The TCP checksum is never touched: on a protected packet it is the
checksum of the original segment, which is valid again once the packet is
restored.

## 5. Control plane

The switch holds no configuration of its own. Two interchangeable control
planes fill the tables:

* **simple_switch_CLI** (default, `testbed/`). `commands.txt` installs routes,
  the sender id and the `ics_sec` entries. `p4ics_setup.sh` generates a key for
  every lab run, installs it and rotates it. See
  [TESTBED.md](TESTBED.md#keys-and-key-rotation).
* **P4Runtime controller** (optional, `controller/`). It uses `simple_switch_grpc`
  with mutual TLS, installs the same `commands.txt`, and rotates the keys
  itself. It can also activate tunnels on demand, and agree on keys with a
  second controller. See [controller/README.md](../controller/README.md).

The configuration lives in tables because bmv2's P4Runtime server cannot
write registers.

## 6. Security properties and limits

What an attacker on the s1–s2 link cannot do:

* read the industrial data after the protocol header (AES-CBC, 128 to 256-bit
  keys);
* change it, move it to another flow or position, or forge the protocol
  header, the addresses, ports or TCP sequence number without the packet
  being dropped (HMAC-SHA256-128);
* replay a packet: every sender's counter only grows, and each receiver
  accepts it once (64-packet window);
* get a packet through in clear where protection is configured: the switches
  fail closed.

What P4ICS does not cover:

* the protocol header itself is authenticated but not encrypted (for example,
  the Modbus transaction id, length and unit id stay visible);
* the TCP/IP headers, the traffic pattern and the packet sizes (padding hides
  sizes only up to the next 16-byte boundary);
* segments that do not start with a protocol header (a message split across
  TCP segments): their first header-length bytes stay in clear, though still
  authenticated;
* non-P4ICS hops: a router may strip the P4ICS fields, so the protected
  segment must be made of P4ICS-aware switches;
* keys are shared by all the switches of a deployment, one per key phase.

A protected packet is up to 48 bytes larger than the original: near-MTU
segments need a larger MTU on the protected segment or a lower TCP MSS.
