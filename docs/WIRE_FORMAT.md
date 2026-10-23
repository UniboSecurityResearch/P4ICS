# P4ICS protected wire format (v2)

This is the contract between two P4ICS endpoints, for example the switch that
encrypts and the switch that decrypts. It covers Modbus/TCP, MQTT,
EtherNet/IP and DNP3 over TCP.

| Source | What it defines |
|---|---|
| `testbed/s1/industrial_aes.p4`: parser, actions `cipher`/`decipher`, SA tables | headers, lengths, counter, anti-replay window |
| `testbed/s1/extern_lib/definition.cpp`: `p4ics_cipher`/`p4ics_decipher` | keys, IV, AES-CBC, MAC input |

The executable version of this document is
[`tests/reference/p4ics_ref.py`](../tests/reference/p4ics_ref.py).
`tests/bmv2/interop.py` checks it against the running switch, and
`tests/protocols/` runs the real Modbus, DNP3 and EtherNet/IP stacks through
two switches.

## 1. Which frames are protected

The switch looks a frame up in `ics_sec` when all of the following hold:

* the IPv4 IHL is **5** (plaintext) or **13** (protected). Any other IHL is
  forwarded untouched;
* the protocol is TCP. Options of any length are parsed;
* the destination port, or failing that the source port, is 502 (Modbus),
  1883 (MQTT), 44818 (EtherNet/IP) or 20000 (DNP3);
* the segment holds the protocol header **plus at least one byte**.
  Handshakes, pure ACKs and header-only segments (e.g. MQTT `PINGREQ`) are
  forwarded untouched.

The protocol header is parsed into its own typed header and stays in clear:
`modbus_tcp_t` (MBAP, 7 B), `mqtt_tcp_t` (2 B), `cip_tcp_t` (24 B),
`dnp3_tcp_t` (10 B). It is covered by the tag (§4). Everything after it,
up to the end of the IPv4 packet, is the protected data: L bytes.

`ics_sec` matches the egress port and the IPv4 addresses (all ternary) and
decides what happens to the frame: `cipher`, `decipher`, `no_cipher`, or
`request_tunnel` (§7).

## 2. Layout

```
plaintext : Ethernet | IPv4 (IHL 5)  |                                    | TCP + options | protocol hdr | data (L)
protected : Ethernet | IPv4 (IHL 13) | savedLen | SPI | counter | tag     | TCP + options | protocol hdr | ciphertext (C)
                                        4 B       4 B    8 B      16 B
                                       \______ 32 bytes of "IPv4 options" ______/
```

| Field | Value |
|---|---|
| `L` | bytes after the protocol header |
| `C` | `((L / 16) + 1) * 16`: always 1..16 bytes of zero padding |
| IPv4 `ihl`, `totalLen` | 5 → 13; `totalLen − L + C + 32` |
| `savedLen` | `L`; the receiver takes the plaintext length from here |
| `SPI` | bit 31: key phase (§3); bits 7..0: sender id, 1..255; other bits 0 |
| `counter` | per-sender packet counter, strictly increasing (§5) |
| `tag` | HMAC-SHA256 truncated to 128 bits (§4) |
| TCP header + options, protocol header | unchanged, including the TCP checksum (§6) |

* **Payload size.** The switch parses the data into 256-byte slices (a
  header stack filled by a parser loop) plus a `varbit` tail; p4c limits a
  field to 2048 bits. `P4ICS_MAX_SLICES = 255` covers any IPv4 packet. The
  protected packet is up to 48 bytes larger than the plaintext, so near-MTU
  segments need links with MTU ≥ 1548 or a TCP MSS lowered by 48.
* The option bytes are not valid IPv4 options. The first byte of `savedLen`
  is 0 (`End of Option List`), so a Linux router accepts the packet but
  zeroes the rest. The format only survives P4ICS-aware hops.
* The output has exactly C (or L) bytes; there is no Ethernet trailer.

## 3. Keys

A key is 256 bits, read as 8 × 32-bit big-endian words. The switch holds
two, one per **key phase**, in the table `p4ics_keys` (§7). A sender
protects with its current phase and writes it in bit 31 of the SPI; the
receiver picks the key by that bit. In the testbed the key is generated at
random at every lab start (`testbed/s1/p4ics_setup.sh`); `change_key.sh`
truncates it to a key size. The key material **K** is the big-endian bytes
of the words before the first zero word: Nk = 4..8 words, 128 to 256 bits. Two
independent keys are derived from all of K with HKDF-SHA256 (RFC 5869,
salt `"P4ICS-v2"`):

```
enc_key = HKDF(K, info "P4ICS-v2 enc", 4·Nk bytes)   AES key: Rijndael Nb = 4, Nr = Nk + 6
mac_key = HKDF(K, info "P4ICS-v2 mac", 32 bytes)     HMAC-SHA256 key
```

160 and 224 bits are not FIPS-197 AES: they use the FIPS key schedule
generalised to Nk = 5 and 7.

**Rotation without loss.** Install the new key in the idle phase on every
endpoint, then switch the senders to that phase. Frames still in flight
carry the old phase and keep verifying with the old key, which stays
installed until the next rotation. `testbed/rotate_keys.sh` does this with
simple_switch_CLI, `controller/` with P4Runtime.

## 4. Per-packet crypto: encrypt-then-MAC

All integers are big endian.

```
IV   = AES(enc_key, spi ‖ 0⁴ ‖ counter)
ct   = AES-CBC(enc_key, IV, data ‖ zeros(C − L))
aad  = "P4ICS-v2" ‖ spi ‖ counter ‖ L ‖ IPv4 src ‖ IPv4 dst ‖ TCP src port ‖ TCP dst port
       ‖ TCP seq ‖ protocol header
tag  = HMAC-SHA256(mac_key, aad ‖ ct)[0:16]
```

* The receiver checks the tag on the ciphertext **before** decrypting, so
  nothing is decrypted unless it was authenticated.
* The tag binds the payload to its sender (`spi`, `counter`), its flow
  (addresses, ports), its position in the stream (TCP `seq`) and the
  protocol header left in clear (e.g. the Modbus unit id). TTL, IP id and
  checksums are not covered: routers rewrite them.
* The IV is unique per packet (the `(spi, counter)` pair never repeats under
  a key) and unpredictable without `enc_key`, as CBC requires.

## 5. Counter and anti-replay

* **Sender.** `counter = epoch + n`, where `n` (`p4ics_tx_count`) counts
  the packets protected since the switch started and `epoch` is the time in
  nanoseconds since 2020-01-01 when the SA was last configured
  (`p4ics_local`, §7). No switch sends one packet per nanosecond, so the
  counter never goes back, also across restarts and reconfigurations: the IV
  never repeats and packets are not taken as replays. `epoch` stays below
  2^63 (the CLI limit) until 2312.
* **Receiver.** For each sender (index `spi & 0xff`), `p4ics_rx_last` holds
  the highest counter accepted and `p4ics_rx_window` a 64-bit bitmap of the
  counters below it, as in the IPsec ESP anti-replay window (RFC 4303). A
  frame is accepted only once, and only if its counter is above
  `p4ics_rx_last` or within 64 below it and not seen yet. The window is
  updated only after the tag verified, so forged frames cannot move it.
* **Restarts and keys.** Key rotation needs no counter reset. A *receiver*
  that restarts loses its windows, so the key must change with it, or frames
  captured before the restart would be accepted once more. The testbed does
  this by generating a new key at every lab start; after restarting a single
  switch, run `testbed/rotate_keys.sh`. The controller rotates by itself
  when a switch reconnects.

## 6. Checksums

* **IPv4:** RFC 791, over the whole 52-byte header.
* **TCP:** never updated. On a protected frame it is the checksum of the
  original plaintext segment, which becomes valid again once the frame is
  unprotected.

## 7. Switch configuration and behaviour

The control plane configures a switch through three tables, written by
`simple_switch_CLI` (`commands.txt` and `p4ics_setup.sh`) or by a P4Runtime
controller (`controller/`). bmv2's P4Runtime server cannot read or write
registers, so the registers hold data-plane state only.

| Table | Content |
|---|---|
| `p4ics_local` (default action) | `set_local_sa(spi, tx_phase, epoch)`: sender id, phase to protect with, counter base (§5) |
| `p4ics_keys` (key: phase) | `set_key(key)`: the 256-bit key of each phase (§3) |
| `ics_sec` (egress port, IPv4 src, dst: ternary) | `cipher`, `decipher`, `no_cipher`, `request_tunnel` |

Tunnels are activated *statically*, with one wildcard `ics_sec` entry per
port, or *on demand*: with `request_tunnel` as the default action, a frame
of a flow without an entry is dropped and reported to the controller in a
`p4ics_tunnel_request_t` digest (addresses, ports, egress port, whether it
is protected). The controller installs the entries for that endpoint pair,
and TCP retransmits the dropped segment.

* `cipher` forwards an already-protected frame (IHL 13) as is. It drops a
  frame it cannot protect: parser error, payload larger than the slice
  stack, `totalLen` above 65535, no SPI or no key for the current phase.
* `decipher` drops a frame unless it is protected, there is a key for its
  phase, its lengths are consistent, its tag verifies and its counter is
  fresh.
* `p4ics_events` (`counter_read MyIngress.p4ics_events <i>`):

  | i | event |
  |---|---|
  | 0 | protected |
  | 1 | unprotected |
  | 2 | rejected: tag, lengths, not protected, no key |
  | 3 | rejected: replay |
  | 4 | dropped: waiting for an on-demand tunnel |

## 8. Changes from previous versions

| v1 (paper evaluation, until commit 75d8e5a) | v2 |
|---|---|
| one `varbit<2048>` payload field (≤ 256 B), zero-filled 256-byte output | slice stack + tail: any IPv4 packet, exact length |
| L from protocol length fields; DNP3 frames with more than 16 B of user data came back corrupted | L = bytes after the protocol header, `savedLen` on the way back |
| TCP options assumed to be `NOP, NOP, TS` | any options |
| HMAC over the plaintext's hex text, sequence number only, key from `k1 ‖ k2` (64 bits) | encrypt-then-MAC over the ciphertext and its context, keys from all of K (HKDF) |
| `decipher` did not act on the tag check | drops, checking the tag before decrypting |
| IV derived from the TCP sequence number (repeats across flows) | IV from `(spi, counter)` |
| replay protection: none beyond TCP | per-sender counter + 64-packet window |
| key in a register, SPI in a register, `ics_sec` exact on the port | two key phases and the SA in tables (P4Runtime-writable), `ics_sec` ternary on port and addresses, on-demand tunnels |
| IHL 14, 36 option bytes, checksum over 20 bytes | IHL 13, 32 option bytes, RFC 791 checksum |

## 9. Remaining limitations

* Per-segment processing: when an application message spans several TCP
  segments, the following segments do not start with a protocol header.
  Their first `hdr_len` bytes stay in clear. They are still authenticated,
  as part of the "protocol header" bound by the tag.
* The protocol header is authenticated but not encrypted.
* The window is per sender, not per flow: reordering by more than 64
  packets across all flows of one sender causes drops.
