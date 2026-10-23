#!/usr/bin/env python3
"""Executable specification of the P4ICS protected wire format (v2).

This module is the single source of truth used by the tests; the prose
version is docs/WIRE_FORMAT.md. It mirrors the switch implementation in
``testbed/s1/industrial_aes.p4`` (actions ``cipher``/``decipher``) and
``testbed/s1/extern_lib/definition.cpp`` (externs ``p4ics_cipher``/
``p4ics_decipher``), and ``tests/bmv2/interop.py`` checks it against a running
bmv2 switch for Modbus, MQTT, EtherNet/IP and DNP3.

It is pure Python (no third-party dependency) so it also runs inside the
``loriringhio97/p4`` image, and it supports the non-standard 160/224-bit
Rijndael keys that the P4ICS extern accepts.
"""

import hashlib
import hmac
import socket
import struct

ETH_LEN = 14
IPV4_BASE_LEN = 20
IPV4_IHL_PLAIN = 5
IPV4_IHL_PROTECTED = 13
OPT_LEN = 32                    # savedLen (4) + SPI (4) + counter (8) + tag (16)
TAG_LEN = 16                    # HMAC-SHA256 truncated to 128 bits
AES_BLOCK = 16
REPLAY_WINDOW = 64              # counters accepted below the highest one seen
REPLAY_SLOTS = 256              # receiver state is indexed by SPI & 0xff

# Industrial protocols by TCP port (the parser tries the destination port
# first, then the source port) -> bytes of protocol header left in clear.
PROTOCOLS = {502: ("modbus", 7), 1883: ("mqtt", 2), 44818: ("cip", 24), 20000: ("dnp3", 10)}
MODBUS_PORT = 502
MBAP_LEN = 7

SLICE_LEN = 256                 # payload_slice_t
MAX_SLICES = 255                # P4ICS_MAX_SLICES in industrial_aes.p4

# The eBPF host datapath (Modbus only) keeps the ciphertext in 256 bytes.
HOST_MAX_CIPHER = 256
HOST_MAX_PLAIN = HOST_MAX_CIPHER - 1

LABEL = b"P4ICS-v2"             # HKDF salt and first bytes of the MAC input
ENC_INFO = b"P4ICS-v2 enc"
MAC_INFO = b"P4ICS-v2 mac"


class P4icsError(Exception):
    """Raised when a frame cannot be protected/unprotected."""


class P4icsAuthError(P4icsError):
    """Raised when the HMAC tag of a protected frame does not verify."""


class P4icsReplayError(P4icsError):
    """Raised by ReplayWindow for a counter already seen or too old."""


def crypt_len(plain_len):
    """Ciphertext length used by the switch: always adds 1..16 zero bytes."""
    return ((plain_len // AES_BLOCK) + 1) * AES_BLOCK


# --------------------------------------------------------------------------
# AES / Rijndael with Nb = 4 and Nk = 4..8 (same key schedule as the extern)
# --------------------------------------------------------------------------

def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            inv = next(y for y in range(1, 256) if _gmul(x, y) == 1)
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for x, s in enumerate(sbox):
        inv_sbox[s] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()


def aes_expand_key(key):
    """Return (round_keys, nr); round_keys is a list of 4*(nr+1) byte-lists."""
    nk = len(key) // 4
    if len(key) % 4 or not 4 <= nk <= 8:
        raise ValueError("AES key must be 16..32 bytes in 4-byte steps")
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return words, nr


def _add_round_key(state, words, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= words[4 * rnd + c][r]


def aes_encrypt_block(expanded, block):
    words, nr = expanded
    state = [[block[c * 4 + r] for c in range(4)] for r in range(4)]
    _add_round_key(state, words, 0)
    for rnd in range(1, nr + 1):
        state = [[SBOX[b] for b in row] for row in state]
        state = [row[r:] + row[:r] for r, row in enumerate(state)]
        if rnd != nr:
            for c in range(4):
                a = [state[r][c] for r in range(4)]
                state[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
                state[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
                state[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
                state[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        _add_round_key(state, words, rnd)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes_decrypt_block(expanded, block):
    words, nr = expanded
    state = [[block[c * 4 + r] for c in range(4)] for r in range(4)]
    _add_round_key(state, words, nr)
    for rnd in range(nr - 1, -1, -1):
        state = [row[-r:] + row[:-r] if r else row for r, row in enumerate(state)]
        state = [[INV_SBOX[b] for b in row] for row in state]
        _add_round_key(state, words, rnd)
        if rnd:
            for c in range(4):
                a = [state[r][c] for r in range(4)]
                state[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
                state[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
                state[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
                state[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def cbc_encrypt(expanded, iv, data):
    out, prev = bytearray(), iv
    for off in range(0, len(data), AES_BLOCK):
        block = bytes(a ^ b for a, b in zip(data[off:off + AES_BLOCK], prev))
        prev = aes_encrypt_block(expanded, block)
        out += prev
    return bytes(out)


def cbc_decrypt(expanded, iv, data):
    out, prev = bytearray(), iv
    for off in range(0, len(data), AES_BLOCK):
        block = data[off:off + AES_BLOCK]
        out += bytes(a ^ b for a, b in zip(aes_decrypt_block(expanded, block), prev))
        prev = block
    return bytes(out)


# --------------------------------------------------------------------------
# Key material (the 8 x 32-bit `keys` register of the switch)
# --------------------------------------------------------------------------

def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 HKDF with SHA-256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block = b"", b""
    for i in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
    return out[:length]


class P4icsKeys:
    """Key material derived from the 8 register words written by commands.txt.

    The key material K is the big-endian bytes of the words before the first
    zero word (Nk = 4..8 words: 128/160/192/224/256 bits). From K, HKDF-SHA256
    (salt "P4ICS-v2") derives two independent keys:
    * enc_key, Nk words: the AES key (Rijndael with Nb = 4, Nr = Nk + 6);
    * mac_key, 32 bytes: the HMAC-SHA256 key.
    """

    def __init__(self, words):
        words = [int(w) for w in words]
        if len(words) != 8 or any(not 0 <= w <= 0xFFFFFFFF for w in words):
            raise ValueError("expected 8 unsigned 32-bit key words")
        self.words = tuple(words)
        nk = next((i for i, w in enumerate(words) if w == 0), 8)
        if nk < 4:
            raise ValueError("at least the first 4 key words must be non-zero")
        self.nk = nk
        self.nr = nk + 6
        material = b"".join(w.to_bytes(4, "big") for w in words[:nk])
        self.enc_key = hkdf_sha256(material, LABEL, ENC_INFO, 4 * nk)
        self.mac_key = hkdf_sha256(material, LABEL, MAC_INFO, 32)
        self.expanded = aes_expand_key(self.enc_key)

    @property
    def bits(self):
        return self.nk * 32

    def iv(self, spi, counter):
        """IV = AES(enc_key, be32(spi) || 0^4 || be64(counter)): unique per packet."""
        return aes_encrypt_block(self.expanded, struct.pack("!IIQ", spi, 0, counter))

    def tag(self, aad, ciphertext):
        """Encrypt-then-MAC: HMAC-SHA256(mac_key, aad || ciphertext)[0:16]."""
        return hmac.new(self.mac_key, aad + ciphertext, hashlib.sha256).digest()[:TAG_LEN]


# Fixed key used by the tests (the testbed generates a random one per run).
TESTBED_WORDS = (729683222, 682545830, 2885096840, 164581180,
                 102358694, 259174683, 243695780, 96548217)


def testbed_words(bits=256):
    """TESTBED_WORDS truncated to a key size, as change_key.sh does."""
    nk = bits // 32
    if bits % 32 or not 4 <= nk <= 8:
        raise ValueError("bits must be one of 128, 160, 192, 224, 256")
    return TESTBED_WORDS[:nk] + (0,) * (8 - nk)


def parse_commands(path):
    """Extract the key words from a simple_switch_CLI commands.txt file."""
    words = [0] * 8
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 4 and parts[:2] == ["register_write", "keys"]:
                words[int(parts[2])] = int(parts[3], 10)
    return words


# --------------------------------------------------------------------------
# Checksums and frame helpers
# --------------------------------------------------------------------------

def ones_sum(data, start=0):
    """16-bit one's complement sum (not inverted) of `data`, seeded by `start`."""
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    total = start
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def ipv4_checksum(header):
    """RFC 791 checksum of `header` (whose checksum field must be zero)."""
    return (~ones_sum(header)) & 0xFFFF


def tcp_pseudo_sum(src, dst, tcp_len):
    return ones_sum(src + dst + struct.pack("!BBH", 0, 6, tcp_len))


def tcp_checksum(src, dst, segment):
    seg = bytearray(segment)
    seg[16:18] = b"\x00\x00"
    return (~ones_sum(seg, tcp_pseudo_sum(src, dst, len(seg)))) & 0xFFFF


def tcp_checksum_ok(frame):
    p = parse(frame)
    seg = frame[p.l4:p.end]
    return ones_sum(seg, tcp_pseudo_sum(p.src, p.dst, len(seg))) == 0xFFFF


class Parsed:
    """Offsets of the interesting headers of an Ethernet/IPv4/TCP frame."""

    def __init__(self, frame):
        if len(frame) < ETH_LEN + IPV4_BASE_LEN or frame[12:14] != b"\x08\x00":
            raise P4icsError("not an IPv4 frame")
        ip = ETH_LEN
        if frame[ip] >> 4 != 4:
            raise P4icsError("not IPv4")
        self.ihl = frame[ip] & 0x0F
        self.tot_len = struct.unpack_from("!H", frame, ip + 2)[0]
        self.end = ip + self.tot_len
        if frame[ip + 9] != 6 or self.end > len(frame):
            raise P4icsError("not a complete TCP packet")
        self.src = bytes(frame[ip + 12:ip + 16])
        self.dst = bytes(frame[ip + 16:ip + 20])
        self.l4 = ip + 4 * self.ihl
        self.sport, self.dport, self.seq = struct.unpack_from("!HHI", frame, self.l4)
        self.doff = frame[self.l4 + 12] >> 4
        self.l7 = self.l4 + 4 * self.doff
        if self.l7 > self.end:
            raise P4icsError("truncated TCP header")
        self.payload_len = self.end - self.l7
        self.proto, self.hdr_len = (PROTOCOLS.get(self.dport) or PROTOCOLS.get(self.sport)
                                    or (None, 0))
        self.data_off = self.l7 + self.hdr_len
        self.data_len = self.payload_len - self.hdr_len

    @property
    def protectable(self):
        """What the switch hands to ics_sec: an industrial header plus >= 1 byte."""
        return self.proto is not None and self.data_len > 0


def parse(frame):
    return Parsed(frame)


def build_frame(app, *, src="195.11.14.5", dst="200.1.1.7", sport=40000,
                dport=MODBUS_PORT, seq=0x12345678, ack=0x0BADBEEF, tsval=1000,
                tsecr=2000, options=None, src_mac="00:00:0a:00:01:01",
                dst_mac="00:00:00:00:00:01", ip_id=0x4242, ttl=64, csum="full"):
    """Build an Ethernet/IPv4/TCP frame carrying `app`, as Linux would send it.

    options defaults to NOP,NOP,Timestamps (data offset 8).
    csum="full"    -> valid TCP checksum (what reaches the wire)
    csum="partial" -> pseudo-header sum only (CHECKSUM_PARTIAL, as seen at TC egress)
    """
    if options is None:
        options = b"\x01\x01\x08\x0a" + struct.pack("!II", tsval, tsecr)
    if len(options) % 4 or len(options) > 40:
        raise ValueError("TCP options must be 0..40 bytes, multiple of 4")
    doff = 5 + len(options) // 4
    tcp = bytearray(struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                                doff << 4, 0x18, 502, 0, 0)) + options
    seg = bytes(tcp) + bytes(app)
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    if csum == "full":
        check = tcp_checksum(s, d, seg)
    elif csum == "partial":
        check = tcp_pseudo_sum(s, d, len(seg))
    else:
        raise ValueError(csum)
    seg = seg[:16] + struct.pack("!H", check) + seg[18:]
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, IPV4_BASE_LEN + len(seg),
                               ip_id, 0x4000, ttl, 6, 0, s, d))
    ip[10:12] = struct.pack("!H", ipv4_checksum(ip))
    eth = bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00"
    return eth + bytes(ip) + seg


def build_modbus_frame(pdu, *, tid=1, unit=1, **kw):
    """Modbus/TCP: MBAP header + PDU."""
    return build_frame(struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + bytes(pdu), **kw)


def industrial_header(proto, data_len):
    """A plausible header for each protocol (the switch does not interpret it)."""
    if proto == "modbus":
        return struct.pack("!HHHB", 1, 0, (data_len + 1) & 0xFFFF, 1)
    if proto == "mqtt":                                     # PUBLISH, 1-byte length
        return bytes([0x30, data_len & 0x7F])
    if proto == "cip":                                      # SendRRData encapsulation
        return struct.pack("!HHIIQI", 0x6F, data_len & 0xFFFF, 0x11223344, 0, 0, 0)
    if proto == "dnp3":                                     # link header (+ CRC)
        return struct.pack("!HBBHHH", 0x0564, min(data_len + 5, 255), 0xC4, 1, 1024, 0xBEEF)
    raise ValueError(proto)


def build_ics_frame(proto, data, **kw):
    """Frame of `proto` ("modbus", "mqtt", "cip", "dnp3") carrying `data` after its header."""
    port = {name: port for port, (name, _) in PROTOCOLS.items()}[proto]
    kw.setdefault("dport", port)
    return build_frame(industrial_header(proto, len(data)) + bytes(data), **kw)


# --------------------------------------------------------------------------
# The P4ICS transformation
# --------------------------------------------------------------------------

def mac_context(frame, p, spi, counter, plain_len):
    """What the tag binds besides the ciphertext (the AAD)."""
    ip = ETH_LEN
    return (LABEL + struct.pack("!IQI", spi, counter, plain_len) +
            bytes(frame[ip + 12:ip + 20]) +                 # IPv4 source, destination
            bytes(frame[p.l4:p.l4 + 8]) +                   # TCP ports, sequence number
            bytes(frame[p.l7:p.data_off]))                  # industrial header, in clear


def protect(frame, keys, spi, counter):
    """Plaintext frame -> P4ICS protected frame (switch `cipher`).

    Everything after the industrial protocol header (L bytes) is protected;
    savedLen = L. spi/counter identify the sender and the packet. The IPv4
    checksum covers the whole 52-byte header.
    """
    p = parse(frame)
    if p.ihl != IPV4_IHL_PLAIN:
        raise P4icsError("plaintext frame must have IHL 5")
    if not p.protectable:
        raise P4icsError("no industrial payload to protect")
    data = bytes(frame[p.data_off:p.end])
    plain, clen = len(data), crypt_len(len(data))
    ct = cbc_encrypt(keys.expanded, keys.iv(spi, counter), data + b"\x00" * (clen - plain))
    tag = keys.tag(mac_context(frame, p, spi, counter, plain), ct)
    opts = struct.pack("!IIQ", plain, spi, counter) + tag

    ip = bytearray(frame[ETH_LEN:ETH_LEN + IPV4_BASE_LEN])
    ip[0] = 0x40 | IPV4_IHL_PROTECTED
    struct.pack_into("!H", ip, 2, p.tot_len + OPT_LEN + clen - plain)
    ip[10:12] = b"\x00\x00"
    ip[10:12] = struct.pack("!H", ipv4_checksum(bytes(ip) + opts))
    return bytes(frame[:ETH_LEN]) + bytes(ip) + opts + bytes(frame[p.l4:p.data_off]) + ct


def protected_fields(frame):
    """(savedLen, spi, counter, tag) of a protected frame."""
    opt = ETH_LEN + IPV4_BASE_LEN
    plain, spi, counter = struct.unpack_from("!IIQ", frame, opt)
    return plain, spi, counter, bytes(frame[opt + 16:opt + 16 + TAG_LEN])


def unprotect(frame, keys, window=None):
    """P4ICS protected frame -> plaintext frame (switch `decipher`).

    The tag is verified before decrypting. Raises P4icsError if the lengths
    are inconsistent, P4icsAuthError if the tag does not verify and, when a
    ReplayWindow is given, P4icsReplayError for a counter already accepted.
    The switch drops the frame in all three cases.
    """
    p = parse(frame)
    if p.ihl != IPV4_IHL_PROTECTED:
        raise P4icsError("protected frame must have IHL %d" % IPV4_IHL_PROTECTED)
    if not p.protectable:
        raise P4icsError("no industrial payload")
    plain, spi, counter, tag = protected_fields(frame)
    clen = crypt_len(plain)
    if p.data_len != clen:
        raise P4icsError("ciphertext length %d != crypt_len(savedLen=%d)" % (p.data_len, plain))
    ct = bytes(frame[p.data_off:p.end])
    if not hmac.compare_digest(tag, keys.tag(mac_context(frame, p, spi, counter, plain), ct)):
        raise P4icsAuthError("HMAC tag mismatch")
    if window is not None:
        window.accept(spi, counter)
    data = cbc_decrypt(keys.expanded, keys.iv(spi, counter), ct)[:plain]

    ip = bytearray(frame[ETH_LEN:ETH_LEN + IPV4_BASE_LEN])
    ip[0] = 0x40 | IPV4_IHL_PLAIN
    struct.pack_into("!H", ip, 2, p.tot_len - OPT_LEN - clen + plain)
    ip[10:12] = b"\x00\x00"
    ip[10:12] = struct.pack("!H", ipv4_checksum(ip))
    return bytes(frame[:ETH_LEN]) + bytes(ip) + bytes(frame[p.l4:p.data_off]) + data


class ReplayWindow:
    """Receiver anti-replay state, as kept in the switch registers.

    Per sender (SPI & 0xff): the highest counter accepted and a 64-bit bitmap of
    the counters below it (bit i = highest - i). A counter is accepted once,
    if it is above the highest or within the window and not seen yet.
    """

    def __init__(self):
        self.last = [0] * REPLAY_SLOTS
        self.bitmap = [0] * REPLAY_SLOTS

    def accept(self, spi, counter):
        i = spi & (REPLAY_SLOTS - 1)
        last, bitmap = self.last[i], self.bitmap[i]
        if counter > last:
            ahead = counter - last
            bitmap = 1 if ahead >= REPLAY_WINDOW else ((bitmap << ahead) | 1) & (2 ** REPLAY_WINDOW - 1)
            last = counter
        else:
            behind = last - counter
            if behind >= REPLAY_WINDOW or bitmap & (1 << behind):
                raise P4icsReplayError("counter %d of SPI %d replayed or too old" % (counter, spi))
            bitmap |= 1 << behind
        self.last[i], self.bitmap[i] = last, bitmap


def complete_tx_checksum(frame):
    """Emulate skb_checksum_help(): fold the TCP segment over a CHECKSUM_PARTIAL seed."""
    p = parse(frame)
    out = bytearray(frame)
    seg = bytes(out[p.l4:p.end])
    struct.pack_into("!H", out, p.l4 + 16, (~ones_sum(seg)) & 0xFFFF)
    return bytes(out)


def normalize(frame):
    """Drop what a switch hop legitimately changes: MACs, TTL, IPv4 checksum, trailer."""
    p = parse(frame)
    out = bytearray(frame[ETH_LEN:p.end])
    out[8] = 0
    out[10:12] = b"\x00\x00"
    return bytes(frame[12:14]) + bytes(out)


if __name__ == "__main__":
    k = P4icsKeys(testbed_words(256))
    f = build_modbus_frame(bytes.fromhex("0300000001"))
    prot = protect(f, k, 1, (1792700000 << 32) + 1)
    assert unprotect(prot, k) == f
    print("plaintext frame :", f.hex())
    print("protected frame :", prot.hex())
