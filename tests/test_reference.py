#!/usr/bin/env python3
"""Unit tests of tests/reference/p4ics_ref.py (no root, no Docker).

Primitives against FIPS-197, RFC 4231, RFC 5869 and, when available, the
`cryptography` package; then the P4ICS v2 transformation: round trips for
every protocol, what the tag binds, and the anti-replay window.
"""

import hashlib
import hmac
import os
import random
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "reference"))
import p4ics_ref as ref  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    Cipher = None

SPI, COUNTER = 1, (1792700000 << 32) + 1


class Primitives(unittest.TestCase):
    def test_aes_fips197(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        for nk, ct in ((4, "69c4e0d86a7b0430d8cdb78070b4c55a"),
                       (6, "dda97ca4864cdfe06eaf70a0ec0d7191"),
                       (8, "8ea2b7ca516745bfeafc49904b496089")):
            ex = ref.aes_expand_key(bytes(range(4 * nk)))
            self.assertEqual(ref.aes_encrypt_block(ex, pt).hex(), ct)
            self.assertEqual(ref.aes_decrypt_block(ex, bytes.fromhex(ct)), pt)

    @unittest.skipIf(Cipher is None, "cryptography not installed")
    def test_cbc_against_cryptography(self):
        rnd = random.Random(3)
        for n in (16, 24, 32):
            for _ in range(10):
                key, iv = rnd.randbytes(n), rnd.randbytes(16)
                data = rnd.randbytes(16 * rnd.randrange(1, 17))
                enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                expected = enc.update(data) + enc.finalize()
                ex = ref.aes_expand_key(key)
                self.assertEqual(ref.cbc_encrypt(ex, iv, data), expected)
                self.assertEqual(ref.cbc_decrypt(ex, iv, expected), data)

    def test_rijndael_160_224_round_trip(self):
        rnd = random.Random(4)
        for n in (20, 28):
            ex = ref.aes_expand_key(rnd.randbytes(n))
            self.assertEqual(ex[1], n // 4 + 6)
            block = rnd.randbytes(16)
            self.assertEqual(ref.aes_decrypt_block(ex, ref.aes_encrypt_block(ex, block)), block)

    def test_hmac_rfc4231(self):
        mac = hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest()
        self.assertEqual(mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    def test_hkdf_rfc5869(self):
        okm = ref.hkdf_sha256(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ec"
                                    "c4c5bf34007208d5b887185865")


class Keys(unittest.TestCase):
    def test_key_sizes(self):
        for bits in (128, 160, 192, 224, 256):
            k = ref.P4icsKeys(ref.testbed_words(bits))
            self.assertEqual(k.bits, bits)
            self.assertEqual(len(k.enc_key), bits // 8)

    def test_keys_are_independent(self):
        a = ref.P4icsKeys(ref.testbed_words(128))
        b = ref.P4icsKeys(ref.testbed_words(256))
        self.assertNotEqual(a.mac_key, b.mac_key)      # every key word matters
        self.assertNotEqual(a.mac_key[:16], a.enc_key)

    def test_rejects_short_keys(self):
        with self.assertRaises(ValueError):
            ref.P4icsKeys([1, 2, 3, 0, 5, 6, 7, 8])

    def test_parse_commands(self):
        path = os.path.join(HERE, "..", "testbed", "s1", "commands.txt")
        self.assertEqual(tuple(ref.parse_commands(path)), ref.TESTBED_WORDS)


class WireFormat(unittest.TestCase):
    keys = ref.P4icsKeys(ref.testbed_words(256))

    def test_round_trip_lengths(self):
        rnd = random.Random(5)
        for i, n in enumerate(list(range(1, 300)) + [511, 512, 513, 1400, 9000]):
            f = ref.build_modbus_frame(rnd.randbytes(n), seq=rnd.randrange(1 << 32))
            p = ref.protect(f, self.keys, SPI, COUNTER + i)
            q = ref.parse(p)
            self.assertEqual(q.ihl, ref.IPV4_IHL_PROTECTED)
            self.assertEqual(q.payload_len, ref.MBAP_LEN + ref.crypt_len(n))
            self.assertEqual(ref.ones_sum(p[14:14 + 52]), 0xFFFF)
            self.assertEqual(ref.unprotect(p, self.keys), f)

    def test_all_protocols(self):
        for proto, hdr in (("modbus", 7), ("mqtt", 2), ("cip", 24), ("dnp3", 10)):
            for n in (1, 16, 300):
                f = ref.build_ics_frame(proto, bytes(n))
                p = ref.parse(f)
                self.assertEqual((p.proto, p.hdr_len, p.data_len), (proto, hdr, n))
                self.assertEqual(ref.unprotect(ref.protect(f, self.keys, SPI, COUNTER), self.keys), f)

    def test_counter_changes_ciphertext(self):
        f = ref.build_modbus_frame(bytes(32))
        a, b = ref.protect(f, self.keys, SPI, COUNTER), ref.protect(f, self.keys, SPI, COUNTER + 1)
        self.assertNotEqual(a[-48:], b[-48:])          # fresh IV per packet

    def test_tag_binds_context(self):
        f = ref.build_modbus_frame(bytes(range(30)))
        prot = bytearray(ref.protect(f, self.keys, SPI, COUNTER))
        p = ref.parse(bytes(prot))
        offsets = {
            "ciphertext": p.end - 1, "tag": 14 + 20 + 16, "savedLen": 14 + 23,
            "spi": 14 + 27, "counter": 14 + 35, "source address": 14 + 12,
            "destination address": 14 + 19, "source port": p.l4, "sequence number": p.l4 + 7,
            "industrial header (MBAP unit id)": p.l7 + 6,
        }
        for what, off in offsets.items():
            bad = bytearray(prot)
            bad[off] ^= 1
            with self.assertRaises(ref.P4icsError, msg=what):
                ref.unprotect(bytes(bad), self.keys)
        # ...but not the fields routers rewrite.
        hop = bytearray(prot)
        hop[14 + 8] -= 1                                # TTL
        self.assertEqual(ref.normalize(ref.unprotect(bytes(hop), self.keys)), ref.normalize(f))

    def test_replay_window(self):
        w, base = ref.ReplayWindow(), COUNTER
        w.accept(SPI, base)
        with self.assertRaises(ref.P4icsReplayError):
            w.accept(SPI, base)                         # exact replay
        w.accept(SPI, base + 10)
        w.accept(SPI, base + 3)                         # late, inside the window
        with self.assertRaises(ref.P4icsReplayError):
            w.accept(SPI, base + 3)
        w.accept(SPI, base + 10 + 100)                  # jump: window restarts
        with self.assertRaises(ref.P4icsReplayError):
            w.accept(SPI, base + 10 + 100 - ref.REPLAY_WINDOW)   # too old
        w.accept(SPI + 1, base)                         # other senders are independent
        f = ref.build_modbus_frame(bytes(8))
        prot = ref.protect(f, self.keys, 9, 77)
        self.assertEqual(ref.unprotect(prot, self.keys, w), f)
        with self.assertRaises(ref.P4icsReplayError):
            ref.unprotect(prot, self.keys, w)

    def test_header_only_is_not_protected(self):
        f = ref.build_ics_frame("mqtt", b"")
        self.assertFalse(ref.parse(f).protectable)
        with self.assertRaises(ref.P4icsError):
            ref.protect(f, self.keys, SPI, COUNTER)

    def test_crypt_len_always_pads(self):
        self.assertEqual(ref.crypt_len(15), 16)
        self.assertEqual(ref.crypt_len(16), 32)
        self.assertEqual(ref.crypt_len(255), 256)

    def test_already_protected(self):
        prot = ref.protect(ref.build_modbus_frame(bytes(40)), self.keys, SPI, COUNTER)
        with self.assertRaises(ref.P4icsError):
            ref.protect(prot, self.keys, SPI, COUNTER + 1)

    def test_partial_checksum_emulation(self):
        f = ref.build_modbus_frame(bytes(range(9)))
        partial = ref.build_modbus_frame(bytes(range(9)), csum="partial")
        self.assertTrue(ref.tcp_checksum_ok(f))
        self.assertEqual(ref.complete_tx_checksum(partial), f)


if __name__ == "__main__":
    unittest.main(verbosity=1)
