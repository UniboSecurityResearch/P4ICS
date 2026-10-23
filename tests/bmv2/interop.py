#!/usr/bin/env python3
"""Ground-truth check of tests/reference/p4ics_ref.py against the P4ICS switch.

Runs the switch program of testbed/s1 (bmv2 + extern) and checks, for Modbus,
MQTT, EtherNet/IP and DNP3 and payloads from 1 byte to ~60 KB:

  A. plaintext  --(port 1 -> 2, `cipher`)-->   must equal ref.protect()
  B. ref.protect() --(port 2 -> 1, `decipher`)--> must equal the plaintext

then the security behaviour of `decipher`: anything that does not
authenticate, and every replay, is dropped and counted. Run via
run_interop.sh (needs NET_ADMIN, uses the loriringhio97/p4 image).
"""

import argparse
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "reference"))
sys.path.insert(0, HERE)

import p4ics_ref as ref                                   # noqa: E402
from switch_harness import Port, Switch, build_switch, make_veth, sh, through  # noqa: E402

MODBUS_LENGTHS = [1, 2, 5, 15, 16, 17, 31, 32, 33, 100, 200, 252, 253, 255]
BIG_LENGTHS = [1, 15, 16, 17, 255, 256, 257, 511, 512, 513, 1000, 1380, 4000, 9000,
               20000, 40000, 60000]
OPTIONS = {
    "ts": None,                                               # NOP,NOP,TS (doff 8)
    "none": b"",                                              # doff 5
    "mss+sack+ts": bytes.fromhex("020405b4" "0402080a") + struct.pack("!II", 7, 9) + bytes.fromhex("01030307"),
}

SWITCH_SPI = 1            # what the switch puts in the frames it protects
PEER_SPI = 7              # the "other end" whose frames the switch deciphers
EVENTS = "MyIngress.p4ics_events"

WILDCARD = "0.0.0.0&&&0.0.0.0 0.0.0.0&&&0.0.0.0"
ROUTES = """\
table_set_default ipv4_lpm drop
table_add ipv4_lpm ipv4_forward 200.1.1.7/32 => 00:00:00:00:00:03 2
table_add ipv4_lpm ipv4_forward 195.11.14.5/32 => 00:00:0a:00:01:01 1
table_add ics_sec decipher 1&&&0x1ff %s => 1000
table_add ics_sec cipher 2&&&0x1ff %s => 1000
""" % (WILDCARD, WILDCARD)


class Checker:
    def __init__(self):
        self.total = self.failures = 0

    def __call__(self, name, ok, got=None, expected=None):
        self.total += 1
        if not ok:
            self.failures += 1
            print("FAIL %s" % name)
            if got is not None or expected is not None:
                print("  got %s\n  exp %s" % (got.hex()[:400] if got else None,
                                             expected.hex()[:400] if expected else None))
        return ok


class Peer:
    """The remote endpoint: protects frames with increasing counters."""

    def __init__(self, spi, base):
        self.spi, self.counter = spi, base

    def protect(self, frame, keys):
        self.counter += 1
        return ref.protect(frame, keys, self.spi, self.counter)


def ip_checksum_ok(frame):
    p = ref.parse(frame)
    return ref.ones_sum(frame[14:p.l4]) == 0xFFFF


def to_server(proto, data, seq, sport, options=None):
    return ref.build_ics_frame(proto, data, seq=seq, sport=sport, options=options)


def to_client(proto, data, seq, dport, options=None):
    port = {name: p for p, (name, _) in ref.PROTOCOLS.items()}[proto]
    return ref.build_ics_frame(proto, data, src="200.1.1.7", dst="195.11.14.5", sport=port,
                               dport=dport, seq=seq, options=options,
                               src_mac="00:00:0a:00:01:02", dst_mac="00:00:00:00:00:04")


class Bench:
    def __init__(self, sw, p1, p2, check):
        self.sw, self.p1, self.p2, self.check = sw, p1, p2, check
        self.tx_counter = 0
        self.peer = Peer(PEER_SPI, 1 << 40)

    def set_epoch(self, epoch, phase=0):
        """Counters of the switch continue at epoch + packets protected so far."""
        self.sw.set_local(SWITCH_SPI, phase, epoch)
        self.tx_counter = epoch + self.sw.register_read("MyIngress.p4ics_tx_count", 0)
        self.tx_phase = phase

    def round_trip(self, keys, name, plain_up, plain_down):
        """A: switch cipher == reference; B: switch decipher(reference) == plaintext."""
        out = through(self.p1, self.p2, plain_up)
        self.tx_counter += 1
        expected = ref.protect(plain_up, keys, ref.spi_field(SWITCH_SPI, self.tx_phase), self.tx_counter)
        ok = out is not None and ref.normalize(out) == ref.normalize(expected)
        if ok:
            # exact length (no Ethernet trailer), RFC 791 checksum over the options
            ok = len(out) == ref.parse(out).end and ip_checksum_ok(out)
            ok = ok and ref.normalize(ref.unprotect(out, keys)) == ref.normalize(plain_up)
        self.check("cipher   %s" % name, ok, out, expected)

        out = through(self.p2, self.p1, self.peer.protect(plain_down, keys))
        ok = out is not None and ref.normalize(out) == ref.normalize(plain_down)
        self.check("decipher %s" % name, ok and ip_checksum_ok(out), out, plain_down)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p4-dir", default="/p4ics/testbed/s1")
    ap.add_argument("--work", default="/tmp/p4ics-interop")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    work = build_switch(args.p4_dir, args.work)
    make_veth("p1h", "p1s")
    make_veth("p2h", "p2s")
    for dev in ("p1h", "p1s", "p2h", "p2s"):
        sh("ip link set %s mtu 65535" % dev)
    sw = Switch(work, [(1, "p1s"), (2, "p2s")], log=os.path.join(work, "switch.log"))
    p1, p2 = Port("p1h"), Port("p2h")
    sw.cli(ROUTES)
    check = Checker()
    bench = Bench(sw, p1, p2, check)
    bench.set_epoch(5000 << 32)

    def rand(n):
        return rnd.randbytes(n)

    try:
        # Modbus: every key size, every PDU length class.
        for bits in (128, 160, 192, 224, 256):
            keys = ref.P4icsKeys(ref.testbed_words(bits))
            sw.set_keys(keys.words)
            for n in MODBUS_LENGTHS:
                data, seq = rand(n), rnd.randrange(1 << 32)
                bench.round_trip(keys, "modbus AES-%d L=%d" % (bits, n),
                                 to_server("modbus", data, seq, rnd.randrange(1024, 65535)),
                                 to_client("modbus", data, seq ^ 0x5A5A5A5A, rnd.randrange(1024, 65535)))
            print("modbus AES-%d: done" % bits)

        # All protocols, payloads from one byte to ~60 KB (slices + tail).
        keys = ref.P4icsKeys(ref.testbed_words(256))
        sw.set_keys(keys.words)
        for proto in ("modbus", "mqtt", "cip", "dnp3"):
            for n in BIG_LENGTHS:
                data, seq = rand(n), rnd.randrange(1 << 32)
                bench.round_trip(keys, "%s L=%d" % (proto, n),
                                 to_server(proto, data, seq, rnd.randrange(1024, 65535)),
                                 to_client(proto, data, seq + 1, rnd.randrange(1024, 65535)))
            for oname, opts in OPTIONS.items():
                data, seq = rand(300), rnd.randrange(1 << 32)
                bench.round_trip(keys, "%s tcp-options=%s" % (proto, oname),
                                 to_server(proto, data, seq, 40000, opts),
                                 to_client(proto, data, seq, 40001, opts))
            print("%s: done" % proto)

        security_checks(sw, p1, p2, check, keys, bench, rand)
        rekey_checks(sw, p1, p2, check, keys, bench, rand)
        on_demand_checks(sw, p1, p2, check, keys, bench, rand)
    finally:
        sw.stop()

    print("%d/%d switch interop checks passed" % (check.total - check.failures, check.total))
    return 1 if check.failures else 0


def security_checks(sw, p1, p2, check, keys, bench, rand):
    before = [sw.counter_read(EVENTS, i) for i in range(4)]
    plain = to_client("modbus", rand(40), 0xCAFEBABE, 40002)

    # decipher drops anything that does not authenticate.
    prot = bytearray(bench.peer.protect(plain, keys))
    p = ref.parse(bytes(prot))
    tampered = {
        "ciphertext": p.end - 1, "tag": 14 + 20 + 16, "savedLen": 14 + 23, "spi": 14 + 27,
        "counter": 14 + 35, "source address": 14 + 12, "destination port": p.l4 + 3,
        "sequence number": p.l4 + 7, "MBAP unit id": p.l7 + 6,
    }
    for what, off in tampered.items():
        bad = bytearray(prot)
        bad[off] ^= 0x01
        check("decipher drops tampered %s" % what, through(p2, p1, bytes(bad), 1.0) is None)
    wrong = ref.P4icsKeys([w ^ 1 if w else 0 for w in keys.words])
    check("decipher drops another key",
          through(p2, p1, ref.protect(plain, wrong, PEER_SPI, bench.peer.counter + 50), 1.0) is None)
    check("decipher drops unprotected payload", through(p2, p1, plain, 1.0) is None)

    # Anti-replay: the untampered frame is accepted once.
    check("decipher accepts the genuine frame", through(p2, p1, bytes(prot)) is not None)
    check("decipher drops its replay", through(p2, p1, bytes(prot), 1.0) is None)
    late = bench.peer.protect(plain, keys)            # counter n
    newer = [bench.peer.protect(plain, keys) for _ in range(3)]
    for f in newer:
        through(p2, p1, f)
    check("late frame inside the window accepted", through(p2, p1, late) is not None)
    check("... but only once", through(p2, p1, late, 1.0) is None)
    old = ref.protect(plain, keys, PEER_SPI, bench.peer.counter - ref.REPLAY_WINDOW - 1)
    check("frame older than the window dropped", through(p2, p1, old, 1.0) is None)
    other = Peer(PEER_SPI + 1, 10)
    check("other senders have their own window",
          through(p2, p1, other.protect(plain, keys)) is not None)
    jump = ref.protect(plain, keys, PEER_SPI, bench.peer.counter + 1000)
    check("counter jump accepted", through(p2, p1, jump) is not None)
    check("pre-jump counters now too old",
          through(p2, p1, ref.protect(plain, keys, PEER_SPI, bench.peer.counter + 1), 1.0) is None)

    after = [sw.counter_read(EVENTS, i) for i in range(4)]
    rejected_tag, replays = after[2] - before[2], after[3] - before[3]
    check("p4ics_events: %d tag/length rejections, %d replays" % (rejected_tag, replays),
          rejected_tag == len(tampered) + 2 and replays == 4)

    # Pass-through and fail-closed cases on the cipher side.
    counter_before = sw.register_read("MyIngress.p4ics_tx_count", 0)
    up = to_server("modbus", rand(20), 7, 40003)
    already = bench.peer.protect(up, keys)
    out = through(p1, p2, already)
    check("cipher forwards an already protected frame",
          out is not None and ref.normalize(out) == ref.normalize(already))
    for name, frame in (("header-only", ref.build_ics_frame("mqtt", b"", dport=1883)),
                        ("shorter than header", ref.build_frame(b"\x00\x01\x00", dport=502))):
        out = through(p1, p2, frame)
        check("cipher forwards %s segment" % name,
              out is not None and ref.normalize(out) == ref.normalize(frame))
    check("pass-through does not consume counters",
          sw.register_read("MyIngress.p4ics_tx_count", 0) == counter_before)
    sw.set_local(0, 0, 1 << 40)
    check("cipher drops when no SPI is configured", through(p1, p2, up, 1.0) is None)
    bench.set_epoch(6000 << 32)


def rekey_checks(sw, p1, p2, check, keys, bench, rand):
    """Hitless rekey: both phases are accepted while senders switch over."""
    new = ref.P4icsKeys([w ^ 0x5A5A5A5A for w in keys.words])
    down = to_client("modbus", rand(30), 0xABCD, 40010)
    peer = bench.peer
    peer.counter += 2000          # past the counter jump of security_checks

    def peer_frame(k, phase):
        peer.counter += 1
        return ref.protect(down, k, ref.spi_field(PEER_SPI, phase), peer.counter)

    check("phase-1 frame dropped while only phase 0 has a key",
          through(p2, p1, peer_frame(new, 1), 1.0) is None)
    sw.install_key(1, new.words)
    check("phase-1 frame accepted once the new key is installed",
          through(p2, p1, peer_frame(new, 1)) is not None)
    check("phase-0 frames (old key) still accepted during the switch-over",
          through(p2, p1, peer_frame(keys, 0)) is not None)
    check("a phase-1 frame under the old key is rejected",
          through(p2, p1, peer_frame(keys, 1), 1.0) is None)

    bench.set_epoch(7000 << 32, phase=1)
    up = to_server("modbus", rand(25), 0x1234, 40011)
    out = through(p1, p2, up)
    bench.tx_counter += 1
    expected = ref.protect(up, new, ref.spi_field(SWITCH_SPI, 1), bench.tx_counter)
    check("after the switch-over the switch protects with phase 1 and the new key",
          out is not None and ref.normalize(out) == ref.normalize(expected), out, expected)
    sw.install_key(0, keys.words)
    bench.set_epoch(8000 << 32, phase=0)


def on_demand_checks(sw, p1, p2, check, keys, bench, rand):
    """ics_sec default request_tunnel: drop + digest until an entry exists."""
    events = lambda: sw.counter_read(EVENTS, 4)            # noqa: E731
    sw.cli("table_clear ics_sec\ntable_set_default ics_sec request_tunnel\n")
    up = to_server("modbus", rand(20), 0x4242, 40020)
    before = events()
    check("on demand: flow without a tunnel is dropped", through(p1, p2, up, 1.0) is None)
    check("on demand: ... and reported (p4ics_events[4])", events() == before + 1)
    sw.cli("table_add ics_sec cipher 2&&&0x1ff 195.11.14.5&&&255.255.255.255 "
           "200.1.1.7&&&255.255.255.255 => 10\n")
    out = through(p1, p2, up)
    bench.tx_counter += 1
    expected = ref.protect(up, keys, ref.spi_field(SWITCH_SPI, 0), bench.tx_counter)
    check("on demand: protected once the endpoint-pair entry is installed",
          out is not None and ref.normalize(out) == ref.normalize(expected), out, expected)
    other = ref.build_ics_frame("modbus", rand(20), src="195.11.14.99", sport=40021)
    before = events()
    check("on demand: another source still waits for its own tunnel",
          through(p1, p2, other, 1.0) is None and events() == before + 1)
    sw.cli("table_clear ics_sec\ntable_set_default ics_sec no_cipher\n"
           "table_add ics_sec decipher 1&&&0x1ff %s => 1000\n"
           "table_add ics_sec cipher 2&&&0x1ff %s => 1000\n"
           "table_add ics_sec no_cipher 2&&&0x1ff 195.11.14.5&&&255.255.255.255 "
           "200.1.1.7&&&255.255.255.255 => 10\n" % (WILDCARD, WILDCARD))
    check("a specific entry takes precedence over the per-port tunnel",
          ref.normalize(through(p1, p2, up)) == ref.normalize(up))


if __name__ == "__main__":
    sys.exit(main())
