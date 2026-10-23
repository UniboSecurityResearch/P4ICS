#!/usr/bin/env python3
"""Modbus-framed TCP echo, to drive traffic through the switches.

    echo.py server ADDR PORT
    echo.py client DST PORT --src ADDR (--count N | --duration S) [--interval S]

The client sends MBAP header + random PDU (1..200 bytes), checks the echo
and prints one JSON line: {"ok", "bad", "error", "max_rtt_ms", "retrans"}.
retrans: segments the client retransmitted (TCP_INFO); a lost echo shows up
as an RTT above the 200 ms minimum retransmission timeout.
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import threading
import time


def serve(addr, port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, port))
    srv.listen(16)

    def echo(conn):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=echo, args=(conn,), daemon=True).start()


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def total_retrans(sock):
    """tcpi_total_retrans of struct tcp_info (8 bytes, then u32 fields)."""
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    return struct.unpack_from("I", info, 8 + 23 * 4)[0]


def client(args):
    out = {"ok": 0, "bad": 0, "error": None, "max_rtt_ms": 0.0, "retrans": None}
    try:
        sock = socket.create_connection((args.dst, args.port), timeout=args.timeout,
                                        source_address=(args.src, 0))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        end = time.monotonic() + args.duration
        n = 0
        while (args.count and n < args.count) or (not args.count and time.monotonic() < end):
            pdu = os.urandom(random.randint(1, 200))
            msg = struct.pack("!HHHB", n & 0xFFFF, 0, len(pdu) + 1, 1) + pdu
            t0 = time.monotonic()
            sock.sendall(msg)
            got = recv_exact(sock, len(msg))
            out["max_rtt_ms"] = max(out["max_rtt_ms"], (time.monotonic() - t0) * 1000)
            out["ok" if got == msg else "bad"] += 1
            n += 1
            time.sleep(args.interval)
        out["retrans"] = total_retrans(sock)
        sock.close()
    except (OSError, ConnectionError) as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    print(json.dumps(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server", "client"])
    ap.add_argument("addr")
    ap.add_argument("port", type=int)
    ap.add_argument("--src", default="0.0.0.0")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--duration", type=float, default=5)
    ap.add_argument("--interval", type=float, default=0.01)
    ap.add_argument("--timeout", type=float, default=3)
    args = ap.parse_args()
    if args.mode == "server":
        serve(args.addr, args.port)
    else:
        args.dst = args.addr
        client(args)


if __name__ == "__main__":
    sys.exit(main())
