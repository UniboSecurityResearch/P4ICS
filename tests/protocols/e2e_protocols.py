#!/usr/bin/env python3
"""Real industrial stacks through two P4ICS switches (testbed/s1, testbed/s2).

    ns client                  root ns of the container                    ns server
    195.11.14.5 c0 -- c0s [s1] b1 ===== protected ===== b2 [s2] sv0s -- sv0 200.1.1.7

Servers: testbed/modbusserver/server.py (pymodbus), dnp3_server
(protocols/dnp3/server_tcp), protocols/Ethernet-IP/server.py (cpppo).
Clients: testbed/modbusclient/modbus_client.py --rw, dnp3_client,
protocols/Ethernet-IP/client.py. Run via run_protocols.sh.
"""

import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "reference"))
sys.path.insert(0, os.path.join(REPO, "tests", "bmv2"))

import p4ics_ref as ref                          # noqa: E402
from switch_harness import Switch, build_switch, sh  # noqa: E402

WORK = "/tmp/p4ics-protocols"
EVENTS = "MyIngress.p4ics_events"
KEYS = ref.P4icsKeys(ref.TESTBED_WORDS)       # in the lab: shared/p4ics_key, one per run
PORTS = {502: "modbus", 20000: "dnp3", 44818: "enip"}
SERVER = "200.1.1.7"
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, (" -- " + detail) if detail else ""))
    sys.stdout.flush()


def ns(name, cmd, env="", timeout=120):
    full = "nsenter --net=/run/netns/%s sh -c '%s %s'" % (name, env, cmd)
    return subprocess.run(full, shell=True, text=True, capture_output=True, timeout=timeout)


class Capture:
    """Every IPv4/TCP frame to/from an industrial port seen on an interface."""

    def __init__(self, dev):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sock.bind((dev, 0))
        self.sock.settimeout(0.2)
        self.frames, self.running = [], True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            try:
                frame = self.sock.recv(65535)
            except socket.timeout:
                continue
            try:
                p = ref.parse(frame)
            except ref.P4icsError:
                continue
            if (p.sport in PORTS or p.dport in PORTS) and p.payload_len:
                self.frames.append(frame)

    def stop(self):
        time.sleep(0.5)
        self.running = False
        self.thread.join()
        return self.frames


def setup():
    sh("rm -rf %s && mkdir -p %s" % (WORK, WORK))
    s1_dir = build_switch(os.path.join(REPO, "testbed", "s1"), os.path.join(WORK, "s1"))
    s2_dir = build_switch(os.path.join(REPO, "testbed", "s2"), os.path.join(WORK, "s2"))
    for n in ("client", "server"):
        sh("ip netns del %s 2>/dev/null || true; ip netns add %s; ip -n %s link set lo up" % (n, n, n))
    for a, b in (("c0", "c0s"), ("b1", "b2"), ("sv0", "sv0s")):
        sh("ip link add %s type veth peer name %s" % (a, b))
    sh("ip link set c0 netns client && ip link set sv0 netns server")
    for dev in ("c0s", "b1", "b2", "sv0s"):
        sh("ip link set %s up" % dev)
    sh("ip -n client link set c0 address 00:00:0a:00:01:01 up")
    sh("ip -n client addr add 195.11.14.5/24 dev c0")
    sh("ip -n client route add default via 195.11.14.1")
    sh("ip -n client neigh add 195.11.14.1 lladdr 00:00:00:00:00:01 dev c0")
    sh("ip -n server link set sv0 address 00:00:0a:00:01:02 up")
    sh("ip -n server addr add %s/24 dev sv0" % SERVER)
    sh("ip -n server route add default via 200.1.1.1")
    sh("ip -n server neigh add 200.1.1.1 lladdr 00:00:00:00:00:04 dev sv0")
    # bmv2 reads through packet sockets: let the endpoints compute TCP checksums.
    for n, dev in (("client", "c0"), ("server", "sv0")):
        sh("nsenter --net=/run/netns/%s ethtool -K %s tx off >/dev/null" % (n, dev))

    epoch = time.time_ns() - 1577836800 * 10**9
    switches = []
    for name, d, ports, thrift in (("s1", s1_dir, [(1, "c0s"), (2, "b1")], 9090),
                                   ("s2", s2_dir, [(1, "sv0s"), (2, "b2")], 9091)):
        sw = Switch(d, ports, thrift_port=thrift, log=os.path.join(WORK, name + ".log"))
        sw.cli(open(os.path.join(REPO, "testbed", name, "commands.txt")).read())
        sw.set_keys(KEYS.words)
        sw.cli("register_write p4ics_tx_counter 0 %d\n" % epoch)
        switches.append(sw)

    servers = [
        "cd /p4ics/testbed/modbusserver && exec python3 server.py",
        "exec dnp3_server",
        "ENIP_ADDRESS=%s:44818 exec python3 /p4ics/protocols/Ethernet-IP/server.py" % SERVER,
    ]
    procs = [subprocess.Popen("nsenter --net=/run/netns/server sh -c '%s'" % cmd, shell=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for cmd in servers]
    time.sleep(3)
    return switches, procs


def main():
    (s1, s2), procs = setup()
    try:
        before = {name: [sw.counter_read(EVENTS, i) for i in range(4)]
                  for name, sw in (("s1", s1), ("s2", s2))}
        cap = Capture("b1")

        r = ns("client", "cd /p4ics/testbed/modbusclient && python3 modbus_client.py --rw")
        check("Modbus: pymodbus write + read through P4ICS",
              r.returncode == 0 and "registro 0: 45" in r.stdout, r.stdout.strip().replace("\n", " | "))
        r = ns("client", "dnp3_client",
               env="DNP3_ENDPOINT=%s:20000 DNP3_READS=300 DNP3_TIMES_FILE=/tmp/dnp3.txt" % SERVER)
        check("DNP3: 300 class-0 reads (stepfunc/dnp3) through P4ICS",
              r.returncode == 0 and "OK: 300" in r.stdout, (r.stdout + r.stderr).strip()[-200:])
        r = ns("client", "python3 /p4ics/protocols/Ethernet-IP/client.py && wc -l < /tmp/enip.txt",
               env="ENIP_HOST=%s ENIP_READS=300 ENIP_TIMES_FILE=/tmp/enip.txt" % SERVER)
        check("EtherNet/IP: 300 CIP tag reads (cpppo) through P4ICS",
              r.returncode == 0 and r.stdout.strip().endswith("300"), (r.stdout + r.stderr).strip()[-200:])

        frames = cap.stop()
        per_proto, bad, window = {}, [], ref.ReplayWindow()
        for f in frames:
            p = ref.parse(f)
            proto = PORTS.get(p.dport) or PORTS.get(p.sport)
            if p.data_len <= 0:
                continue                                    # header-only: never protected
            per_proto[proto] = per_proto.get(proto, 0) + 1
            try:
                plain = ref.unprotect(f, KEYS, window)
                spi = ref.protected_fields(f)[1]
                expected_spi = 1 if ref.parse(plain).dst == socket.inet_aton(SERVER) else 2
                if spi != expected_spi:
                    bad.append((proto, "spi %d" % spi))
            except ref.P4icsError as exc:
                bad.append((proto, str(exc)))
        check("s1-s2 link: every industrial payload protected, authenticated, fresh",
              per_proto and not bad, "%s frames, %d problems %s" % (per_proto, len(bad), bad[:3]))

        after = {name: [sw.counter_read(EVENTS, i) for i in range(4)]
                 for name, sw in (("s1", s1), ("s2", s2))}
        for name in ("s1", "s2"):
            d = [a - b for a, b in zip(after[name], before[name])]
            check("%s p4ics_events: %d protected, %d unprotected, no rejections or replays" % (
                name, d[0], d[1]), d[0] > 0 and d[1] > 0 and d[2] == 0 and d[3] == 0)

        # Replay a captured DNP3 request into s2.
        replay = next(f for f in frames if ref.parse(f).dport == 20000 and ref.parse(f).data_len > 0)
        replays = s2.counter_read(EVENTS, 3)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind(("b1", 0))
        sock.send(replay)
        time.sleep(0.5)
        check("replayed DNP3 frame dropped by s2", s2.counter_read(EVENTS, 3) > replays)
    finally:
        for p in procs:
            p.terminate()
        s1.stop()
        s2.stop()

    print("%d/%d protocol checks passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
