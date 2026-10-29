#!/usr/bin/env python3
"""The optional P4Runtime controller (controller/) driving two P4ICS switches,
and its web GUI.

    ns client                     root ns of the container                ns server
    195.11.14.5, .6 c0 -- c0s [s1] b1 ===== protected ===== b2 [s2] sv0s -- sv0 200.1.1.7
                               |  gRPC, mutual TLS          |
                               +----- p4ics-controller -----+   (or c1 <-> c2, Diffie-Hellman)

simple_switch_grpc starts with no program; the controller pushes the
pipeline of testbed/sN, installs testbed/sN/commands.txt, and manages keys,
SPIs and counters. Traffic: Modbus-framed TCP echoes (echo.py). Run via
run_controller.sh.
"""

import base64
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "reference"))
sys.path.insert(0, os.path.join(REPO, "tests", "bmv2"))
sys.path.insert(0, os.path.join(REPO, "tests", "protocols"))

import grpc                                       # noqa: E402
from google.protobuf import text_format           # noqa: E402
from p4.config.v1 import p4info_pb2               # noqa: E402
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc  # noqa: E402

import p4ics_ref as ref                           # noqa: E402
from e2e_protocols import Capture                 # noqa: E402
from switch_harness import build_switch, sh       # noqa: E402

WORK = "/tmp/p4ics-controller"
PKI = WORK + "/pki"
GUI_PASSWORD = WORK + "/gui-password"
SERVER, CLIENT, OTHER = "200.1.1.7", "195.11.14.5", "195.11.14.6"
ECHO = os.path.join(HERE, "echo.py")
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, (" -- " + str(detail)) if detail else ""))
    sys.stdout.flush()


def wait_for(pred, timeout=30, step=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = pred()
            if v:
                return v
        except (OSError, KeyError, ValueError, http.client.HTTPException):
            pass
        time.sleep(step)
    return None


def ns(name, cmd):
    return "nsenter --net=/run/netns/%s %s" % (name, cmd)


def echo(src=CLIENT, count=20, duration=0, interval=0.01, timeout=3):
    """Run the echo client in the client namespace; returns its summary."""
    opts = "--count %d" % count if count else "--duration %s" % duration
    r = subprocess.run(ns("client", "python3 %s client %s 502 --src %s %s --interval %s --timeout %s" % (
        ECHO, SERVER, src, opts, interval, timeout)), shell=True, text=True, capture_output=True)
    return json.loads(r.stdout.strip().splitlines()[-1])


def echo_bg(src=CLIENT, duration=8):
    return subprocess.Popen(ns("client", "python3 %s client %s 502 --src %s --duration %s" % (
        ECHO, SERVER, src, duration)), shell=True, text=True, stdout=subprocess.PIPE)


def echo_result(proc):
    return json.loads(proc.communicate()[0].strip().splitlines()[-1])


def hitless(r):
    """The echo flow lost nothing: no error, no retransmission by the client,
    and no echo late enough to have been retransmitted by the server."""
    return not r["error"] and r["bad"] == 0 and r["retrans"] == 0 and r["max_rtt_ms"] < 150


class GrpcSwitch:
    """simple_switch_grpc with no program and a mutual-TLS P4Runtime server."""

    def __init__(self, name, ports, device_id, port):
        self.name, self.ports, self.device_id, self.port = name, ports, device_id, port
        self.dir = os.path.join(WORK, name)
        self.start()

    def start(self):
        ifaces = " ".join("-i %d@%s" % p for p in self.ports)
        self.proc = subprocess.Popen(
            "exec simple_switch_grpc %s --device-id %d --no-p4 -- --load-modules=extern_lib/definition.so "
            "--grpc-server-addr 127.0.0.1:%d --grpc-server-ssl --grpc-server-cacert %s/ca.pem "
            "--grpc-server-cert %s/%s.pem --grpc-server-key %s/%s-key.pem --grpc-server-with-client-auth" % (
                ifaces, self.device_id, self.port, PKI, PKI, self.name, PKI, self.name),
            shell=True, cwd=self.dir, stdout=open(os.path.join(WORK, self.name + ".log"), "a"),
            stderr=subprocess.STDOUT)
        if not wait_for(lambda: socket.create_connection(("127.0.0.1", self.port), timeout=1), 30):
            raise RuntimeError("%s did not come up" % self.name)

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


class Controller:
    def __init__(self, name, port, switches, tunnels=None, rotate="0s", peer=None, gui=None):
        self.name, self.port, self.gui_port = name, port, gui
        cfg = {
            "name": name,
            "tls": {"ca": PKI + "/ca.pem", "cert": "%s/%s.pem" % (PKI, name), "key": "%s/%s-key.pem" % (PKI, name)},
            "api": {"listen": "127.0.0.1:%d" % port},
            "keys": {"bits": 256, "rotate": rotate},
            "tunnels": tunnels or {"mode": "static"},
            "switches": [{
                "name": sw.name, "address": "127.0.0.1:%d" % sw.port, "device_id": sw.device_id,
                "json": sw.dir + "/industrial_aes.json", "p4info": sw.dir + "/industrial_aes.p4info.txtpb",
                "commands": os.path.join(REPO, "testbed", sw.name, "commands.txt"),
            } for sw in switches],
        }
        if peer:
            cfg["peer"] = {"name": peer[0], "url": "https://127.0.0.1:%d" % peer[1]}
        if gui:
            cfg["gui"] = {"listen": "127.0.0.1:%d" % gui, "user": "admin", "password_file": GUI_PASSWORD}
        self.config = os.path.join(WORK, name + ".json")       # YAML is a superset of JSON
        with open(self.config, "w") as f:
            json.dump(cfg, f)
        self.log = os.path.join(WORK, name + ".controller.log")
        self.start()

    def start(self):
        self.proc = subprocess.Popen(["p4ics-controller", "-config", self.config],
                                     stdout=open(self.log, "a"), stderr=subprocess.STDOUT)

    def stop(self):
        self.proc.terminate()
        self.proc.wait()

    def api(self, method, path, body=None, cert="admin", ca=PKI, timeout=30):
        ctx = ssl.create_default_context(cafile=PKI + "/ca.pem")
        if cert:
            ctx.load_cert_chain("%s/%s.pem" % (ca, cert), "%s/%s-key.pem" % (ca, cert))
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=timeout)
        conn.request(method, path, body=json.dumps(body) if body is not None else None)
        r = conn.getresponse()
        data = r.read()
        return r.status, (json.loads(data) if data.startswith((b"{", b"[")) else data)

    def gui(self, path, form=None, auth=("admin", None)):
        """GET path on the web GUI, or POST form to it: status, redirect location, body."""
        headers = {}
        if auth:
            user, pw = auth[0], auth[1] or open(GUI_PASSWORD).read().strip()
            headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn = http.client.HTTPConnection("127.0.0.1", self.gui_port, timeout=30)
        conn.request("GET" if form is None else "POST", path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read().decode()
        return r.status, urllib.parse.unquote_plus(r.getheader("Location") or ""), data

    def gui_post(self, path, **form):
        """Submit a GUI form, with the token of its pages; returns the redirect location."""
        form["csrf"] = re.search(r"name='csrf' value='([0-9a-f]+)'", self.gui("/p4ics")[2]).group(1)
        return self.gui(path, form)[1]

    def gui_tables(self, switch):
        return {t["name"]: t for t in json.loads(self.gui("/getRules?switch=" + switch)[2])}

    def status(self):
        code, st = self.api("GET", "/status")
        if code != 200:
            raise ValueError(st)
        return st

    def ready(self, n=None):
        st = self.status()
        sws = st["switches"]
        return st if all(s["ready"] for s in sws) and st["rotation"] >= 1 and (n is None or len(sws) == n) else None

    def rekey(self):
        return self.api("POST", "/rekey?wait=1")

    def events(self):
        return {s["name"]: s.get("events", {}) for s in self.status()["switches"]}

    def tail(self, n=15):
        with open(self.log) as f:
            return "".join(f.readlines()[-n:])


def same_key(c1, c2):
    a, b = c1.status(), c2.status()
    return a["phase"] == b["phase"] and a["rotation"] == b["rotation"] and a["keys"][a["phase"]] == b["keys"][b["phase"]]


def events_of(*ctls):
    out = {}
    for c in ctls:
        out.update(c.events())
    return out


def delta(after, before, key):
    return {sw: after[sw].get(key, 0) - before[sw].get(key, 0) for sw in after}


def setup():
    sh("rm -rf %s && mkdir -p %s" % (WORK, WORK))
    build_switch(os.path.join(REPO, "testbed", "s1"), os.path.join(WORK, "s1"))
    build_switch(os.path.join(REPO, "testbed", "s2"), os.path.join(WORK, "s2"))
    sh("bash %s/controller/pki.sh %s s1=127.0.0.1 s2=127.0.0.1 c1=127.0.0.1 c2=127.0.0.1 c9=127.0.0.1 admin"
       % (REPO, PKI))
    sh("bash %s/controller/pki.sh %s/rogue admin" % (REPO, WORK))      # another CA
    with open(GUI_PASSWORD, "w") as f:
        f.write(base64.b64encode(os.urandom(12)).decode() + "\n")

    for n in ("client", "server"):
        sh("ip netns del %s 2>/dev/null || true; ip netns add %s; ip -n %s link set lo up" % (n, n, n))
    for a, b in (("c0", "c0s"), ("b1", "b2"), ("sv0", "sv0s")):
        sh("ip link add %s type veth peer name %s" % (a, b))
    sh("ip link set c0 netns client && ip link set sv0 netns server")
    for dev in ("c0s", "b1", "b2", "sv0s"):
        sh("ip link set %s up" % dev)
    sh("ip -n client link set c0 address 00:00:0a:00:01:01 up")
    sh("ip -n client addr add %s/24 dev c0" % CLIENT)
    # OTHER gets the MAC address s1's commands.txt forwards it to
    sh("ip -n client link add mv0 link c0 type macvlan mode private")
    sh("ip -n client link set mv0 address 00:00:0a:00:02:01 up")
    sh("ip -n client addr add %s/24 dev mv0" % OTHER)
    for conf in ("all", "default", "c0", "mv0"):
        sh(ns("client", "sysctl -qw net.ipv4.conf.%s.rp_filter=0" % conf))
    sh("ip -n client route add default via 195.11.14.1 dev c0")
    sh("ip -n client neigh add 195.11.14.1 lladdr 00:00:00:00:00:01 dev c0")
    sh("ip -n server link set sv0 address 00:00:0a:00:01:02 up")
    sh("ip -n server addr add %s/24 dev sv0" % SERVER)
    sh("ip -n server route add default via 200.1.1.1")
    sh("ip -n server neigh add 200.1.1.1 lladdr 00:00:00:00:00:04 dev sv0")
    for n, dev in (("client", "c0"), ("server", "sv0")):
        sh(ns(n, "ethtool -K %s tx off >/dev/null" % dev))
    server = subprocess.Popen(ns("server", "python3 %s server %s 502" % (ECHO, SERVER)), shell=True)
    s1 = GrpcSwitch("s1", [(1, "c0s"), (2, "b1")], 1, 50051)
    s2 = GrpcSwitch("s2", [(1, "sv0s"), (2, "b2")], 2, 50052)
    return s1, s2, server


def p4runtime_capabilities(port, cert=None, ca=PKI):
    """Can a client with this certificate (None: no certificate) use the switch?"""
    root = open(PKI + "/ca.pem", "rb").read()
    if cert:
        creds = grpc.ssl_channel_credentials(root, open("%s/%s-key.pem" % (ca, cert), "rb").read(),
                                             open("%s/%s.pem" % (ca, cert), "rb").read())
    else:
        creds = grpc.ssl_channel_credentials(root)
    opts = (("grpc.ssl_target_name_override", "s1"),)
    with grpc.secure_channel("127.0.0.1:%d" % port, creds, opts) as ch:
        try:
            p4runtime_pb2_grpc.P4RuntimeStub(ch).Capabilities(p4runtime_pb2.CapabilitiesRequest(), timeout=3)
            return True
        except grpc.RpcError:
            return False


def switch_keys(sw):
    """The set_key values of p4ics_keys, read from the switch over P4Runtime (hex)."""
    info = text_format.Parse(open(sw.dir + "/industrial_aes.p4info.txtpb").read(), p4info_pb2.P4Info(),
                             allow_unknown_field=True)
    table = next(t.preamble.id for t in info.tables if t.preamble.name.endswith(".p4ics_keys"))
    creds = grpc.ssl_channel_credentials(open(PKI + "/ca.pem", "rb").read(), open(PKI + "/admin-key.pem", "rb").read(),
                                         open(PKI + "/admin.pem", "rb").read())
    req = p4runtime_pb2.ReadRequest(device_id=sw.device_id, entities=[
        p4runtime_pb2.Entity(table_entry=p4runtime_pb2.TableEntry(table_id=table))])
    with grpc.secure_channel("127.0.0.1:%d" % sw.port, creds, (("grpc.ssl_target_name_override", sw.name),)) as ch:
        return sorted(p.value.hex() for r in p4runtime_pb2_grpc.P4RuntimeStub(ch).Read(req, timeout=5)
                      for e in r.entities for p in e.table_entry.action.action.params)


def gui_keys_hidden(c, switches):
    """The GUI shows the keys of the switches by the ids of /status, never by value."""
    before = [k for sw in switches for k in switch_keys(sw)]
    st = c.status()
    pages = "".join(c.gui(p)[2] for p in ["/", "/p4ics", "/api/status"] +
                    ["/getRules?switch=" + sw.name for sw in switches])
    ids = [p for sw in switches for e in c.gui_tables(sw.name)["p4ics_keys"]["entries"] for p in e["params"]]
    after = [k for sw in switches for k in switch_keys(sw)]
    if before != after:
        return None         # a rotation in between: try again
    return before and "key id " + st["keys"][st["phase"]] in ids and \
        not any(k.lstrip("0")[:16] in pages for k in before)


def wire_check(name, frames, phases=None):
    """Industrial payloads on the s1-s2 link: all protected, sender ids by direction."""
    bad, seen = [], set()
    for f in frames:
        p = ref.parse(f)
        if p.data_len <= 0:
            continue
        if p.ihl != 13:
            bad.append("plaintext")
            continue
        spi = ref.protected_fields(f)[1]
        sender = 1 if p.dst == socket.inet_aton(SERVER) else 2
        if spi & 0x7FFFFFFF != sender:
            bad.append("spi %#x" % spi)
        seen.add(ref.key_phase(spi))
    ok = frames and not bad and (phases is None or seen == set(phases))
    check(name, ok, "%d frames, phases %s, %s" % (len(frames), sorted(seen), bad[:3]))


def static_checks(s1, s2):
    c1 = Controller("c1", 3333, [s1, s2], rotate="3s", gui=8080)
    try:
        st = wait_for(lambda: c1.ready(2), 60)
        check("controller configures both switches and installs a first key", st,
              st and "rotation %d, keys %s" % (st["rotation"], st["keys"]))
        cap = Capture("b1")
        r = echo(count=50)
        check("traffic through the switches (50 Modbus-framed echoes)", r["ok"] == 50 and not r["error"], r)
        wire_check("s1-s2 link: every payload protected, SPI = sender id", cap.stop())

        # Hitless rotation: 10 rekeys under traffic, plus the periodic ones.
        before, rot = c1.events(), c1.status()["rotation"]
        cap = Capture("b1")
        traffic = echo_bg(duration=8)
        codes = []
        for _ in range(10):
            time.sleep(0.5)
            codes.append(c1.rekey()[0])
        r = echo_result(traffic)
        frames = cap.stop()
        after, st = c1.events(), c1.status()
        check("10 rekeys under traffic: all done", codes == [200] * 10 and st["rotation"] >= rot + 10,
              "%s, rotation %d -> %d" % (codes, rot, st["rotation"]))
        check("... no frame rejected, no replay, no TCP retransmission",
              r["ok"] > 100 and hitless(r) and
              set(delta(after, before, "rejected").values()) == {0} and
              set(delta(after, before, "replay").values()) == {0},
              "%s, rejected %s" % (r, delta(after, before, "rejected")))
        wire_check("... both key phases seen on the wire", frames, phases=(0, 1))
        rot = c1.status()["rotation"]
        time.sleep(7)
        check("periodic rotation (keys.rotate 3s)", c1.status()["rotation"] >= rot + 2)

        # API and switch access need a certificate of the CA.
        check("API: admin certificate accepted", c1.api("GET", "/status")[0] == 200)
        code, _ = c1.api("POST", "/rekey", cert="c2")
        check("API: certificate of a non-admin name refused (403)", code == 403, code)
        for desc, kw in (("without a certificate", {"cert": None}), ("with another CA's certificate",
                                                                    {"ca": WORK + "/rogue"})):
            try:
                c1.api("GET", "/status", **kw)
                ok = False
            except (ssl.SSLError, ConnectionError, OSError):
                ok = True
            check("API: client %s refused" % desc, ok)
        check("switch P4Runtime: CA certificate accepted", p4runtime_capabilities(s1.port, "admin"))
        check("switch P4Runtime: client without a certificate refused", not p4runtime_capabilities(s1.port))
        check("switch P4Runtime: another CA's certificate refused",
              not p4runtime_capabilities(s1.port, "admin", WORK + "/rogue"))

        # Web GUI: basic authentication, pages, entries, rotation.
        codes = [c1.gui("/", auth=None)[0], c1.gui("/", auth=("admin", "wrong"))[0], c1.gui("/api/status", auth=None)[0]]
        check("GUI: refused without the right password (401)", codes == [401] * 3, codes)
        code, _, page = c1.gui("/")
        check("GUI: switches page, both switches ready, their tables read back",
              code == 200 and page.count("badge bg-success'>ready<") == 2 and "200.1.1.7/32" in page and
              "195.11.14.5/32" in page, code)
        check("GUI: keys shown by the ids of /status, never by value", wait_for(lambda: gui_keys_hidden(c1, [s1, s2]), 15))
        loc = c1.gui_post("/rules/add", switch="s1", table="ipv4_lpm", action="ipv4_forward",
                          match="10.9.0.0/16", params="00:00:0a:00:09:01 1")
        added = [e for e in c1.gui_tables("s1")["ipv4_lpm"]["entries"] if e["match"] == ["10.9.0.0/16"]]
        check("GUI: entry added to the ipv4_lpm of s1, read back from the switch",
              loc.startswith("/?ok=") and len(added) == 1 and added[0]["params"] == ["00:00:0a:00:09:01", "0x1"],
              (loc, added))
        loc = c1.gui_post("/rules/delete", switch="s1", table="ipv4_lpm", ref=added[0]["ref"] if added else "")
        left = [e for e in c1.gui_tables("s1")["ipv4_lpm"]["entries"] if e["match"] == ["10.9.0.0/16"]]
        check("GUI: ... and deleted", loc.startswith("/?ok=") and not left, loc)
        loc = c1.gui_post("/rules/add", switch="s1", table="p4ics_keys", action="set_key", match="0", params="0x1")
        check("GUI: p4ics_keys cannot be changed by hand", "managed by the controller" in loc, loc)
        rot = c1.status()["rotation"]
        loc = c1.gui_post("/rekey")
        r = echo(count=20)
        check("GUI: key rotation, traffic still flowing",
              loc.startswith("/p4ics?ok=key rotated") and c1.status()["rotation"] > rot and r["ok"] == 20, (loc, r))

        # A second controller cannot take over a switch.
        c9 = Controller("c9", 3339, [s1])
        time.sleep(5)
        st9 = c9.status()
        r = echo(count=20)
        check("second controller for s1 does not become primary; c1 keeps working",
              not st9["switches"][0]["ready"] and c1.ready(2) and r["ok"] == 20, (st9["switches"], r))
        c9.stop()

        # Switch restart: new pipeline, new key; frames captured before are rejected.
        cap = Capture("b1")
        echo(count=5)
        old = [f for f in cap.stop() if ref.parse(f).dst == socket.inet_aton(SERVER) and ref.parse(f).data_len > 0]
        rot = c1.status()["rotation"]
        s2.stop()
        t0 = time.time()
        s2.start()
        st = wait_for(lambda: c1.ready(2) and c1.status()["rotation"] > rot and c1.status(), 60)
        r = echo(count=20, timeout=10)
        check("s2 restarted: reconfigured and rekeyed, traffic back", st and r["ok"] == 20,
              "%.1fs, %s" % (time.time() - t0, r))
        before = c1.events()
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind(("b1", 0))
        for f in old:
            sock.send(f)
        time.sleep(0.5)
        after = c1.events()
        # (>=: bmv2 also reads frames sent out of its own port b1, and sends them on)
        check("frames captured before the restart are rejected by s2",
              old and delta(after, before, "rejected")["s2"] >= len(old) and
              delta(after, before, "unprotected")["s2"] == 0,
              "%d sent, %s" % (len(old), delta(after, before, "rejected")))

        # Controller restart: everything reinstalled.
        c1.stop()
        c1.start()
        st = wait_for(lambda: c1.ready(2), 60)
        r = echo(count=20, timeout=10)
        check("controller restarted: switches reconfigured, traffic back", st and r["ok"] == 20, r)
        check("... and its GUI back", wait_for(lambda: c1.gui("/healthz")[0] == 200, 30))
    finally:
        c1.stop()
        if not all(results):
            print(c1.tail())


def on_demand_checks(s1, s2):
    tunnels = {"mode": "on-demand", "allow": [{"a": CLIENT + "/32", "b": SERVER + "/32"}]}
    c1 = Controller("c1", 3333, [s1, s2], tunnels=tunnels, gui=8080)
    try:
        wait_for(lambda: c1.ready(2), 60)
        before = c1.events()
        r = echo(count=20, timeout=5)
        st = c1.status()
        check("on demand: allowed pair gets a tunnel when traffic starts",
              r["ok"] == 20 and st["tunnels"] == ["%s<->%s" % (CLIENT, SERVER)] and
              delta(c1.events(), before, "waiting")["s1"] >= 1, (r, st["tunnels"]))
        before = c1.events()
        r = echo(src=OTHER, count=1, timeout=3)
        check("on demand: pair outside tunnels.allow keeps waiting (fail closed)",
              r["ok"] == 0 and r["error"] and delta(c1.events(), before, "waiting")["s1"] >= 1 and
              len(c1.status()["tunnels"]) == 1, r)
        code, _ = c1.api("POST", "/tunnels", {"a": OTHER, "b": SERVER})
        r = echo(src=OTHER, count=10, timeout=5)
        check("on demand: tunnel added through the API", code == 200 and r["ok"] == 10, (code, r))
        code, _ = c1.api("DELETE", "/tunnels?a=%s&b=%s" % (OTHER, SERVER))
        r = echo(src=OTHER, count=1, timeout=3)
        check("on demand: tunnel deleted through the API", code == 200 and r["ok"] == 0, (code, r))
        loc = c1.gui_post("/tunnels/add", a=OTHER, b=SERVER)
        r = echo(src=OTHER, count=10, timeout=5)
        check("on demand: tunnel added from the GUI", loc.startswith("/p4ics?ok=") and r["ok"] == 10, (loc, r))
        loc = c1.gui_post("/tunnels/delete", a=OTHER, b=SERVER)
        r = echo(src=OTHER, count=1, timeout=3)
        check("on demand: tunnel deleted from the GUI", loc.startswith("/p4ics?ok=") and r["ok"] == 0, (loc, r))
        before = c1.events()
        traffic = echo_bg(duration=4)
        codes = []
        for _ in range(4):
            time.sleep(0.5)
            codes.append(c1.rekey()[0])
        r = echo_result(traffic)
        check("on demand: rekeys under traffic are hitless",
              codes == [200] * 4 and r["ok"] > 50 and hitless(r) and
              set(delta(c1.events(), before, "rejected").values()) == {0}, r)
    finally:
        c1.stop()
        if not all(results):
            print(c1.tail())


def peer_checks(s1, s2):
    c1 = Controller("c1", 3333, [s1], peer=("c2", 3334))
    c2 = Controller("c2", 3334, [s2], peer=("c1", 3333), gui=8081)
    try:
        ok = wait_for(lambda: c1.ready(1) and c2.ready(1), 60)
        st1, st2 = c1.status(), c2.status()
        check("two controllers (c1 leader: s1, c2: s2) agree on the key by Diffie-Hellman",
              ok and st1["role"] == "leader" and st2["role"] == "follower" and
              st1["keys"][st1["phase"]] == st2["keys"][st2["phase"]] != "" and st1["phase"] == st2["phase"],
              (st1["keys"], st2["keys"]))
        r = echo(count=20)
        check("... traffic through the two switches", r["ok"] == 20, r)
        before = events_of(c1, c2)
        traffic = echo_bg(duration=5)
        codes = []
        for c in (c1, c2, c1, c2):
            time.sleep(0.6)
            codes.append(c.api("POST", "/rekey")[0])
        time.sleep(1)
        r = echo_result(traffic)
        after = events_of(c1, c2)
        st1, st2 = c1.status(), c2.status()
        check("... rekeys asked to either controller, under traffic: same key, hitless",
              codes == [200] * 4 and st1["keys"] == st2["keys"] and st1["rotation"] == st2["rotation"] >= 3 and
              r["ok"] > 50 and hitless(r) and set(delta(after, before, "rejected").values()) == {0},
              (codes, st1["rotation"], st2["rotation"], r))
        rot = st1["rotation"]
        loc = c2.gui_post("/rekey")
        check("... rotation from the GUI of the follower (asks the leader)",
              loc.startswith("/p4ics?ok=key rotated") and c1.status()["rotation"] > rot and same_key(c1, c2), loc)
        rot = c1.status()["rotation"]
        s2.stop()
        s2.start()
        ok = wait_for(lambda: c2.ready(1) and c1.status()["rotation"] > rot, 60)
        r = echo(count=20, timeout=10)
        check("... s2 restarted: c2 asks the leader for a new key, traffic back",
              ok and r["ok"] == 20 and same_key(c1, c2), r)
        rot = c2.status()["rotation"]
        c1.stop()
        c1.start()
        ok = wait_for(lambda: c1.ready(1) and c1.status()["rotation"] > rot and same_key(c1, c2), 60)
        r = echo(count=20, timeout=10)
        check("... leader restarted: continues the rotations with c2, traffic back", ok and r["ok"] == 20,
              (c1.status()["rotation"], rot, r))
    finally:
        c1.stop()
        c2.stop()
        if not all(results):
            print(c1.tail())
            print(c2.tail())


def main():
    s1, s2, server = setup()
    try:
        static_checks(s1, s2)
        on_demand_checks(s1, s2)
        peer_checks(s1, s2)
    finally:
        server.terminate()
        s1.stop()
        s2.stop()
    print("%d/%d controller checks passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
