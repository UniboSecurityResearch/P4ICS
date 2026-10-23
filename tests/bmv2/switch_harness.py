"""Drive a real bmv2 simple_switch running a P4ICS program from Python.

Runs inside the loriringhio97/p4 image (see run_interop.sh). The switch gets
two ports backed by veth pairs:

    port 1: p1s <-> p1h   (towards the "client" side, 195.11.14.0/24)
    port 2: p2s <-> p2h   (towards the "server" side, 200.1.1.0/24)

ics_sec is configured like testbed/s1: cipher on egress port 2, decipher on
egress port 1. Frames are injected/captured with AF_PACKET sockets on the
host-side ends.
"""

import os
import re
import select
import shutil
import socket
import struct
import subprocess
import time

ETH_P_ALL = 0x0003


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw).stdout


def build_switch(p4_dir, work_dir):
    """Compile a P4ICS switch directory (industrial_aes.p4 + extern_lib)."""
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    shutil.copytree(p4_dir, work_dir)
    sh("p4c-bm2-ss --emit-externs -o industrial_aes.json industrial_aes.p4", cwd=work_dir)
    sh("make -s", cwd=os.path.join(work_dir, "extern_lib"))
    return work_dir


def make_veth(host, sw):
    sh("ip link del %s 2>/dev/null || true" % host)
    sh("ip link add %s type veth peer name %s" % (host, sw))
    for dev in (host, sw):
        sh("sysctl -qw net.ipv6.conf.%s.disable_ipv6=1 2>/dev/null || true" % dev)
        sh("ip link set %s up" % dev)


class Switch:
    def __init__(self, work_dir, ports, thrift_port=9090, log=None):
        self.thrift_port = thrift_port
        device_id = thrift_port - 9090      # distinct IPC notification sockets
        iface_args = " ".join("-i %d@%s" % (n, dev) for n, dev in ports)
        out = open(log, "w") if log else subprocess.DEVNULL
        self.proc = subprocess.Popen(
            "exec simple_switch %s --thrift-port %d --device-id %d industrial_aes.json "
            "-- --load-modules=extern_lib/definition.so" % (iface_args, thrift_port, device_id),
            shell=True, cwd=work_dir, stdout=out, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                self.cli("help")
                return
            except subprocess.CalledProcessError:
                time.sleep(0.2)
        raise RuntimeError("simple_switch did not come up")

    def cli(self, commands):
        return subprocess.run(["simple_switch_CLI", "--thrift-port", str(self.thrift_port)],
                              input=commands, text=True, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

    def install_key(self, phase, words):
        """Key of one key phase (p4ics_keys), from the 8 register-style words."""
        if not hasattr(self, "_key_handles"):
            self._key_handles = {}
        hexkey = "0x" + "".join("%08x" % w for w in words)
        if phase in self._key_handles:
            self.cli("table_modify p4ics_keys set_key %d => %s\n" % (self._key_handles[phase], hexkey))
        else:
            out = self.cli("table_add p4ics_keys set_key %d => %s\n" % (phase, hexkey))
            self._key_handles[phase] = int(re.search(r"handle (\d+)", out).group(1))

    def set_keys(self, words):
        self.install_key(0, words)

    def set_local(self, spi, phase, epoch):
        """This switch as a sender (p4ics_local): SPI, key phase, counter base."""
        self.cli("table_set_default p4ics_local set_local_sa %d %d %d\n" % (spi, phase, epoch))

    def register_read(self, name, index):
        out = self.cli("register_read %s %d\n" % (name, index))
        return int(re.search(r"%s\[%d\]\s*=\s*(\d+)" % (re.escape(name), index), out).group(1))

    def counter_read(self, name, index):
        out = self.cli("counter_read %s %d\n" % (name, index))
        return int(re.search(r"(\d+) packets", out).group(1))

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


class Port:
    """AF_PACKET endpoint on the host side of a veth pair."""

    def __init__(self, dev):
        self.dev = dev
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((dev, 0))

    def send(self, frame):
        self.sock.send(frame)

    def drain(self):
        while select.select([self.sock], [], [], 0)[0]:
            self.sock.recv(65535)

    def recv_ics(self, timeout=3.0, ports=(502, 1883, 44818, 20000)):
        """Return the next incoming IPv4/TCP frame to/from an industrial port, or None."""
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0 or not select.select([self.sock], [], [], left)[0]:
                return None
            frame, addr = self.sock.recvfrom(65535)
            if addr[2] == socket.PACKET_OUTGOING or frame[12:14] != b"\x08\x00":
                continue
            l4 = 14 + 4 * (frame[14] & 0x0F)
            if frame[23] != 6 or len(frame) < l4 + 4:
                continue
            sport, dport = struct.unpack_from("!HH", frame, l4)
            if sport in ports or dport in ports:
                return frame


def through(src, dst, frame, timeout=3.0):
    dst.drain()
    src.send(frame)
    return dst.recv_ics(timeout)
