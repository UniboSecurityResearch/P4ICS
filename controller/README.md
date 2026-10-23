# P4ICS controller (optional)

A P4Runtime control plane for P4ICS switches, as described in §9.1 of the
paper. It is optional: the testbed in [`testbed/`](../testbed) runs
`simple_switch` and is configured with `simple_switch_CLI`, and keeps working
without the controller.

The controller:

* connects to every switch (`simple_switch_grpc`) over **gRPC with mutual
  TLS**, becomes its primary client and pushes the pipeline (bmv2 JSON +
  P4Info);
* installs the tables of the switch's own `commands.txt`, the same file the
  CLI mode uses, translated into P4Runtime entries;
* gives each switch its sender id and counter base, and **rotates the key
  without dropping traffic**: periodically, on request, and whenever a switch
  (re)connects;
* activates tunnels **statically** (the per-port `ics_sec` entries of
  `commands.txt`) or **on demand**, per endpoint pair, when the switch reports
  traffic that has no tunnel yet;
* with a second controller managing other switches, agrees on every key with
  an ephemeral **Diffie–Hellman** exchange (X25519 + HKDF-SHA256).

It is written in Go on top of
[UniboSecurityResearch/p4runtime-go-client](https://github.com/UniboSecurityResearch/p4runtime-go-client)
(stream channel, arbitration, reconnection, digests, reads and writes).

## Build

```bash
cd controller
go build -o p4ics-controller ./cmd/p4ics-controller   # Go >= 1.24
# or the image used by the Kathara lab, from the repository root:
docker build -f Dockerfile/controller.Dockerfile -t loriringhio97/p4ics-controller .
```

## Run

1. Certificates: one CA, one certificate per switch, controller and API
   client. `pki.sh` creates them (EC P-256; the common name is the name):

   ```bash
   ./pki.sh pki s1=100.0.1.1 s2=100.0.1.2 c1=100.0.1.11 admin
   ```

2. Compile the switch program with its P4Info, and start the switch with no
   program and a mutual-TLS P4Runtime server:

   ```bash
   p4c-bm2-ss --emit-externs --p4runtime-files industrial_aes.p4info.txtpb -o industrial_aes.json industrial_aes.p4
   simple_switch_grpc -i 1@eth0 -i 2@eth1 --device-id 1 --no-p4 -- \
       --load-modules=extern_lib/definition.so --grpc-server-addr 100.0.1.1:50051 \
       --grpc-server-ssl --grpc-server-cacert pki/ca.pem --grpc-server-cert pki/s1.pem \
       --grpc-server-key pki/s1-key.pem --grpc-server-with-client-auth
   ```

3. Start the controller: `p4ics-controller -config c1.yml` (`-check` only
   validates the configuration, `-v` logs more).

### Kathara lab

`lab/make_lab.sh` builds a copy of the testbed in which s1 and s2 run
`simple_switch_grpc` on a management LAN (100.0.1.0/24) with the controller:

```bash
controller/lab/make_lab.sh /tmp/p4ics-lab          # c1 manages s1 and s2
controller/lab/make_lab.sh --peer /tmp/p4ics-lab   # c1 manages s1, c2 manages s2
cd /tmp/p4ics-lab && kathara lstart
kathara exec c1 -- p4ics-api /status
kathara exec c1 -- p4ics-api POST '/rekey?wait=1'
kathara exec modbusclient -- python3 /modbus_client.py --rw
```

c1 creates the certificates of each lab run in `shared/p4ics/pki` (removed
at `kathara lclean`). Each switch publishes its program, P4Info and
`commands.txt` in `shared/p4ics/pipeline`. The logs are in `shared/c1.log`
and `shared/sN.log`. The lab configurations are in `lab/single/` and
`lab/peer/`.

## Configuration

```yaml
name: c1                       # common name of this controller's certificate
tls:                           # mutual TLS with switches, peer and API clients
  ca: pki/ca.pem
  cert: pki/c1.pem
  key: pki/c1-key.pem
api:
  listen: 100.0.1.11:3333      # HTTPS API; omit to disable (required with a peer)
  admins: [admin]              # common names allowed to use it (default: admin)
keys:
  bits: 256                    # 128, 160, 192, 224 or 256 (default 256)
  rotate: 10m                  # periodic rotation; 0 or omitted: none
tunnels:
  mode: static                 # or on-demand
  allow:                       # on-demand: pairs that may get a tunnel
    - {a: 195.11.14.0/24, b: 200.1.1.0/24}
switches:
  - name: s1                   # also the name expected in its certificate (server_name)
    address: 100.0.1.1:50051
    device_id: 1
    json: s1/industrial_aes.json
    p4info: s1/industrial_aes.p4info.txtpb
    commands: s1/commands.txt  # simple_switch_CLI table commands
    # spi: 1                   # default: set_local_sa in commands.txt
peer:                          # optional second controller
  name: c2
  url: https://100.0.1.12:3333
```

## How it works

**Switch configuration.** For each switch the controller pushes the
pipeline, then installs the `table_add`/`table_set_default` lines of
`commands.txt`. It owns `p4ics_local` (sender id, key phase, counter base)
and `p4ics_keys` (one key per phase). Configuration is in tables because
bmv2's P4Runtime server cannot read or write registers. simple_switch_CLI
priorities (lower wins) become P4Runtime priorities (higher wins).

**Keys.** A rotation installs the new key in the idle phase of every switch,
then switches every sender to that phase. Receivers pick the key by the phase
bit of the SPI, so frames in flight still verify, and the old key stays
installed until the next rotation. The counter base is the time in
nanoseconds since 2020, so counters never go back. A switch that
(re)connects is reprogrammed. It gets no key until the rotation that follows,
so it never accepts frames sent before its restart. When the controller
itself restarts, it reprograms its switches the same way. Keys live only in
the controller's memory and in the switches; the API shows a key id (a hash
prefix).

**Tunnels on demand.** With `tunnels.mode: on-demand` the per-port `ics_sec`
entries of `commands.txt` are not installed. They only tell the controller
which ports face the tunnel (`cipher`) and which face the hosts
(`decipher`). The default action of `ics_sec` becomes `request_tunnel`: the
switch drops the first segment of a flow without a tunnel and sends a
`p4ics_tunnel_request_t` digest. If `tunnels.allow` permits the pair, the
controller installs the entries of both directions on every switch, using
`ipv4_lpm` to find the ports, and TCP retransmits the segment. Other pairs
stay blocked (fail closed).

**Two controllers.** Each controller manages its own switches; the one whose
name sorts first leads the rotations. For every rotation, the leader sends an
ephemeral X25519 public value (`POST /peer/prepare`). The follower answers
with its own, derives the key with HKDF-SHA256 (bound to the rotation number,
phase and both public values) and installs it in the idle phase. The leader
derives the same key and installs it, then both activate it
(`POST /peer/activate`). The follower forwards rotation requests to the
leader (`POST /peer/rekey`), for example when one of its switches restarts.
The controllers also forward on-demand tunnels to each other.

## API

HTTPS with client certificates of the CA. `admins` may use everything except
`/peer/*`, which only the peer may use. The peer may also read `/status`.

| Request | |
|---|---|
| `GET /status` | phase, rotation, key ids, tunnels, switches (ready, SPI, `p4ics_events`) |
| `POST /rekey` | queue a rotation; `?wait=1` returns after it |
| `GET /tunnels` | on-demand tunnels |
| `POST /tunnels` `{"a": "...", "b": "..."}` | add one (bypasses `allow`) |
| `DELETE /tunnels?a=...&b=...` | remove one |

`lab/api.sh` (`p4ics-api` in the image) wraps `curl` with the lab's admin
certificate.

## Limitations

* All switches of a controller, and of its peer, share one key per phase. A
  peer controller is limited to one (two controllers in total).
* (Re)programming a switch resets its tables and registers. When the
  controller restarts, traffic stops briefly.
* The client library checks the connection every 5 s, so a restarted switch
  is reprogrammed about 5 s after it comes back.
* The client library pins the P4Runtime protobufs at 1.4.0-rc.5. Newer
  P4Info fields written by p4c (such as `initial_default_action`) are
  ignored.
* The `simple_switch_grpc` of the testbed image has no Thrift server, so the
  `simple_switch_CLI` scripts (`rotate_keys.sh`, `change_key.sh`,
  `retrieve_info.sh`) do not apply in controller mode; use the API.
