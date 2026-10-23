# Working on P4ICS

## Where things are

| Path | Content |
|---|---|
| `testbed/s1/industrial_aes.p4` | the switch program (source of truth; s2 is a copy) |
| `testbed/s1/extern_lib/` | the C++ externs: payload gather/scatter and crypto |
| `testbed/s1/commands.txt`, `testbed/s2/commands.txt` | per-switch tables: routes, sender id, `ics_sec` |
| `testbed/s1/p4ics_setup.sh` | keys and security association through `simple_switch_CLI` |
| `docs/WIRE_FORMAT.md` | the protected packet format |
| `tests/reference/p4ics_ref.py` | the same format as executable Python, used by every test |
| `controller/` | the optional P4Runtime controller (Go) |
| `Dockerfile/` | images of the testbed devices and of the controller |

## Changing the switch

1. Edit `testbed/s1/industrial_aes.p4` and `testbed/s1/extern_lib/`.
2. Copy them to s2: `testbed/sync_switches.sh` (`--check` only compares).
3. Compile with the testbed toolchain:

   ```bash
   docker run --rm -v "$PWD/testbed/s1:/src:ro" loriringhio97/p4 sh -c \
       'cp -r /src /tmp/s1 && cd /tmp/s1 && p4c-bm2-ss --emit-externs -o x.json industrial_aes.p4 && make -C extern_lib'
   ```

4. If tables, actions, counters or digests changed, regenerate the P4Info the
   controller's unit tests use:

   ```bash
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/p4ics" -w /tmp loriringhio97/p4 p4c-bm2-ss --emit-externs \
       --p4runtime-files /p4ics/controller/internal/p4rt/testdata/industrial_aes.p4info.txtpb \
       -o /tmp/x.json /p4ics/testbed/s1/industrial_aes.p4
   ```

A change to the bytes on the wire goes to three places that must agree: the
extern (`definition.cpp`), `docs/WIRE_FORMAT.md`, and
`tests/reference/p4ics_ref.py`. `tests/bmv2/interop.py` checks the first
against the last, byte for byte.

## Adding an industrial protocol

The switch recognises a protocol by its TCP port and keeps its header in
clear. To add one:

1. **Parser.** A header type with the protocol's fixed header, a `PROTO_*`
   constant, its port in `check_dst_port_tcp` and `check_src_port_tcp`, and a
   `proto_*`/`extract_*` state pair setting `hdr_len`.
2. **Externs.** Pass the new header to `p4ics_cipher` and `p4ics_decipher`
   (`declaration.p4`, the two calls in `industrial_aes.p4`, and
   `definition.cpp`: the extern signatures and `industrial_header()`), so that
   the tag binds it.
3. **Deparser and ingress.** Emit the header, and add it to the
   `isValid()` test in front of `ics_sec`.
4. **Reference and tests.** Add the port and header length to `PROTOCOLS` in
   `tests/reference/p4ics_ref.py`. The interop test then covers the new
   protocol.
5. **Testbed.** A client and a server (see `protocols/`), an image in
   `Dockerfile/`, devices in `testbed/lab.conf` with their `.startup` files,
   and routes in both `commands.txt`.

The parser handles TCP only: a UDP protocol such as BACnet/IP also needs a
UDP path through the parser, the externs and the wire format.

## Checks

CI (`.github/workflows/tests.yml`) runs these on every push. They run
locally with Docker. The commands come from the repository root:

| Command | Checks |
|---|---|
| `python3 tests/test_reference.py` | the reference: FIPS-197, RFC 4231 and RFC 5869 vectors, round trips, tag binding, replay window (needs `cryptography`) |
| `testbed/sync_switches.sh --check` | s1 and s2 run the same program |
| `tests/testbed/run_startup.sh` | switch start-up and shutdown scripts: keys, modes, rotation |
| `tests/bmv2/run_interop.sh` | the switch against the reference: all protocols and lengths, tampering, replays, key phases, on-demand entries |
| `tests/protocols/run_protocols.sh` | pymodbus, DNP3 and cpppo through two switches (build `loriringhio97/dnp3` first) |
| `cd controller && go test ./...` | controller units |
| `tests/controller/run_controller.sh` | the controller with two `simple_switch_grpc`: traffic, rekeying, restarts, on-demand tunnels, two controllers |

The bmv2 image of the tests is pinned by digest in the workflow (`P4_IMAGE`);
the scripts take the same variable.

## Releases

1. Tag the release on `main` (`git tag -a vX.Y.Z`) and push it.
2. Publish the images: `Dockerfile/publish.sh vX.Y.Z` (needs `docker login`
   and QEMU for arm64; see the script).
3. Publish a GitHub release from the tag: the Zenodo integration archives
   releases, not bare tags.

`v1.0.0` is the code at the time of the paper (wire format v1).
