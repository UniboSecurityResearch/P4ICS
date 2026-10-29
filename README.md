# P4ICS: P4 In-Network Security for Industrial Control Systems

[![Tests](https://github.com/UniboSecurityResearch/P4ICS/actions/workflows/tests.yml/badge.svg)](https://github.com/UniboSecurityResearch/P4ICS/actions/workflows/tests.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![DOI](https://zenodo.org/badge/763412444.svg)](https://doi.org/10.5281/zenodo.17190336)

Artifact of the paper **P4ICS: P4 In-Network Security for Industrial Control
Systems Networks** (Computer Networks, vol. 287, 2026,
[doi:10.1016/j.comnet.2026.112560](https://doi.org/10.1016/j.comnet.2026.112560)).

Industrial protocols such as Modbus, DNP3, EtherNet/IP and MQTT were designed
without security, and the PLCs and field devices that speak them can rarely be
upgraded. P4ICS moves confidentiality, integrity and replay protection into
P4-programmable switches. A switch at each edge of an untrusted segment
encrypts and authenticates the payload of every industrial message, and the
switch at the other end verifies it and delivers the original packet. The
endpoints do not change.

```
  Modbus / DNP3 / EtherNet/IP / MQTT                        Modbus / DNP3 / EtherNet/IP / MQTT
  clients ──── [ P4ICS switch ] ════ AES-CBC + HMAC-SHA256 ════ [ P4ICS switch ] ──── servers
                                     replay-protected
```

* **Per-message protection in the data plane.** The payload after the
  protocol header is encrypted with AES-CBC (128 to 256-bit keys). An
  HMAC-SHA256 tag binds it to its sender, flow and position
  (encrypt-then-MAC), and per-sender counters reject replays.
* **Protocol-aware parsing.** The switch recognises each protocol, keeps its
  header in clear and authenticated, and handles payloads of any length.
* **Two control planes.** `simple_switch_CLI` scripts with a fresh key for
  every run and key rotation without loss. An optional P4Runtime controller
  adds mutual TLS, on-demand tunnels and Diffie–Hellman key agreement.
* **A reproducible testbed** in [Kathara](https://www.kathara.org/), with
  real Modbus, DNP3, EtherNet/IP and MQTT stacks.

## Quick start

You need [Docker](https://docs.docker.com/get-docker/) and
[Kathara](https://www.kathara.org/). The images are on Docker Hub for amd64
and arm64.

```bash
git clone https://github.com/UniboSecurityResearch/P4ICS.git
cd P4ICS/testbed
kathara lstart --noterminals
kathara exec modbusclient -- python3 /modbus_client.py --rw      # Modbus write + read through P4ICS
./rotate_keys.sh                                                  # new key, no packet lost
kathara lclean
```

Wireshark runs in the lab: open http://localhost:3000 and capture on the
s1–s2 link to see the protected packets. [docs/TESTBED.md](docs/TESTBED.md)
covers the other protocols, the clients' options, keys and measurements.

## Documentation

| Document | Content |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | how the switch works: parser, tables, cipher/decipher, externs, security properties and limits |
| [docs/WIRE_FORMAT.md](docs/WIRE_FORMAT.md) | the protected packet format, keys, crypto, counters |
| [docs/TESTBED.md](docs/TESTBED.md) | the Kathara lab: topology, devices, clients, keys, measurements, images |
| [controller/README.md](controller/README.md) | the optional P4Runtime controller |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | changing the switch, adding a protocol, checks, releases |

## Repository layout

| Path | Content |
|---|---|
| [`testbed/`](testbed) | the Kathara lab: P4ICS switches (`s1/`, `s2/`: P4 program, C++ externs, tables), Modbus and MQTT clients and servers, key scripts |
| [`controller/`](controller) | optional P4Runtime controller (Go, on [p4runtime-go-client](https://github.com/UniboSecurityResearch/p4runtime-go-client)) with a web GUI, and its Kathara lab |
| [`protocols/`](protocols) | industrial protocol clients and servers to build testbed images from: DNP3, EtherNet/IP, BACnet, IEC 61850, Profinet |
| [`Dockerfile/`](Dockerfile) | images of the testbed devices and of the controller |
| [`docs/`](docs) | documentation |
| [`tests/`](tests) | executable wire-format reference and the checks run in CI |
| [`results/`](results) | data and plots of the papers' evaluations, run on a physical testbed with Revolution Pi devices (see the papers) |
| [`sota/`](sota) | comparison with in-network AES on scrambled lookup tables (Chen, SPIN 2020) |
| [`modbus_tep_case_study/`](modbus_tep_case_study) | Modbus monitoring case study on the Tennessee Eastman Process (see the paper) |

## Versions

* **v1.0.0**: the code at the time of the paper
  ([Zenodo](https://doi.org/10.5281/zenodo.17190336)).
* **v2.0.0**: protected format v2 (encrypt-then-MAC, anti-replay, payloads of
  any length), key rotation without loss, on-demand tunnels, the P4Runtime
  controller, DNP3 and EtherNet/IP in the testbed. See
  [WIRE_FORMAT §8](docs/WIRE_FORMAT.md#8-changes-from-previous-versions).
* **v2.1.0**: web GUI of the P4Runtime controller
  ([controller/README.md](controller/README.md#web-gui)), in the image
  `loriringhio97/p4ics-controller:v2.1.0`. Same wire format as v2.0.0.

## Citation

```bibtex
@article{p4ics,
  title   = {{P4ICS}: {P4} in-network security for Industrial Control Systems networks},
  author  = {Rinieri, Lorenzo and Melis, Andrea and Girau, Roberto and Pau, Giovanni and Prandini, Marco and Callegati, Franco},
  journal = {Computer Networks},
  volume  = {287},
  pages   = {112560},
  year    = {2026},
  issn    = {1389-1286},
  doi     = {10.1016/j.comnet.2026.112560},
  url     = {https://doi.org/10.1016/j.comnet.2026.112560}
}
```

## License

GPL-3.0: see [LICENSE](LICENSE).
