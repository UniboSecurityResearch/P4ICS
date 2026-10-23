# P4ICS: P4 In-Network Security for Industrial Control Systems

[![Tests](https://github.com/UniboSecurityResearch/P4ICS/actions/workflows/tests.yml/badge.svg)](https://github.com/UniboSecurityResearch/P4ICS/actions/workflows/tests.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![DOI](https://zenodo.org/badge/763412444.svg)](https://doi.org/10.5281/zenodo.17190336)

This repository contains the source files, testbed configurations, and evaluation results for the paper:
**P4ICS: P4 In-Network Security for Industrial Control Systems Networks**.

P4ICS is a framework that shifts security functions for Industrial Control Systems (ICS) from endpoints into P4-programmable switches, providing confidentiality, integrity, and replay protection for protocols such as **Modbus, DNP3, EtherNet/IP, and MQTT**. In the testbed pipeline, confidentiality and integrity are implemented in switch externs with **AES-CBC** and **HMAC-SHA256** (encrypt-then-MAC), and replays are rejected with per-sender packet counters. The protected packet format is specified in [`docs/WIRE_FORMAT.md`](docs/WIRE_FORMAT.md).

---

## 📂 Repository Structure

- **Dockerfile/**
  Contains container definitions for running industrial protocol clients and servers on the Kathara testbed (`modbus`, `dnp3`, `enip`, MQTT). Pushing a `v*` tag publishes the Modbus, DNP3 and EtherNet/IP images with that tag (`.github/workflows/images.yml`).

- **docs/**
  Specification of the P4ICS protected packet format.

- **modbus_tep_case_study/**
  Files and results for the **Modbus case study** presented in the paper (based on the Tennessee Eastman Process).

- **protocols/** 
  Implementations of ICS client and server applications for: 
  - EtherNet/IP 
  - BACnet
  - DNP3
  - IEC 61850 (libiec61580)
  - Profinet

- **results/**
  Scripts and raw data used to generate the **graphs and tables** included in the paper.

- **sota/**
  Code and comparison experiments with the state-of-the-art AES P4 implementation:
  > Chen, Xiaoqi. *Implementing AES Encryption on Programmable Switches via Scrambled Lookup Tables*.
  > *ACM SIGCOMM SPIN 2020 Workshop on Secure Programmable Network Infrastructure*, ACM, 2020.

- **testbed/**
  A Kathara-based virtual lab to reproduce the P4ICS pipeline outside the physical testbed.
  Includes:
  - Modbus, MQTT, DNP3 and EtherNet/IP support
  - P4 source files (folders `s1/` and `s2/`): payloads are parsed into a header stack of 256-byte slices plus a `varbit` tail, and handed to a single extern per direction
  - Network topology for Kathara

---

## 🔧 Prerequisites

To run the testbed, you need the following software installed on your machine:

- [Docker](https://docs.docker.com/get-docker/)
  Used to build and run the containers of protocol clients and servers.

- [Kathara](https://www.kathara.org/)
  Network emulation platform used to reproduce the P4ICS pipeline and deploy the virtual lab.

Make sure both Docker and Kathara are properly installed and configured before starting the testbed.


## ▶️ Running the Testbed

1. Clone the repository:
   ```bash
   git clone https://github.com/UniboSecurityResearch/P4ICS.git
   cd P4ICS/testbed
   ```

2. Start the Kathara lab:
   ```bash
   kathara lstart
   ```

3. **Modbus Client**  
   - Inside the `modbusclient` terminal you can run the Modbus client interface:
     ```bash
     python3 modbus_client.py [options]
     ```
     The client supports read, write, RTT testing, and different encryption modes.
   - Alternatively, you can run the TLS-enabled client:
     ```bash
     python3 tls_client.py
     ```

4. **MQTT Client**
   - Inside the `mqttclient` terminal you can connect to the broker using plaintext:
     ```bash
     python3 mqtt_client.py
     ```
   - Or connect over TLS:
     ```bash
     python3 mqtt_client_tls.py
     ```

5. **DNP3 and EtherNet/IP**
   - Build the images from the repository root, then uncomment the `dnp3*` and `enip*` devices in `testbed/lab.conf`:
     ```bash
     docker build -f Dockerfile/dnp3.Dockerfile -t loriringhio97/dnp3 .
     docker build -f Dockerfile/enip.Dockerfile -t loriringhio97/enip .
     ```
   - Inside the `dnp3client` terminal (outstation on `dnp3server`, 200.1.1.9):
     ```bash
     DNP3_ENDPOINT=200.1.1.9:20000 DNP3_READS=1000 dnp3_client
     ```
   - Inside the `enipclient` terminal (CIP server on `enipserver`, 200.1.1.10):
     ```bash
     cd /enip && ENIP_HOST=200.1.1.10 ENIP_READS=1000 python client.py
     ```

**Keys.** No key is stored in the repository. When the lab starts, the first switch generates a random 256-bit key in `testbed/shared/p4ics_key` and both switches load it (`s1/p4ics_setup.sh`); `kathara lclean` deletes it, so every lab run uses a new key. `./rotate_keys.sh` (from `testbed/`, while the lab runs) replaces it on both switches without dropping traffic: each switch holds two keys, and the new one is installed in the idle slot before the switches start using it. `./change_key.sh <128|160|192|224|256>` inside a switch changes the key size. `auto_test.sh` selects the key size, or the plaintext/TLS baselines, through `testbed/shared/p4ics_mode`.

Each switch has its own sender identifier (`table_set_default p4ics_local set_local_sa <1..255> ...` in `commands.txt`), and its packet counter starts from the current time, so counters never repeat across restarts. `counter_read MyIngress.p4ics_events <0..4>` reports protected, unprotected, rejected (tag) and rejected (replay) packets, and packets waiting for an on-demand tunnel. s1 and s2 run the same P4 program and extern: edit them in `s1/` and copy them with `./sync_switches.sh`.

---

## ⚙️ Modbus Client Options

The `modbus_client.py` provides a CLI with the following options:

### 🔹 Basic Operations
- **Write to a register**
  ```bash
  python3 modbus_client.py --write
  ```
- **Read from a register**
  ```bash
  python3 modbus_client.py --read
  ```
- **Write and then read (RW)**
  ```bash
  python3 modbus_client.py --rw
  ```
- **Connect to the server only** (repeat 5 times)
  ```bash
  python3 modbus_client.py --connect --connect-times 5
  ```

### 🔹 Performance Tests
- **RTT test (write) with AES-128 key**
  ```bash
  python3 modbus_client.py --test-rtt-write 128
  ```
- **RTT test (read) without encryption** 
  ```bash
  python3 modbus_client.py --test-rtt-read no-encryption
  ```
- **Continuous read test with AES-256 key** 
  ```bash
  python3 modbus_client.py --test-read 256
  ```
- **Continuous write test with AES-192 key** 
  ```bash
  python3 modbus_client.py --test-write 192
  ```

### 🔹 Supported Encryption Modes
```
no-encryption | 128 | 160 | 192 | 224 | 256
```

These correspond to **AES key sizes in bits**, used in the P4ICS security pipeline.
For secure modes, the switch externs use AES-CBC encryption followed by an HMAC-SHA256 tag over the ciphertext and the packet context (addresses, ports, TCP sequence number, protocol header, sender and counter), verified before decryption.

---

## 📊 Results

- Experimental results include:
  - Round-trip time (RTT) comparison between **plaintext**, **TLS**, and **P4ICS**
  - CPU, memory, and power overhead on embedded devices (RevPi, Raspberry Pi 5)
  - Comparison with **state-of-the-art in-network AES** implementations
  - Modbus **monitoring case study** over the Tennessee Eastman Process

Scripts to reproduce the plots from the paper are available in the `results/` folder.

---

## 📑 Reference

If you use this repository, please cite our paper:

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

---

## ⚖️ License

This project is licensed under the terms of the [LICENSE](./LICENSE) file.  
