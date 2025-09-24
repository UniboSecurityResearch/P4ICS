# P4ICS: P4 In-Network Security for Industrial Control Systems

This repository contains the source files, testbed configurations, and evaluation results for the paper:
**P4ICS: P4 In-Network Security for Industrial Control Systems Networks**.

P4ICS is a framework that shifts security functions for Industrial Control Systems (ICS) from endpoints into P4-programmable switches, providing confidentiality, integrity, and replay protection for protocols such as **Modbus, DNP3, EtherNet/IP, and MQTT**.

---

## 📂 Repository Structure

- **Dockerfile/**
  Contains container definitions for running industrial protocol clients and servers on the Kathara testbed.

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
  - Modbus and MQTT support
  - P4 source files (folders `s1/` and `s2/`)
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
   git clone https://github.com/<your-org>/P4ICS.git
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
no-encryption | 128 | 192 | 256
```

These correspond to **AES key sizes in bits**, used in the P4ICS security pipeline.

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

If you use this repository, please cite the paper:

```bibtex
@article{rinieri2025p4ics,
  title   = {P4ICS: P4 In-Network Security for Industrial Control Systems Networks},
  author  = {},
  journal = {Preprint submitted to Computer Networks},
  year    = {2025}
}
```

---

## ⚖️ License

This project is licensed under the terms of the [LICENSE](./LICENSE) file.  
