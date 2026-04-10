# P4-Based DNP3 Decoy for ICS/SCADA Deception

A programmable data-plane decoy that impersonates DNP3 outstations (RTUs)
on a Tofino switch. Attackers scanning the network see virtual devices with
realistic MAC addresses, OS fingerprints, open TCP ports, and substation
measurements — none of which physically exist.

## What It Does

The switch creates three virtual DNP3 outstations:

| Decoy IP    | Device         | Vendor MAC          | TTL | DNP3 Addr |
|-------------|----------------|---------------------|-----|-----------|
| 10.0.1.20   | SEL-3530 RTAC  | 00:30:a7:00:00:01   | 255 | 10        |
| 10.0.1.21   | GE D20MX       | 00:60:35:00:00:01   | 64  | 11        |
| 10.0.2.20   | ABB REC670     | 00:15:ac:00:00:01   | 128 | 12        |

Each decoy responds to:

- **ARP** — vendor-correct MAC address (data plane, sub-microsecond)
- **ICMP ping** — echo reply with device-specific TTL (data plane)
- **TCP SYN to port 20000** — SYN-ACK with MSS option (data plane)
- **TCP SYN to other ports** — RST+ACK, port closed (data plane)
- **DNP3 Integrity Poll** — fake substation measurements (controller)
- **DNP3 Direct Operate** — absorbed and logged as attack (controller)

The integrity poll response includes realistic grid values:
breaker states, bus voltages (138.00 V), line currents (4.25 A),
frequency (59.98 Hz), and event counters.

## Testbed Layout

```
 Vision (attacker)          Tofino Switch           Hulk (relay)
   10.0.1.10          ┌──────────────────┐          10.0.2.10
   Port 8 ────────────┤  P4 data plane   ├──────── Port 11
                       │                  │
                       │  decoy_ips table │
                       │  ARP, ICMP, TCP  │
                       │  DNP3 parsing    │
                       └────────┬─────────┘
                                │ digest
                       ┌────────┴─────────┐
                       │  Controller      │
                       │  (laptop/switch) │
                       │  builds DNP3     │
                       │  response frames │
                       └────────┬─────────┘
                                │ UDP 9999
                       ┌────────┴─────────┐
                       │  Inject Helper   │
                       │  (runs on Hulk)  │
                       │  raw socket out  │
                       └──────────────────┘
```

## Quick Start

### 1. Start the switch (on ufispace)

```bash
sudo ./scripts/start_switch.sh
```

Wait for `bfshell>` prompt, then load tables:

```
bfrt_python controller/setup_tables.py
```

### 2. Start the injection helper (on Hulk)

```bash
ssh decps@10.10.54.136
sudo ./scripts/start_inject_helper.sh
```

### 3. Start the controller (on ufispace, second terminal)

```bash
./scripts/start_controller.sh
```

### 4. Run the end-to-end test (on Vision)

```bash
ssh decps@10.0.1.10
sudo ./scripts/run_e2e_test.sh
```

This runs nmap, sends DNP3 packets, captures responses, and decodes
the fake measurements — all in one script.

## Manual Testing

### nmap port scan

```bash
sudo nmap -Pn -sS -p 20000 10.0.1.20 10.0.1.21 10.0.2.20
```

Expected: `20000/tcp open dnp` for all three decoys.

### nmap OS detection

```bash
sudo nmap -Pn -sS -O -p 20000,22,80 10.0.1.20
```

Expected: port 20000 open, ports 22/80 closed, OS fingerprint attempted.

### Decode a pcap independently

```bash
python3 tools/decode_dnp3_pcap.py /tmp/dnp3_e2e_test.pcap
```

No Wireshark needed. Prints decoded breaker states, voltages, currents,
frequency, and counters from each response.

## Project Structure

```
p4_decoy/
├── src/
│   └── dnp3_decoy.p4          # P4 data plane program (Tofino 1, TNA)
│
├── controller/
│   ├── dnp3_controller.py      # Main controller: digest polling, response building
│   ├── dnp3_frames.py          # DNP3 frame builder with CRC-16/DNP
│   ├── device_profiles.py      # Three decoy device configurations
│   ├── setup_tables.py         # Populate switch tables (run in bfrt_python)
│   └── inject_helper.py        # Raw packet relay (runs on Hulk)
│
├── scripts/
│   ├── start_switch.sh         # Compile + start bf_switchd
│   ├── start_controller.sh     # Start the controller
│   ├── start_inject_helper.sh  # Start the Hulk relay
│   └── run_e2e_test.sh         # Full end-to-end test from Vision
│
├── tools/
│   └── decode_dnp3_pcap.py     # Independent DNP3 pcap decoder
│
├── tests/
│   ├── test_dnp3_send.py       # Send DNP3 test packets (requires scapy)
│   └── test_measure.py         # Measurement test suite
│
└── report/
    ├── report.md
    └── report.tex
```

## Data Plane Pipeline (P4)

```
Parser:
  Ethernet → IPv4 → TCP
    ├── SYN to port 20000      → accept (handle in control)
    ├── Non-SYN to port 20000  → skip TCP options → parse DNP3
    └── Other                  → accept

Ingress control (decoy path):
  Step 1: decoy_ips table lookup
  Step 2: ICMP echo → reply with device TTL
  Step 3: TCP SYN to 20000 → SYN-ACK + MSS (CRC32 ISN)
  Step 3b: TCP SYN other port → RST+ACK (closed)
  Step 4: DNP3 data → digest to controller → drop
  Step 5: Other TCP → drop

Normal path: IPv4 LPM forwarding (Vision ↔ Hulk)
```

## Requirements

- Tofino 1 switch with BF-SDE 9.13.x
- Python 3.8+ with `grpcio`, `protobuf` (controller)
- Python 3 with `scapy` (test scripts, on Vision)
- Two servers with 25G NICs (Vision and Hulk)
