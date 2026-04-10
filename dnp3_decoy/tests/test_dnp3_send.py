#!/usr/bin/env python3
"""
test_dnp3_send.py — Send test DNP3 packets to decoy IPs

Run on Vision (10.0.1.10) to test the P4 decoy pipeline.

Usage:
    sudo python3 test_dnp3_send.py

What it does:
    1. Sends a DNP3 Integrity Poll (FC=0x01) to each decoy IP on port 20000
    2. The switch should parse the DNP3 headers and digest to the controller
    3. Without the controller running, the packet is just dropped (no response)
    4. With the controller running, you should get a valid DNP3 response back

What to check:
    - On Hulk: run 'sudo tcpdump -i enp59s0f0np0 port 20000' — should see NOTHING
      (packets are intercepted by the decoy, not forwarded)
    - On the switch bfrt_python: check digest counters
    - With controller running: Wireshark on Vision should show DNP3 responses
"""

import time
import sys

try:
    from scapy.all import Ether, IP, TCP, Raw, sendp, conf
except ImportError:
    print("ERROR: scapy not installed. Run: sudo pip3 install scapy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Testbed config
# ---------------------------------------------------------------------------
IFACE = "enp59s0f0np0"        # Vision's 25G NIC
VISION_IP = "10.0.1.10"
VISION_MAC = "3c:fd:fe:e5:f9:90"

# Decoy targets
DECOYS = [
    {"ip": "10.0.1.20", "mac": "00:30:a7:00:00:01", "dnp3_addr": 10, "name": "SEL-3530"},
    {"ip": "10.0.1.21", "mac": "00:60:35:00:00:01", "dnp3_addr": 11, "name": "GE D20MX"},
    {"ip": "10.0.2.20", "mac": "00:15:ac:00:00:01", "dnp3_addr": 12, "name": "ABB REC670"},
]

MASTER_DNP3_ADDR = 1          # Our (attacker's) DNP3 address


def build_dnp3_integrity_poll(dst_dnp3_addr, src_dnp3_addr=MASTER_DNP3_ADDR):
    """
    Build a raw DNP3 Integrity Poll payload (Read Class 0,1,2,3).

    This is the most common reconnaissance query — it asks the outstation
    to return all its data points (binary inputs, analog inputs, counters).

    Frame structure:
        Data Link Header (10 bytes):
            0x05 0x64           — start bytes
            length              — user data length + CRC bytes
            control             — 0xC0 = DIR=1 PRM=1 FC=0 (unconfirmed)
            dst addr (2 LE)     — outstation address
            src addr (2 LE)     — master address
            CRC (2 LE)          — placeholder (real CRC would go here)

        User Data Block (with transport + application):
            Transport: 0xC0    — FIR=1, FIN=1, seq=0
            App Control: 0xC0  — FIR=1, FIN=1, CON=0, UNS=0, seq=0
            FC: 0x01           — Read
            Obj 60 Var 1       — Class 0 data
            Qualifier: 0x06    — All objects, no range
            Obj 60 Var 2       — Class 1 events
            Qualifier: 0x06
            Obj 60 Var 3       — Class 2 events
            Qualifier: 0x06
            Obj 60 Var 4       — Class 3 events
            Qualifier: 0x06
            CRC (2 LE)         — placeholder
    """
    # DNP3 addresses are little-endian on the wire
    dst_lo = dst_dnp3_addr & 0xFF
    dst_hi = (dst_dnp3_addr >> 8) & 0xFF
    src_lo = src_dnp3_addr & 0xFF
    src_hi = (src_dnp3_addr >> 8) & 0xFF

    payload = bytes([
        # --- Data Link Header ---
        0x05, 0x64,             # Start bytes
        0x14,                   # Length (20 bytes of user data + CRCs follow)
        0xC0,                   # Control: DIR=1, PRM=1, FC=0
        dst_lo, dst_hi,         # Destination address (outstation)
        src_lo, src_hi,         # Source address (master)
        0x00, 0x00,             # CRC placeholder (P4 parser extracts but ignores)

        # --- User Data Block 1 (transport + application) ---
        0xC0,                   # Transport: FIR=1, FIN=1, seq=0
        0xC0,                   # App control: FIR=1, FIN=1, seq=0
        0x01,                   # Function Code = Read (0x01)
        0x3C, 0x01, 0x06,      # Object Group 60, Var 1 (Class 0), Qualifier 0x06
        0x3C, 0x02, 0x06,      # Object Group 60, Var 2 (Class 1), Qualifier 0x06
        0x3C, 0x03, 0x06,      # Object Group 60, Var 3 (Class 2), Qualifier 0x06
        0x3C, 0x04, 0x06,      # Object Group 60, Var 4 (Class 3), Qualifier 0x06
        0x00, 0x00,             # CRC placeholder
    ])
    return payload


def build_dnp3_direct_operate(dst_dnp3_addr, src_dnp3_addr=MASTER_DNP3_ADDR):
    """
    Build a DNP3 Direct Operate (FC=0x05) — this is an ATTACK command.
    Tells the outstation to immediately execute a control action.
    The decoy should absorb this and log it as an attack attempt.
    """
    dst_lo = dst_dnp3_addr & 0xFF
    dst_hi = (dst_dnp3_addr >> 8) & 0xFF
    src_lo = src_dnp3_addr & 0xFF
    src_hi = (src_dnp3_addr >> 8) & 0xFF

    payload = bytes([
        # --- Data Link Header ---
        0x05, 0x64,
        0x0B,                   # Length
        0xC0,                   # Control
        dst_lo, dst_hi,
        src_lo, src_hi,
        0x00, 0x00,             # CRC placeholder

        # --- User Data ---
        0xC0,                   # Transport: FIR=1, FIN=1, seq=0
        0xC1,                   # App control: FIR=1, FIN=1, seq=1
        0x05,                   # Function Code = Direct Operate (0x05)
        0x0C, 0x01,             # Object Group 12, Var 1 (CROB)
        0x00,                   # Qualifier
        0x00, 0x00,             # CRC placeholder
    ])
    return payload


def send_test(decoy, payload, test_name):
    """Send a DNP3 packet and print status."""
    pkt = (
        Ether(dst=decoy["mac"], src=VISION_MAC) /
        IP(src=VISION_IP, dst=decoy["ip"]) /
        TCP(sport=12345, dport=20000, flags="PA", seq=1000, ack=1) /
        Raw(load=payload)
    )

    print(f"  Sending {test_name} to {decoy['ip']} ({decoy['name']})...")
    sendp(pkt, iface=IFACE, verbose=False)
    print(f"  Sent. ({len(pkt)} bytes)")


def main():
    conf.verb = 0  # Quiet scapy

    print("=" * 60)
    print("DNP3 Decoy Test — Sending reconnaissance packets")
    print("=" * 60)
    print()

    # --- Test 1: Integrity Poll to each decoy ---
    print("[Test 1] Integrity Poll (FC=0x01) — read all data points")
    print("-" * 60)
    for decoy in DECOYS:
        payload = build_dnp3_integrity_poll(decoy["dnp3_addr"])
        send_test(decoy, payload, "Integrity Poll")
        time.sleep(0.5)
    print()

    # --- Test 2: Direct Operate (attack command) ---
    print("[Test 2] Direct Operate (FC=0x05) — ATTACK COMMAND")
    print("-" * 60)
    for decoy in DECOYS:
        payload = build_dnp3_direct_operate(decoy["dnp3_addr"])
        send_test(decoy, payload, "Direct Operate (ATTACK)")
        time.sleep(0.5)
    print()

    print("=" * 60)
    print("All test packets sent.")
    print()
    print("What to check:")
    print("  - Hulk tcpdump: should see NO DNP3 packets (intercepted by decoy)")
    print("  - Controller log: should show digest entries for each packet")
    print("  - With controller running: Vision should receive DNP3 responses")
    print("=" * 60)


if __name__ == "__main__":
    main()
