#!/bin/bash
# run_e2e_test.sh — End-to-end test of the DNP3 decoy
#
# Run on Vision (10.0.1.10) as root:
#   sudo ./scripts/run_e2e_test.sh
#
# Prerequisites (all must be running before this script):
#   1. Switch:     sudo ./scripts/start_switch.sh  (+ load tables)
#   2. Hulk:       sudo ./scripts/start_inject_helper.sh
#   3. Controller: ./scripts/start_controller.sh
#
# What this script does:
#   1. Starts a packet capture on the 25G NIC
#   2. Runs nmap port scan against all three decoys
#   3. Sends DNP3 integrity polls and attack commands
#   4. Stops the capture
#   5. Decodes the captured DNP3 responses (independent of Wireshark)

set -e

IFACE="enp59s0f0np0"
PCAP="/tmp/dnp3_e2e_test.pcap"
TEST_SCRIPT="$(dirname "$0")/../tests/test_dnp3_send.py"
DECODER="$(dirname "$0")/../tools/decode_dnp3_pcap.py"

echo "============================================"
echo "  DNP3 Decoy — End-to-End Test"
echo "============================================"
echo ""

# --- Step 1: nmap port scan ---
echo "[1/4] nmap port scan (SYN-ACK test)..."
echo "----------------------------------------------"
nmap -Pn -sS -p 20000 10.0.1.20 10.0.1.21 10.0.2.20
echo ""

# --- Step 2: Capture + send DNP3 ---
echo "[2/4] Starting packet capture..."
tcpdump -i "$IFACE" -w "$PCAP" port 20000 &
TCPDUMP_PID=$!
sleep 1

echo "[3/4] Sending DNP3 test packets..."
python3 "$TEST_SCRIPT"
sleep 3

echo ""
echo "Stopping capture..."
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
echo ""

# --- Step 3: Decode ---
echo "[4/4] Decoding DNP3 responses..."
echo "============================================"
python3 "$DECODER" "$PCAP"
echo ""

echo "============================================"
echo "  Pcap saved: $PCAP"
echo "  Open in Wireshark: Decode As → DNP 3.0"
echo "============================================"
