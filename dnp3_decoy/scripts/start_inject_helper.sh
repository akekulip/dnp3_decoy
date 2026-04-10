#!/bin/bash
# start_inject_helper.sh — Start the packet injection relay on Hulk
#
# Run on Hulk (10.10.54.136) as root:
#   sudo ./scripts/start_inject_helper.sh
#
# Hulk has a 25G NIC connected to the switch. The controller sends
# crafted Ethernet frames via UDP to this helper, which pushes them
# out the NIC as raw frames. This is a testbed workaround because
# the switch has no CPU-to-data-plane port (no bf_pci0).

PROJECT_DIR=/home/decps/my_program/decoy

echo "============================================"
echo "  DNP3 Decoy — Injection Helper (Hulk)"
echo "============================================"
echo "  Listening on UDP 9999"
echo "  Injecting on enp59s0f0np0"
echo "  Ctrl+C to stop"
echo ""

cd "$PROJECT_DIR/controller"
python3 inject_helper.py
