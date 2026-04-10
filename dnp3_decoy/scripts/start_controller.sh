#!/bin/bash
# start_controller.sh — Start the DNP3 decoy controller
#
# Run on the switch (ufispace) in a separate terminal:
#   ./scripts/start_controller.sh
#
# The controller connects to bf_switchd via gRPC, polls for digests,
# builds DNP3 responses, and injects them via the Hulk relay.
#
# Prerequisites:
#   - bf_switchd must be running (start_switch.sh)
#   - Tables must be loaded (setup_tables.py)
#   - pip3 install grpcio protobuf

# --- Configuration ---
SDE=/home/decps/Downloads/bf-sde-9.13.2
SDE_INSTALL=$SDE/install
PROJECT_DIR=/home/decps/my_program/decoy
SWITCH_ADDR="10.10.54.15:50052"

# bfrt_grpc lives under the tofino package
export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$PYTHONPATH

echo "============================================"
echo "  DNP3 Decoy — Controller"
echo "============================================"
echo "  Switch: $SWITCH_ADDR"
echo "  Ctrl+C to stop"
echo ""

cd "$PROJECT_DIR"
python3 dnp3_controller.py --switch-addr "$SWITCH_ADDR"
