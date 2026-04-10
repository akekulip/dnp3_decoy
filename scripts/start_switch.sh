#!/bin/bash
# start_switch.sh — Compile P4, start bf_switchd, load tables
#
# Run on the Tofino switch (ufispace) as root:
#   sudo ./scripts/start_switch.sh
#
# What it does:
#   1. Sets up BF-SDE environment
#   2. Compiles dnp3_decoy.p4 with bf-p4c
#   3. Loads the kernel driver
#   4. Starts bf_switchd with the compiled program
#
# After bf_switchd starts and shows "bfshell>", load tables:
#   bfrt_python /home/decps/my_program/decoy/controller/setup_tables.py

set -e

# --- Configuration (edit these for your setup) ---
SDE=/home/decps/Downloads/bf-sde-9.13.2
PROJECT_DIR=/home/decps/my_program/decoy
P4_SOURCE=$PROJECT_DIR/dnp3_decoy.p4
CONF_FILE=$PROJECT_DIR/dnp3_decoy.tofino/dnp3_decoy.conf

# --- Environment ---
export SDE
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH

echo "============================================"
echo "  DNP3 Decoy — Switch Startup"
echo "============================================"
echo "  SDE:     $SDE_INSTALL"
echo "  P4 src:  $P4_SOURCE"
echo ""

# --- Step 1: Compile ---
echo "[1/3] Compiling P4 program..."
cd "$PROJECT_DIR"
bf-p4c "$P4_SOURCE" --arch tna --target tofino --std p4-16
echo "  Compiled OK."
echo ""

# --- Step 2: Kernel driver ---
echo "[2/3] Loading kernel driver..."
$SDE_INSTALL/bin/bf_kdrv_mod_load $SDE_INSTALL 2>/dev/null || true
echo "  Driver loaded."
echo ""

# --- Step 3: Start switch ---
echo "[3/3] Starting bf_switchd..."
echo "  After 'bfshell>' prompt appears, run:"
echo "    bfrt_python $PROJECT_DIR/controller/setup_tables.py"
echo ""
bf_switchd \
    --install-dir "$SDE_INSTALL" \
    --conf-file "$CONF_FILE" \
    --status-port 7777
