#!/bin/bash
###############################################################################
# check_resources.sh — Show Tofino resource usage for dnp3_decoy.p4
#
# Two modes:
#   ./check_resources.sh compile   — Compile P4 and show compiler resource report
#   ./check_resources.sh runtime   — Query running bf_switchd for live table usage
#   ./check_resources.sh           — Defaults to compile mode
###############################################################################

set -euo pipefail

SDE=${SDE:-/home/philip/bf-sde-9.13.1}
SDE_INSTALL=${SDE_INSTALL:-$SDE/install}
P4_SRC="$(dirname "$0")/../src/dnp3_decoy.p4"
P4C="$SDE_INSTALL/bin/bf-p4c"
PROGRAM="dnp3_decoy"
BUILD_DIR="/tmp/${PROGRAM}_build"
MODE="${1:-compile}"

print_header() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
}

#------------------------------------------------------------------------------
# Mode 1: Compile and extract resource report
#------------------------------------------------------------------------------
compile_resources() {
    print_header "Compiling $PROGRAM — Resource Analysis"

    mkdir -p "$BUILD_DIR"

    echo "  P4 source:  $P4_SRC"
    echo "  Compiler:   $P4C"
    echo "  Output dir: $BUILD_DIR"
    echo ""

    # Compile with resource logging
    "$P4C" \
        --std p4-16 \
        --target tofino \
        --arch tna \
        -o "$BUILD_DIR" \
        --bf-rt-schema "$BUILD_DIR/bf-rt.json" \
        "$P4_SRC" 2>&1 | tee "$BUILD_DIR/compile.log"

    echo ""

    # --- 1. Stage allocation ---
    print_header "Stage Allocation"
    if [ -f "$BUILD_DIR/$PROGRAM/tofino/pipe/logs/mau.resources.log" ]; then
        cat "$BUILD_DIR/$PROGRAM/tofino/pipe/logs/mau.resources.log"
    elif [ -f "$BUILD_DIR/pipe/logs/mau.resources.log" ]; then
        cat "$BUILD_DIR/pipe/logs/mau.resources.log"
    else
        # Fallback: search for it
        RESLOG=$(find "$BUILD_DIR" -name "mau.resources.log" 2>/dev/null | head -1)
        if [ -n "$RESLOG" ]; then
            cat "$RESLOG"
        else
            echo "  (mau.resources.log not found — checking compile.log)"
            grep -iE "stage|tcam|sram|exact|ternary|action|gateway|hash|resource|allocated|entries" \
                "$BUILD_DIR/compile.log" || echo "  No resource lines found in compile log"
        fi
    fi

    # --- 2. Table resource breakdown ---
    print_header "Table Resource Summary"
    RESLOG=$(find "$BUILD_DIR" -name "mau.resources.log" 2>/dev/null | head -1)
    if [ -n "$RESLOG" ]; then
        grep -iE "table|tcam|sram|exact|ternary|entries|match|action" "$RESLOG" | head -60
    fi

    # --- 3. Power summary ---
    print_header "Power Estimate"
    PWRLOG=$(find "$BUILD_DIR" -name "power.json" -o -name "power_summary.*" 2>/dev/null | head -1)
    if [ -n "$PWRLOG" ]; then
        cat "$PWRLOG"
    else
        echo "  (no power estimate file found)"
    fi

    # --- 4. context.json summary ---
    print_header "Context JSON — Table Sizes"
    CTX=$(find "$BUILD_DIR" -name "context.json" 2>/dev/null | head -1)
    if [ -n "$CTX" ]; then
        python3 - "$CTX" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    ctx = json.load(f)

tables = ctx.get("tables", [])
print(f"  Total tables in context.json: {len(tables)}\n")
print(f"  {'Table':<35} {'Stage':>5} {'Type':<12} {'Size':>8} {'TCAM':>6} {'SRAM':>6}")
print(f"  {'-'*35} {'-'*5} {'-'*12} {'-'*8} {'-'*6} {'-'*6}")

for t in tables:
    name = t.get("name", "?")
    stage = t.get("stage_number", t.get("stage_tables", [{}])[0].get("stage_number", "?")) if t.get("stage_tables") else "?"
    mtype = t.get("match_type", t.get("table_type", "?"))
    size = t.get("size", "?")

    # Count TCAM and SRAM from stage_tables
    tcam_count = 0
    sram_count = 0
    for st in t.get("stage_tables", []):
        for pack in st.get("pack_format", []):
            mem = pack.get("memory_resource_allocation", {})
            tcam_count += len(mem.get("tcam", []))
            sram_count += len(mem.get("sram", []))

    tcam_str = str(tcam_count) if tcam_count else "-"
    sram_str = str(sram_count) if sram_count else "-"

    print(f"  {name:<35} {str(stage):>5} {str(mtype):<12} {str(size):>8} {tcam_str:>6} {sram_str:>6}")

# Overall resource summary
print(f"\n  --- Compiler Targets ---")
total_stages = set()
for t in tables:
    for st in t.get("stage_tables", []):
        s = st.get("stage_number")
        if s is not None:
            total_stages.add(s)
print(f"  MAU stages used: {len(total_stages)} / 12  (stages: {sorted(total_stages)})")
PYEOF
    else
        echo "  (context.json not found)"
    fi

    # --- 5. PHV allocation ---
    print_header "PHV Allocation"
    PHVLOG=$(find "$BUILD_DIR" -name "phv_allocation.*" -o -name "phv.json" 2>/dev/null | head -1)
    if [ -n "$PHVLOG" ]; then
        head -80 "$PHVLOG"
    else
        # Try to extract from compile log
        grep -iE "phv|container|metadata|header" "$BUILD_DIR/compile.log" | head -20 || echo "  (no PHV details found)"
    fi

    # --- 6. Parser resources ---
    print_header "Parser Resources"
    PARSELOG=$(find "$BUILD_DIR" -name "parser.resources.*" -o -name "parser_resources.*" 2>/dev/null | head -1)
    if [ -n "$PARSELOG" ]; then
        cat "$PARSELOG"
    else
        grep -iE "parser|parse_state|tcam_row" "$BUILD_DIR/compile.log" | head -20 || echo "  (no parser resource details found)"
    fi

    print_header "Summary"
    echo "  Full build output: $BUILD_DIR"
    echo "  Compile log:       $BUILD_DIR/compile.log"
    echo ""
    echo "  Key files to inspect:"
    find "$BUILD_DIR" \( -name "*.log" -o -name "context.json" -o -name "bf-rt.json" \) 2>/dev/null | sed 's/^/    /'
    echo ""
}

#------------------------------------------------------------------------------
# Mode 2: Runtime query via bfshell
#------------------------------------------------------------------------------
runtime_resources() {
    print_header "Runtime Resource Query — $PROGRAM"

    if ! pgrep -x bf_switchd > /dev/null 2>&1; then
        echo "  ERROR: bf_switchd is not running."
        echo "  Start the switch first, then re-run: $0 runtime"
        exit 1
    fi

    BFSHELL="$SDE_INSTALL/bin/bfshell"

    # Table occupancy via bfrt_python
    print_header "Table Occupancy (bfrt_python)"
    echo 'bfrt_python
import json

for tbl_name in ["SwitchIngress.decoy_ips", "SwitchIngress.decoy_arp", "SwitchIngress.ipv4_forward", "SwitchIngress.syn_cookie_tbl"]:
    try:
        tbl = eval(f"bfrt.dnp3_decoy.pipe.{tbl_name}")
        info = tbl.info(return_info=True, print_info=False)
        usage = info.get("usage", "?")
        capacity = info.get("size", "?")
        print(f"  {tbl_name:<40} {usage}/{capacity} entries")
    except Exception as e:
        print(f"  {tbl_name:<40} ERROR: {e}")

exit()
exit' | "$BFSHELL"

    # TCAM/SRAM utilization via ucli
    print_header "Hardware Resource Utilization (ucli)"
    echo 'ucli
tf1 tbl-info
exit
exit' | "$BFSHELL"
}

#------------------------------------------------------------------------------
# Dispatch
#------------------------------------------------------------------------------
case "$MODE" in
    compile)
        compile_resources
        ;;
    runtime)
        runtime_resources
        ;;
    *)
        echo "Usage: $0 [compile|runtime]"
        echo "  compile  — Compile P4 and show resource report (default)"
        echo "  runtime  — Query running switch for live table usage"
        exit 1
        ;;
esac
