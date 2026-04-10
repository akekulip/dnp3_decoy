"""
Run inside bfrt_python to dump all Tofino resource usage.

Usage:
  1. Start bf_switchd with dnp3_decoy
  2. Open bfshell:  $SDE_INSTALL/bin/bfshell
  3. Type:          bfrt_python
  4. Paste:         exec(open('/home/philip/dnp3_decoy/tools/query_resources.py').read())
"""

print("=" * 70)
print("  RUNTIME RESOURCE REPORT — dnp3_decoy")
print("=" * 70)

# ── 1. Table occupancy ──
print("\n── 1. TABLE OCCUPANCY ──\n")
user_tables = [
    "SwitchIngress.decoy_ips",
    "SwitchIngress.decoy_arp",
    "SwitchIngress.ipv4_forward",
    "SwitchIngress.syn_cookie_tbl",
]

# Try both naming conventions (DecoyIngress vs SwitchIngress)
for prefix in ["DecoyIngress", "SwitchIngress"]:
    for short_name in ["decoy_ips", "decoy_arp", "ipv4_forward", "syn_cookie_tbl"]:
        full = f"bfrt.dnp3_decoy.pipe.{prefix}.{short_name}"
        try:
            tbl = eval(full)
            info = tbl.info(return_info=True, print_info=False)
            usage = info.get("usage", "?")
            capacity = info.get("size", info.get("capacity", "?"))
            key_fields = info.get("key_fields", {})
            print(f"  {prefix}.{short_name}")
            print(f"    Entries: {usage} / {capacity}")
            if key_fields:
                for kf_name, kf_info in key_fields.items():
                    print(f"    Key: {kf_name} ({kf_info})")
            print()
        except Exception:
            pass

# ── 2. All tables in the program ──
print("\n── 2. ALL PROGRAM TABLES ──\n")
try:
    all_info = bfrt.dnp3_decoy.info(return_info=True, print_info=False)
    for item in all_info:
        name = item.get("full_name", item.get("name", "?"))
        usage = item.get("usage", "-")
        size = item.get("size", "-")
        ttype = item.get("type", "?")
        if "pipe" in str(name):
            print(f"  {name:<55} {ttype:<12} {usage}/{size}")
except Exception as e:
    print(f"  Error listing tables: {e}")
    # Fallback: just print the tree
    try:
        bfrt.dnp3_decoy.pipe.info()
    except Exception as e2:
        print(f"  Fallback also failed: {e2}")

# ── 3. Port status ──
print("\n── 3. PORT STATUS ──\n")
try:
    bfrt.port.port.get(regex=True, print_ents=True)
except Exception as e:
    print(f"  {e}")
    print("  (No ports configured or port table not accessible)")

print("\n" + "=" * 70)
print("  Done. Check above for entry counts and table types.")
print("=" * 70)
