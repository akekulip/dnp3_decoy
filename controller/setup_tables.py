# setup_tables.py — Configure ports and populate tables for dnp3_decoy.p4
#
# Run this inside bfrt_python on the switch:
#   bfshell> bfrt_python setup_tables.py
#
# Or from the bfrt_python prompt:
#   bfrt_python> exec(open("setup_tables.py").read())
#
# Testbed:
#   Vision: 10.0.1.10, DEV_PORT 8  (Port 15/0), MAC 3c:fd:fe:e5:f9:90
#   Hulk:   10.0.2.10, DEV_PORT 11 (Port 15/3), MAC 3c:fd:fe:cc:5d:c0
#
# Decoy IPs:
#   10.0.1.20 — SEL-3530 RTAC  (DNP3 addr 10, TTL=255, MAC=00:30:a7:00:00:01)
#   10.0.1.21 — GE D20MX       (DNP3 addr 11, TTL=64,  MAC=00:60:35:00:00:01)
#   10.0.2.20 — ABB REC670     (DNP3 addr 12, TTL=128, MAC=00:15:ac:00:00:01)

# ============================================================
# Step 1: Configure 25G ports
# ============================================================
try:
    bfrt.port.port.add(DEV_PORT=8, SPEED="BF_SPEED_25G",
                       FEC="BF_FEC_TYP_NONE",
                       AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE",
                       PORT_ENABLE=True)
    print("Port 8 (Vision 15/0) configured")
except:
    print("Port 8 already exists")

try:
    bfrt.port.port.add(DEV_PORT=11, SPEED="BF_SPEED_25G",
                       FEC="BF_FEC_TYP_NONE",
                       AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE",
                       PORT_ENABLE=True)
    print("Port 11 (Hulk 15/3) configured")
except:
    print("Port 11 already exists")

# ============================================================
# Step 2: Populate decoy_ips table
#
#   Maps destination IP -> decoy device profile (MAC, TTL, TCP window)
#   When the P4 program sees traffic to these IPs, it marks the
#   packet as destined for a decoy and applies the profile.
# ============================================================
p = bfrt.dnp3_decoy.pipe.DecoyIngress

# SEL-3530 RTAC — VxWorks OS (TTL=255)
try:
    p.decoy_ips.add_with_set_decoy_profile(
        dst_addr=0x0A000114,    # 10.0.1.20
        mac=0x0030A7000001,     # SEL OUI
        ttl=255,
        tcp_win=8192)
    print("Decoy IP: 10.0.1.20 -> SEL-3530 (TTL=255)")
except:
    print("10.0.1.20 already exists")

# GE D20MX — Linux OS (TTL=64)
try:
    p.decoy_ips.add_with_set_decoy_profile(
        dst_addr=0x0A000115,    # 10.0.1.21
        mac=0x006035000001,     # GE OUI
        ttl=64,
        tcp_win=4096)
    print("Decoy IP: 10.0.1.21 -> GE D20MX (TTL=64)")
except:
    print("10.0.1.21 already exists")

# ABB REC670 — Windows CE (TTL=128)
try:
    p.decoy_ips.add_with_set_decoy_profile(
        dst_addr=0x0A000214,    # 10.0.2.20
        mac=0x0015AC000001,     # ABB OUI
        ttl=128,
        tcp_win=8760)
    print("Decoy IP: 10.0.2.20 -> ABB REC670 (TTL=128)")
except:
    print("10.0.2.20 already exists")

# ============================================================
# Step 3: Populate decoy_arp table
#
#   Maps ARP target IP -> vendor MAC for synthesized ARP replies.
#   When someone ARPs for a decoy IP, the switch responds with
#   the correct vendor MAC — no real device needed.
# ============================================================

try:
    p.decoy_arp.add_with_set_arp_decoy(
        target_proto_addr=0x0A000114,   # 10.0.1.20
        mac=0x0030A7000001)
    print("ARP: 10.0.1.20 -> 00:30:a7:00:00:01")
except:
    print("ARP 10.0.1.20 already exists")

try:
    p.decoy_arp.add_with_set_arp_decoy(
        target_proto_addr=0x0A000115,   # 10.0.1.21
        mac=0x006035000001)
    print("ARP: 10.0.1.21 -> 00:60:35:00:00:01")
except:
    print("ARP 10.0.1.21 already exists")

try:
    p.decoy_arp.add_with_set_arp_decoy(
        target_proto_addr=0x0A000214,   # 10.0.2.20
        mac=0x0015AC000001)
    print("ARP: 10.0.2.20 -> 00:15:ac:00:00:01")
except:
    print("ARP 10.0.2.20 already exists")

# ============================================================
# Step 4: IPv4 forwarding rules (for non-decoy traffic)
#
#   Normal traffic between Vision and Hulk still needs to work.
#   These are LPM (longest prefix match) rules.
# ============================================================

try:
    p.ipv4_forward.add_with_set_egress(
        dst_addr=0x0A000100, dst_addr_p_length=24,   # 10.0.1.0/24
        port=8,
        dst_mac=0x3CFDFEE5F990)     # Vision MAC
    print("IPv4: 10.0.1.0/24 -> port 8 (Vision)")
except:
    print("10.0.1.0/24 rule already exists")

try:
    p.ipv4_forward.add_with_set_egress(
        dst_addr=0x0A000200, dst_addr_p_length=24,   # 10.0.2.0/24
        port=11,
        dst_mac=0x3CFDFECC5DC0)     # Hulk MAC
    print("IPv4: 10.0.2.0/24 -> port 11 (Hulk)")
except:
    print("10.0.2.0/24 rule already exists")

# ============================================================
# Done
# ============================================================
print("")
print("=== Setup complete ===")
print("Decoys active: 10.0.1.20 (SEL), 10.0.1.21 (GE), 10.0.2.20 (ABB)")
print("")
print("Test from Vision:")
print("  arping -c 3 10.0.1.20   (should get reply from 00:30:a7:00:00:01)")
print("  ping -c 3 10.0.1.20     (should get ICMP echo, TTL=255)")
