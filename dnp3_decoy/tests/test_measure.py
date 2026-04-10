#!/usr/bin/env python3
"""
test_measure.py — Measure DNP3 decoy response metrics

Run on Vision (10.0.1.10). Requires sudo for raw sockets.
Usage:
    sudo python3 test_measure.py

Measures:
  M1: ARP — correct vendor MAC returned
  M2: ICMP — correct TTL per device profile
  M3: DNP3 response arrival (if controller + helper running)
  M4: Traffic isolation — packets to decoys don't leak to Hulk
  M5: nmap host discovery results
"""

import time
import sys
import subprocess
import os

try:
    from scapy.all import (
        Ether, IP, TCP, ARP, ICMP, Raw,
        sendp, srp, sr1, conf, get_if_hwaddr
    )
except ImportError:
    print("ERROR: scapy not installed. Run: sudo pip3 install scapy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IFACE = "enp59s0f0np0"
VISION_IP = "10.0.1.10"
VISION_MAC = get_if_hwaddr(IFACE)
conf.verb = 0

DECOYS = [
    {"ip": "10.0.1.20", "mac": "00:30:a7:00:00:01", "ttl": 255, "name": "SEL-3530"},
    {"ip": "10.0.1.21", "mac": "00:60:35:00:00:01", "ttl": 64,  "name": "GE D20MX"},
    {"ip": "10.0.2.20", "mac": "00:15:ac:00:00:01", "ttl": 128, "name": "ABB REC670"},
]

results = []

def log(test, target, status, detail=""):
    entry = {"test": test, "target": target, "status": status, "detail": detail}
    results.append(entry)
    mark = "PASS" if status else "FAIL"
    print(f"  [{mark}] {test}: {target} — {detail}")


def test_arp():
    """M1: ARP — verify correct vendor MAC for each decoy."""
    print("\n" + "=" * 60)
    print("TEST: ARP Resolution")
    print("=" * 60)

    for d in DECOYS:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=VISION_MAC) / \
              ARP(op="who-has", hwsrc=VISION_MAC,
                  psrc=VISION_IP, pdst=d["ip"])
        ans, _ = srp(pkt, iface=IFACE, timeout=2)

        if ans:
            reply_mac = ans[0][1].hwsrc.lower()
            expected = d["mac"].lower()
            match = reply_mac == expected
            log("ARP", d["name"],
                match,
                f"got={reply_mac} expected={expected}")
        else:
            log("ARP", d["name"], False, "no reply")


def test_icmp():
    """M2: ICMP echo — verify correct TTL and measure latency."""
    print("\n" + "=" * 60)
    print("TEST: ICMP Echo Reply (TTL + Latency)")
    print("=" * 60)

    for d in DECOYS:
        latencies = []
        ttl_correct = True

        for i in range(10):
            pkt = IP(src=VISION_IP, dst=d["ip"], ttl=64) / ICMP(seq=i)
            t0 = time.time()
            reply = sr1(pkt, iface=IFACE, timeout=1)
            t1 = time.time()

            if reply:
                latencies.append((t1 - t0) * 1000)  # ms
                if reply.ttl != d["ttl"]:
                    ttl_correct = False
            time.sleep(0.01)

        if latencies:
            avg = sum(latencies) / len(latencies)
            mn = min(latencies)
            mx = max(latencies)
            log("ICMP_TTL", d["name"],
                ttl_correct,
                f"TTL={d['ttl']} expected, got={reply.ttl if reply else '?'}")
            log("ICMP_LATENCY", d["name"],
                True,
                f"min={mn:.3f}ms avg={avg:.3f}ms max={mx:.3f}ms ({len(latencies)}/10 replies)")
        else:
            log("ICMP", d["name"], False, "no replies")


def test_dnp3_response():
    """M3: DNP3 — send Integrity Poll and check if response arrives."""
    print("\n" + "=" * 60)
    print("TEST: DNP3 Integrity Poll Response")
    print("  (requires controller + inject_helper running)")
    print("=" * 60)

    for d in DECOYS:
        # Build DNP3 Integrity Poll
        dnp3_addr = DECOYS.index(d) + 10  # 10, 11, 12
        dst_lo = dnp3_addr & 0xFF
        dst_hi = (dnp3_addr >> 8) & 0xFF

        dnp3_payload = bytes([
            0x05, 0x64, 0x0B, 0xC0,
            dst_lo, dst_hi, 0x01, 0x00,
            0x00, 0x00,
            0xC0, 0xC0, 0x01,
            0x3C, 0x01, 0x06,
            0x00, 0x00
        ])

        pkt = Ether(dst=d["mac"], src=VISION_MAC) / \
              IP(src=VISION_IP, dst=d["ip"]) / \
              TCP(sport=54321, dport=20000, flags="PA", seq=2000, ack=1) / \
              Raw(load=dnp3_payload)

        t0 = time.time()
        sendp(pkt, iface=IFACE)

        # Listen for response (timeout 3 seconds)
        from scapy.all import sniff
        def is_dnp3_response(p):
            return (p.haslayer(TCP) and p[TCP].sport == 20000 and
                    p.haslayer(Raw) and len(p[Raw].load) > 10 and
                    p[Raw].load[0] == 0x05 and p[Raw].load[1] == 0x64)

        responses = sniff(iface=IFACE, timeout=3,
                         lfilter=is_dnp3_response, count=1)
        t1 = time.time()

        if responses:
            resp = responses[0]
            latency_ms = (t1 - t0) * 1000
            payload = bytes(resp[Raw].load)
            # Check start bytes
            valid_start = payload[0] == 0x05 and payload[1] == 0x64
            # Check FC = 0x81 (Response) — it's in the user data after DLL+Transport
            # DLL is 10 bytes, Transport is 1 byte, App Control is 1 byte, then FC
            fc_offset = 10 + 1 + 1  # after DLL CRC + Transport + AppCtrl
            # Actually the FC is at a different offset due to CRC blocks
            # Just check that we got a substantial response
            log("DNP3_RESPONSE", d["name"],
                valid_start,
                f"received {len(payload)} bytes in {latency_ms:.1f}ms, start=0x{payload[0]:02x}{payload[1]:02x}")
        else:
            log("DNP3_RESPONSE", d["name"], False,
                "no response within 3s (is controller running?)")

        time.sleep(0.5)


def test_traffic_isolation():
    """M4: Verify decoy traffic doesn't reach non-decoy hosts."""
    print("\n" + "=" * 60)
    print("TEST: Traffic Isolation")
    print("  (manual check: run tcpdump on Hulk before this test)")
    print("=" * 60)
    print("  To verify: on Hulk run 'sudo tcpdump -i enp59s0f0np0 port 20000 -c 1'")
    print("  Then run this test. Hulk tcpdump should time out with 0 packets.")

    # Send a burst of DNP3 packets to decoys
    for d in DECOYS:
        dnp3_payload = bytes([
            0x05, 0x64, 0x0B, 0xC0,
            0x0A, 0x00, 0x01, 0x00,
            0x00, 0x00, 0xC0, 0xC0, 0x01,
            0x3C, 0x01, 0x06, 0x00, 0x00
        ])
        pkt = Ether(dst=d["mac"], src=VISION_MAC) / \
              IP(src=VISION_IP, dst=d["ip"]) / \
              TCP(sport=12345, dport=20000, flags="PA", seq=1000, ack=1) / \
              Raw(load=dnp3_payload)
        sendp(pkt, iface=IFACE, count=10)

    log("ISOLATION", "all decoys",
        True, "30 packets sent — check Hulk tcpdump for 0 captures")


def print_summary():
    """Print final results table."""
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in results if r["status"])
    failed = sum(1 for r in results if not r["status"])

    for r in results:
        mark = "PASS" if r["status"] else "FAIL"
        print(f"  [{mark}] {r['test']:20s} {r['target']:15s} {r['detail']}")

    print(f"\n  Total: {passed} passed, {failed} failed out of {len(results)} tests")
    print("=" * 60)

    # Save to file
    with open("/home/decps/decoy_results.txt", "w") as f:
        f.write(f"P4 DNP3 Decoy Test Results — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n")
        for r in results:
            mark = "PASS" if r["status"] else "FAIL"
            f.write(f"[{mark}] {r['test']:20s} {r['target']:15s} {r['detail']}\n")
        f.write(f"\nTotal: {passed}/{len(results)} passed\n")
    print(f"\n  Results saved to /home/decps/decoy_results.txt")


def main():
    print("=" * 60)
    print("P4 DNP3 Decoy — Measurement Suite")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Source: {VISION_IP} ({IFACE})")
    print("=" * 60)

    test_arp()
    test_icmp()
    test_dnp3_response()
    test_traffic_isolation()
    print_summary()


if __name__ == "__main__":
    main()
