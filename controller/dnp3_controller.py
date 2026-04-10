#!/usr/bin/env python3
"""
dnp3_controller.py — Main Controller for P4-Based DNP3 Decoy
==============================================================

This controller runs on the laptop (10.10.54.86) and connects to the
Tofino switch via bfrt_grpc.  Its job:

  1. Poll the switch for digest messages.  The P4 data plane sends a
     digest whenever it intercepts a DNP3 query to a decoy IP.
  2. Look up the device profile for the targeted decoy IP.
  3. Build a valid DNP3 response frame (correct CRCs, correct IIN bits,
     realistic data).
  4. Wrap the response in TCP/IP/Ethernet headers.
  5. Inject the packet back through the switch via PacketOut.

Architecture
------------
  Attacker  →  Tofino switch  →  digest to controller
                                      ↓
                              controller builds response
                                      ↓
                              PacketOut → Tofino switch  →  Attacker

The controller is intentionally simple: synchronous, single-threaded,
no fancy frameworks.  This is a research prototype.

Usage
-----
  python3 dnp3_controller.py [--switch-addr 10.10.54.15:50052]
"""

import struct
import socket
import time
import logging
import argparse
import signal
import sys

# ---------------------------------------------------------------------------
# Import our local modules
# ---------------------------------------------------------------------------
from device_profiles import DEVICE_PROFILES, DEFAULT_MASTER_ADDR, get_profile
from dnp3_frames import (
    build_integrity_poll_response,
    build_error_response,
    build_control_response,
)

# ---------------------------------------------------------------------------
# bfrt_grpc import — this is the Tofino gRPC client library
# ---------------------------------------------------------------------------
try:
    import bfrt_grpc.client as gc
except ImportError:
    print("ERROR: bfrt_grpc module not found.")
    print("This module is part of the Intel/Barefoot SDE.")
    print("Make sure $SDE_INSTALL/lib/python3/bfrt_grpc is in PYTHONPATH.")
    sys.exit(1)


# ===========================================================================
# Configuration Constants
# ===========================================================================

SWITCH_GRPC_ADDR = "10.10.54.15:50052"  # Tofino gRPC endpoint
P4_PROGRAM_NAME = "dnp3_decoy"           # Name from the P4 compile
CLIENT_ID = 0
DEVICE_ID = 0

CONTROLLER_IP = "10.10.54.86"            # This laptop's IP
DIGEST_POLL_INTERVAL = 0.01              # 10 ms polling interval (seconds)

# Ethernet type for IPv4
ETHERTYPE_IPV4 = 0x0800

# IP protocol number for TCP
IPPROTO_TCP = 6

# DNP3 function codes (from the request)
FC_READ             = 0x01
FC_WRITE            = 0x02
FC_SELECT           = 0x03
FC_OPERATE          = 0x04
FC_DIRECT_OPERATE   = 0x05
FC_COLD_RESTART     = 0x0D
FC_WARM_RESTART     = 0x0E
FC_ENABLE_UNSOL     = 0x14
FC_DISABLE_UNSOL    = 0x15

# ===========================================================================
# Logging Setup
# ===========================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("dnp3_decoy")

# Separate attack log for critical events (Select/Operate/DirectOperate)
attack_logger = logging.getLogger("attack_log")
attack_handler = logging.FileHandler("attack_log.txt")
attack_handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))
attack_logger.addHandler(attack_handler)
attack_logger.setLevel(logging.INFO)


# ===========================================================================
# TCP State Tracker
# ===========================================================================
# The controller must set correct TCP sequence/ack numbers in injected
# packets.  We track per-connection state here.
#
# Key: (src_ip, src_port, dst_ip)  — from the attacker's perspective
# Value: dict with our_seq, peer_seq

tcp_state = {}


def get_tcp_state(src_ip: str, src_port: int, dst_ip: str,
                  tcp_ack: int = None) -> dict:
    """Get or create TCP state for a connection.

    Parameters
    ----------
    tcp_ack : int, optional
        The attacker's TCP ACK number from the first data digest.
        This equals our ISN + 1 (the P4 SYN-ACK consumed one sequence
        number).  Used to initialize our_seq so the controller's
        responses carry the correct sequence numbers.
    """
    key = (src_ip, src_port, dst_ip)
    if key not in tcp_state:
        # If the digest provides tcp_ack, it equals our ISN + 1
        # (the attacker ACK'd our SYN).  That is exactly the next
        # sequence number we should use for our first data segment.
        our_seq = tcp_ack if tcp_ack else 1000
        tcp_state[key] = {
            "our_seq": our_seq,
            "peer_seq": 0,
        }
    return tcp_state[key]


def update_tcp_state(src_ip: str, src_port: int, dst_ip: str,
                     peer_seq: int, payload_len: int) -> dict:
    """
    Update TCP state after we send a response.

    Parameters
    ----------
    src_ip : str       Attacker's IP.
    src_port : int     Attacker's TCP port.
    dst_ip : str       Decoy's IP.
    peer_seq : int     Sequence number from the attacker's last packet
                       (this becomes our ACK number).
    payload_len : int  Length of our TCP payload (for advancing our_seq).

    Returns
    -------
    dict  Updated TCP state.
    """
    state = get_tcp_state(src_ip, src_port, dst_ip)
    state["peer_seq"] = peer_seq
    state["our_seq"] += payload_len
    return state


# ===========================================================================
# Select-Before-Operate (SBO) State Machine
# ===========================================================================
# DNP3 SBO: master sends Select (FC 0x03), outstation "arms" the control,
# master sends Operate (FC 0x04) to execute.  If we receive Operate
# without a prior Select, it's a protocol violation (or direct attack).
#
# Key: (src_ip, decoy_ip)
# Value: timestamp of Select (expires after 5 seconds per spec)

sbo_pending = {}

SBO_TIMEOUT = 5.0  # seconds — DNP3 SBO timeout


def record_select(src_ip: str, decoy_ip: str):
    """Record that a Select was received from this attacker."""
    sbo_pending[(src_ip, decoy_ip)] = time.time()
    logger.info("SBO: Select armed for %s -> %s", src_ip, decoy_ip)


def check_and_consume_select(src_ip: str, decoy_ip: str) -> bool:
    """
    Check if there's a pending Select for this Operate.
    Returns True if valid SBO sequence, False otherwise.
    Consumes the Select (one-shot).
    """
    key = (src_ip, decoy_ip)
    if key not in sbo_pending:
        return False
    elapsed = time.time() - sbo_pending[key]
    del sbo_pending[key]
    if elapsed > SBO_TIMEOUT:
        logger.warning("SBO: Select expired (%.1fs ago) for %s -> %s",
                       elapsed, src_ip, decoy_ip)
        return False
    return True


# ===========================================================================
# Packet Construction Helpers
# ===========================================================================
# We build raw Ethernet/IP/TCP/DNP3 packets to inject via PacketOut.
# These are simple byte-level constructions — no Scapy dependency.

def _checksum(data: bytes) -> int:
    """
    Compute the Internet checksum (RFC 1071) used in IPv4 and TCP headers.
    """
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_ethernet_header(dst_mac: str, src_mac: str) -> bytes:
    """
    Build a 14-byte Ethernet header.

    Parameters
    ----------
    dst_mac : str   Destination MAC, colon-separated (e.g. "aa:bb:cc:dd:ee:ff")
    src_mac : str   Source MAC (the decoy device's MAC).
    """
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    return dst + src + struct.pack("!H", ETHERTYPE_IPV4)


def build_ipv4_header(src_ip: str, dst_ip: str, ttl: int,
                      payload_len: int) -> bytes:
    """
    Build a 20-byte IPv4 header (no options).

    Parameters
    ----------
    src_ip : str        Decoy's IP address.
    dst_ip : str        Attacker's IP address.
    ttl : int           TTL from device profile (OS fingerprint).
    payload_len : int   Length of TCP header + TCP payload.
    """
    version_ihl = 0x45   # IPv4, IHL=5 (20 bytes, no options)
    dscp_ecn = 0x00
    total_length = 20 + payload_len
    identification = 0x0000   # Could randomize for realism
    flags_offset = 0x4000     # Don't Fragment
    protocol = IPPROTO_TCP
    checksum = 0              # Placeholder, computed below

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_length,
        identification, flags_offset,
        ttl, protocol, checksum,
        src, dst,
    )

    # Compute header checksum
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header


def build_tcp_header(src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     seq: int, ack: int,
                     window: int, payload: bytes) -> bytes:
    """
    Build a 20-byte TCP header (no options) with correct checksum.

    The TCP checksum covers a pseudo-header + TCP header + payload.

    Parameters
    ----------
    src_ip : str        Decoy's IP.
    dst_ip : str        Attacker's IP.
    src_port : int      Decoy's TCP port (20000 for DNP3).
    dst_port : int      Attacker's TCP source port.
    seq : int           Our sequence number.
    ack : int           Acknowledge attacker's data.
    window : int        TCP window size (from device profile).
    payload : bytes     TCP payload (the DNP3 frame).
    """
    data_offset = 5 << 4  # 5 x 32-bit words = 20 bytes, no options
    flags = 0x18          # ACK + PSH (we're sending data)
    urgent = 0
    checksum = 0          # Placeholder

    header = struct.pack("!HHIIBBHHH",
        src_port, dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        data_offset, flags,
        window, checksum, urgent,
    )

    # TCP pseudo-header for checksum
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, IPPROTO_TCP, len(header) + len(payload))
    )
    checksum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", checksum) + header[18:]

    return header


def build_full_packet(
    attacker_ip: str,
    attacker_port: int,
    attacker_mac: str,
    decoy_ip: str,
    profile: dict,
    dnp3_frame: bytes,
    peer_seq: int,
    peer_payload_len: int,
) -> bytes:
    """
    Build a complete Ethernet + IPv4 + TCP + DNP3 packet for injection.

    Parameters
    ----------
    attacker_ip : str       Attacker's IP address.
    attacker_port : int     Attacker's TCP source port.
    attacker_mac : str      Attacker's MAC address.
    decoy_ip : str          Decoy's IP address.
    profile : dict          Device profile.
    dnp3_frame : bytes      Complete DNP3 frame (from dnp3_frames.py).
    peer_seq : int          Attacker's TCP sequence number.
    peer_payload_len : int  Length of attacker's TCP payload (to compute ACK).

    Returns
    -------
    bytes   Complete packet ready for PacketOut.
    """

    # Get TCP state for this connection
    state = get_tcp_state(attacker_ip, attacker_port, decoy_ip)
    our_seq = state["our_seq"]
    our_ack = peer_seq + peer_payload_len  # ACK the attacker's data

    # Build layers inside-out: TCP payload → TCP → IP → Ethernet
    tcp_hdr = build_tcp_header(
        src_ip=decoy_ip,
        dst_ip=attacker_ip,
        src_port=20000,            # DNP3 standard port
        dst_port=attacker_port,
        seq=our_seq,
        ack=our_ack,
        window=profile["tcp_window"],
        payload=dnp3_frame,
    )

    ip_hdr = build_ipv4_header(
        src_ip=decoy_ip,
        dst_ip=attacker_ip,
        ttl=profile["ttl"],
        payload_len=len(tcp_hdr) + len(dnp3_frame),
    )

    eth_hdr = build_ethernet_header(
        dst_mac=attacker_mac,
        src_mac=profile["mac"],
    )

    packet = eth_hdr + ip_hdr + tcp_hdr + dnp3_frame

    # Update TCP state: advance our sequence number by payload length
    update_tcp_state(attacker_ip, attacker_port, decoy_ip,
                     our_ack, len(dnp3_frame))

    return packet


# ===========================================================================
# Digest Processing — The Core Logic
# ===========================================================================

# Counters for statistics
stats = {
    "digests_received": 0,
    "responses_sent": 0,
    "attacks_logged": 0,
    "errors": 0,
}


def process_digest(digest_data: dict, interface) -> None:
    """
    Process a single digest message from the P4 data plane.

    The digest contains metadata extracted by the P4 parser:
      - src_ip        : attacker's IPv4 address (as int or string)
      - src_port      : attacker's TCP source port
      - dst_ip        : decoy's IPv4 address (the target)
      - src_mac       : attacker's MAC address
      - func_code     : DNP3 application function code
      - dnp3_src_addr : DNP3 source address (master)
      - dnp3_dst_addr : DNP3 destination address (outstation)
      - tcp_seq       : attacker's TCP sequence number
      - tcp_payload_len : length of attacker's TCP payload
      - ingress_port  : switch port the packet arrived on

    Parameters
    ----------
    digest_data : dict
        Parsed digest fields.
    interface : gc.ClientInterface
        bfrt_grpc client for PacketOut.
    """
    stats["digests_received"] += 1

    # --- Extract fields from digest ----------------------------------------
    src_ip       = digest_data.get("src_ip", "0.0.0.0")
    src_port     = digest_data.get("src_port", 0)
    dst_ip       = digest_data.get("dst_ip", "0.0.0.0")
    src_mac      = digest_data.get("src_mac", "00:00:00:00:00:00")
    func_code    = digest_data.get("func_code", 0)
    dnp3_src     = digest_data.get("dnp3_src_addr", DEFAULT_MASTER_ADDR)
    dnp3_dst     = digest_data.get("dnp3_dst_addr", 0)
    tcp_seq      = digest_data.get("tcp_seq", 0)
    tcp_ack      = digest_data.get("tcp_ack", 0)
    tcp_plen     = digest_data.get("tcp_payload_len", 0)
    ingress_port = digest_data.get("ingress_port", 0)

    # Convert IPs from int to dotted-quad if needed
    if isinstance(src_ip, int):
        src_ip = socket.inet_ntoa(struct.pack("!I", src_ip))
    if isinstance(dst_ip, int):
        dst_ip = socket.inet_ntoa(struct.pack("!I", dst_ip))

    # --- Look up device profile --------------------------------------------
    profile = get_profile(dst_ip)
    if profile is None:
        logger.warning("No profile for decoy IP %s — ignoring digest", dst_ip)
        stats["errors"] += 1
        return

    logger.info("DIGEST: %s:%d -> %s [%s] FC=0x%02X",
                src_ip, src_port, dst_ip, profile["name"], func_code)

    # Use the master's DNP3 address from the request
    master_addr = dnp3_src

    # --- Seed TCP state with ISN from the P4 SYN-ACK -----------------------
    # tcp_ack = our ISN + 1 (the attacker's ACK of our SYN).
    # Must be called before build_full_packet so our_seq is correct.
    if tcp_ack:
        get_tcp_state(src_ip, src_port, dst_ip, tcp_ack=tcp_ack)

    # --- Record the interaction (all interactions are suspicious) -----------
    log_interaction(src_ip, src_port, dst_ip, func_code, "processing")

    # --- Timing: record when we started processing -------------------------
    t_start = time.time()

    # --- Route by function code --------------------------------------------
    dnp3_frame = None
    action = ""

    if func_code == FC_READ:
        # Integrity Poll / Read request → return all data
        dnp3_frame = build_integrity_poll_response(profile, master_addr)
        action = "READ_RESPONSE: sent all data objects"

    elif func_code == FC_WRITE:
        # Write request → parameter error (read-only outstation)
        dnp3_frame = build_error_response(profile, master_addr,
                                          iin2=0x20)  # parameter error
        action = "WRITE_REJECTED: parameter error"

    elif func_code == FC_SELECT:
        # SBO Select → arm the control, respond success
        record_select(src_ip, dst_ip)
        dnp3_frame = build_control_response(profile, master_addr,
                                            status=0x00)  # armed OK
        action = "SELECT_ARMED: SBO control armed"
        log_attack(src_ip, src_port, dst_ip, func_code, "SELECT — control armed")

    elif func_code == FC_OPERATE:
        # SBO Operate → check if Select was received first
        valid_sbo = check_and_consume_select(src_ip, dst_ip)
        if valid_sbo:
            dnp3_frame = build_control_response(profile, master_addr,
                                                status=0x00)  # success
            action = "OPERATE_SUCCESS: SBO sequence complete"
        else:
            dnp3_frame = build_control_response(profile, master_addr,
                                                status=0x04)  # not selected
            action = "OPERATE_REJECTED: no prior Select"
        log_attack(src_ip, src_port, dst_ip, func_code,
                   f"OPERATE — {'valid SBO' if valid_sbo else 'NO prior Select'}")

    elif func_code == FC_DIRECT_OPERATE:
        # Direct Operate (no SBO) → respond success, log as attack
        dnp3_frame = build_control_response(profile, master_addr,
                                            status=0x00)
        action = "DIRECT_OPERATE: executed (decoy absorbed)"
        log_attack(src_ip, src_port, dst_ip, func_code,
                   "DIRECT OPERATE — control attempt")

    elif func_code in (FC_COLD_RESTART, FC_WARM_RESTART):
        # Restart request → function not supported
        dnp3_frame = build_error_response(profile, master_addr,
                                          iin2=0x80)  # func not supported
        action = f"RESTART_REJECTED: FC=0x{func_code:02X} not supported"

    elif func_code in (FC_ENABLE_UNSOL, FC_DISABLE_UNSOL):
        # Unsolicited enable/disable → acknowledge with empty response
        dnp3_frame = build_error_response(profile, master_addr,
                                          iin1=0x00, iin2=0x00)
        action = f"UNSOL_ACK: FC=0x{func_code:02X} acknowledged"

    else:
        # Unknown function code → function not supported
        dnp3_frame = build_error_response(profile, master_addr,
                                          iin2=0x80)
        action = f"UNKNOWN_FC: 0x{func_code:02X} → not supported"

    if dnp3_frame is None:
        logger.error("Failed to build DNP3 frame for FC=0x%02X", func_code)
        stats["errors"] += 1
        return

    # --- Timing emulation --------------------------------------------------
    # Sleep to match the real device's response latency.
    # This prevents the decoy from responding "too fast" and being
    # detected by timing analysis.
    elapsed_ms = (time.time() - t_start) * 1000.0
    target_ms = profile.get("response_ms", 8.0)
    if elapsed_ms < target_ms:
        time.sleep((target_ms - elapsed_ms) / 1000.0)

    # --- Build complete packet and inject ----------------------------------
    packet = build_full_packet(
        attacker_ip=src_ip,
        attacker_port=src_port,
        attacker_mac=src_mac,
        decoy_ip=dst_ip,
        profile=profile,
        dnp3_frame=dnp3_frame,
        peer_seq=tcp_seq,
        peer_payload_len=tcp_plen,
    )

    try:
        # Inject response via raw socket.
        # The bfrt_grpc API doesn't support PacketOut directly, so we
        # send the crafted Ethernet frame through the CPU port using a
        # raw socket.  The switch's data plane will forward it based on
        # the destination MAC/IP in the normal forwarding path.
        #
        # For this to work, the CPU/management veth or the internal
        # PCIe port must be connected.  As a fallback for the testbed,
        # we send directly from the switch's management NIC — the
        # response reaches the attacker via the management network or
        # we can use scapy's raw socket on any interface that has L2
        # access to the data plane.
        inject_raw_packet(packet, ingress_port)
        stats["responses_sent"] += 1
        logger.info("  -> %s (%d bytes injected on port %d)",
                    action, len(packet), ingress_port)
    except Exception as e:
        logger.error("Injection failed: %s", e)
        stats["errors"] += 1


# ===========================================================================
# Packet Injection via UDP to Hulk Helper
# ===========================================================================
# The bfrt_grpc API on this SDE does not support PacketOut, and the switch
# has no CPU-to-data-plane veth interface (no bf_pci0).
#
# Workaround: send the crafted Ethernet frame via UDP to a helper script
# running on Hulk (which has a 25G data-plane NIC).  The helper sends it
# as a raw frame on its NIC — the frame goes through the switch and
# reaches Vision (the attacker).
#
# This is a testbed workaround.  In a production deployment, the CPU port
# or a dedicated injection interface would be used.

import socket as sock_module

# Hulk's management IP and the helper's listening port
INJECT_HELPER_IP   = "10.10.54.136"   # Hulk management IP — adjust if different
INJECT_HELPER_PORT = 9999

_inject_sock = None


def inject_raw_packet(packet: bytes, ingress_port: int):
    """
    Send a crafted Ethernet frame to the injection helper on Hulk.
    The helper sends it as a raw frame on Hulk's 25G data-plane NIC,
    which goes through the switch to the attacker.
    """
    global _inject_sock

    if _inject_sock is None:
        _inject_sock = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_DGRAM)
        logger.info("Injection socket opened -> %s:%d (Hulk helper)",
                    INJECT_HELPER_IP, INJECT_HELPER_PORT)

    _inject_sock.sendto(packet, (INJECT_HELPER_IP, INJECT_HELPER_PORT))


# ===========================================================================
# Attack Logging
# ===========================================================================

def log_interaction(src_ip: str, src_port: int, dst_ip: str,
                    func_code: int, note: str):
    """Log every interaction with a decoy device."""
    logger.info("INTERACTION: %s:%d -> %s  FC=0x%02X  %s",
                src_ip, src_port, dst_ip, func_code, note)


def log_attack(src_ip: str, src_port: int, dst_ip: str,
               func_code: int, detail: str):
    """
    Log a high-priority attack event.

    These are written to both the console log and a separate attack_log.txt
    file for post-experiment analysis.
    """
    stats["attacks_logged"] += 1
    msg = (f"ATTACK | src={src_ip}:{src_port} | dst={dst_ip} | "
           f"FC=0x{func_code:02X} | {detail}")
    logger.warning("*** %s", msg)
    attack_logger.info(msg)


# ===========================================================================
# Digest Polling Helpers
# ===========================================================================

def parse_digest_entry(entry) -> dict:
    """
    Parse a single digest entry from the bfrt_grpc digest notification
    into a plain dict.

    The exact field names depend on the P4 program's digest definition.
    Adjust field names here if your P4 program uses different names.

    Parameters
    ----------
    entry : digest data entry from bfrt_grpc

    Returns
    -------
    dict with parsed fields.
    """
    # The digest entry is a list of (field_name, value) tuples.
    # Convert to dict.  bfrt_grpc returns field values as bytes or ints
    # depending on the field width.
    d = {}
    for field_name, value in entry:
        if field_name == "src_ip":
            d["src_ip"] = value  # int, will convert later
        elif field_name == "dst_ip":
            d["dst_ip"] = value
        elif field_name == "src_port":
            d["src_port"] = value
        elif field_name == "src_mac":
            # MAC may come as int or bytes — normalize to string
            if isinstance(value, int):
                mac_bytes = value.to_bytes(6, "big")
                d["src_mac"] = ":".join(f"{b:02x}" for b in mac_bytes)
            elif isinstance(value, bytes):
                d["src_mac"] = ":".join(f"{b:02x}" for b in value)
            else:
                d["src_mac"] = str(value)
        elif field_name == "func_code":
            d["func_code"] = value
        elif field_name == "dnp3_src_addr":
            d["dnp3_src_addr"] = value
        elif field_name == "dnp3_dst_addr":
            d["dnp3_dst_addr"] = value
        elif field_name == "tcp_seq":
            d["tcp_seq"] = value
        elif field_name == "tcp_payload_len":
            d["tcp_payload_len"] = value
        elif field_name == "tcp_ack":
            d["tcp_ack"] = value
        elif field_name == "ingress_port":
            d["ingress_port"] = value
        else:
            # Store any unexpected fields for debugging
            d[field_name] = value

    return d


# ===========================================================================
# Main Loop
# ===========================================================================

def main():
    """Connect to the switch and start the digest processing loop."""

    # --- Parse command-line arguments --------------------------------------
    parser = argparse.ArgumentParser(
        description="P4-based DNP3 Decoy Controller"
    )
    parser.add_argument(
        "--switch-addr", default=SWITCH_GRPC_ADDR,
        help=f"Tofino gRPC address (default: {SWITCH_GRPC_ADDR})"
    )
    parser.add_argument(
        "--program", default=P4_PROGRAM_NAME,
        help=f"P4 program name (default: {P4_PROGRAM_NAME})"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug-level logging"
    )
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # --- Print banner ------------------------------------------------------
    logger.info("=" * 60)
    logger.info("  DNP3 Decoy Controller")
    logger.info("  Switch: %s", args.switch_addr)
    logger.info("  P4 program: %s", args.program)
    logger.info("  Decoy devices:")
    for ip, prof in DEVICE_PROFILES.items():
        logger.info("    %-14s  %-20s  DNP3 addr %d",
                     ip, prof["name"], prof["dnp3_addr"])
    logger.info("=" * 60)

    # --- Connect to the Tofino switch via gRPC -----------------------------
    logger.info("Connecting to switch at %s ...", args.switch_addr)
    try:
        interface = gc.ClientInterface(
            grpc_addr=args.switch_addr,
            client_id=CLIENT_ID,
            device_id=DEVICE_ID,
        )
        interface.bind_pipeline_config(args.program)
        bfrt_info = interface.bfrt_info_get()
        logger.info("Connected. Pipeline: %s", args.program)
    except Exception as e:
        logger.error("Failed to connect to switch: %s", e)
        logger.error("Is bf_switchd running?  Is the gRPC address correct?")
        sys.exit(1)

    # --- Get the digest table reference ------------------------------------
    # The P4 program defines a digest named "dnp3_digest_t" (or similar).
    # We need to subscribe to it.
    try:
        learn_filter = bfrt_info.learn_get("dnp3_digest_t")
        learn_filter.info.data_field_name_list_get()
        logger.info("Subscribed to digest: dnp3_digest_t")
    except Exception as e:
        logger.warning("Could not find digest 'dnp3_digest_t': %s", e)
        logger.warning("Trying generic digest subscription...")
        learn_filter = None

    # --- Graceful shutdown handler -----------------------------------------
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        logger.info("Caught signal %d — shutting down...", sig)
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # --- Main polling loop -------------------------------------------------
    logger.info("Entering digest polling loop (Ctrl+C to stop)...")
    logger.info("")

    while running:
        try:
            # Poll for digest messages from the switch.
            # digest_get() returns a list of digest entries, or raises
            # an exception if no digests are available.
            try:
                digest = interface.digest_get(timeout=1)
            except Exception:
                # No digest available — this is normal, just loop
                time.sleep(DIGEST_POLL_INTERVAL)
                continue

            if digest is None:
                time.sleep(DIGEST_POLL_INTERVAL)
                continue

            # Process digest entries.
            # The bfrt_grpc returns a raw protobuf DigestList.
            # It has .data[] entries, each with .fields[] containing
            # field_id (int) and stream (bytes).
            #
            # Our P4 digest fields by field_id (order matches P4 struct):
            #   1: src_ip        (4 bytes)
            #   2: src_port      (2 bytes)
            #   3: dst_ip        (4 bytes)
            #   4: dst_port      (2 bytes)
            #   5: func_code     (1 byte)
            #   6: obj_group     (1 byte)
            #   7: dnp3_dst_addr (2 bytes)
            #   8: dnp3_src_addr (2 bytes)
            #   9: ingress_port  (2 bytes)

            try:
                entries = digest.data if hasattr(digest, 'data') else [digest]
            except Exception:
                entries = [digest]

            for entry in entries:
                try:
                    # Parse raw protobuf fields into a dict
                    fields = {}
                    if hasattr(entry, 'fields'):
                        for f in entry.fields:
                            fields[f.field_id] = f.stream
                    elif hasattr(entry, 'data'):
                        # Nested: entry.data contains fields
                        for f in entry.data.fields:
                            fields[f.field_id] = f.stream

                    if not fields:
                        logger.warning("Empty digest entry, skipping")
                        continue

                    # Decode bytes to integers
                    def to_int(b):
                        return int.from_bytes(b, byteorder='big')

                    digest_data = {
                        "src_ip":        to_int(fields.get(1, b'\x00\x00\x00\x00')),
                        "src_port":      to_int(fields.get(2, b'\x00\x00')),
                        "dst_ip":        to_int(fields.get(3, b'\x00\x00\x00\x00')),
                        "dst_port":      to_int(fields.get(4, b'\x00\x00')),
                        "func_code":     to_int(fields.get(5, b'\x00')),
                        "obj_group":     to_int(fields.get(6, b'\x00')),
                        "dnp3_dst_addr": to_int(fields.get(7, b'\x00\x00')),
                        "dnp3_src_addr": to_int(fields.get(8, b'\x00\x00')),
                        "ingress_port":  to_int(fields.get(9, b'\x00\x00')),
                    }

                    # Debug: log first few digests
                    if stats["digests_received"] < 5:
                        src = f"{(digest_data['src_ip']>>24)&0xFF}.{(digest_data['src_ip']>>16)&0xFF}.{(digest_data['src_ip']>>8)&0xFF}.{digest_data['src_ip']&0xFF}"
                        dst = f"{(digest_data['dst_ip']>>24)&0xFF}.{(digest_data['dst_ip']>>16)&0xFF}.{(digest_data['dst_ip']>>8)&0xFF}.{digest_data['dst_ip']&0xFF}"
                        logger.info("DIGEST: %s:%d -> %s:%d  FC=0x%02X  ObjGrp=%d  DNP3[%d->%d]  port=%d",
                                    src, digest_data['src_port'],
                                    dst, digest_data['dst_port'],
                                    digest_data['func_code'],
                                    digest_data['obj_group'],
                                    digest_data['dnp3_src_addr'],
                                    digest_data['dnp3_dst_addr'],
                                    digest_data['ingress_port'])

                    process_digest(digest_data, interface)
                except Exception as e:
                    logger.error("Error processing digest entry: %s", e)
                    stats["errors"] += 1

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error("Unexpected error in main loop: %s", e)
            stats["errors"] += 1
            time.sleep(0.1)  # Brief pause before retrying

    # --- Shutdown ----------------------------------------------------------
    logger.info("")
    logger.info("=" * 60)
    logger.info("  Shutting down DNP3 Decoy Controller")
    logger.info("  Digests received : %d", stats["digests_received"])
    logger.info("  Responses sent   : %d", stats["responses_sent"])
    logger.info("  Attacks logged   : %d", stats["attacks_logged"])
    logger.info("  Errors           : %d", stats["errors"])
    logger.info("=" * 60)

    # Clean up gRPC connection
    try:
        interface._tear_down_stream()
    except Exception:
        pass

    logger.info("Done.")


# ===========================================================================
# Entry Point
# ===========================================================================

if __name__ == "__main__":
    main()
