#!/usr/bin/env python3
"""
inject_helper.py — Raw packet injection helper

Run this on Hulk (or any host with a data-plane NIC connected to the switch).
Listens on a UDP port for raw Ethernet frames from the controller,
then sends them out the 25G data-plane NIC.

Usage (on Hulk):
    sudo python3 inject_helper.py

The controller sends the fully-crafted Ethernet frame via UDP.
This script just pushes it out the NIC — no parsing, no modification.
"""

import socket
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("inject_helper")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LISTEN_IP   = "0.0.0.0"       # Listen on all interfaces
LISTEN_PORT = 9999             # UDP port for receiving frames from controller
DATA_IFACE  = "enp59s0f0np0"  # Hulk's 25G data-plane NIC

def main():
    # Open raw socket for sending Ethernet frames
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        raw_sock.bind((DATA_IFACE, 0))
        logger.info("Raw socket opened on %s", DATA_IFACE)
    except PermissionError:
        logger.error("Need sudo to open raw socket")
        sys.exit(1)
    except OSError as e:
        logger.error("Cannot open %s: %s", DATA_IFACE, e)
        sys.exit(1)

    # Open UDP socket for receiving frames from controller
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_IP, LISTEN_PORT))
    logger.info("Listening for packets on UDP %s:%d", LISTEN_IP, LISTEN_PORT)
    logger.info("Will inject on interface %s", DATA_IFACE)
    logger.info("Ready. Ctrl+C to stop.")

    count = 0
    try:
        while True:
            data, addr = udp_sock.recvfrom(65535)
            if len(data) < 14:
                logger.warning("Received too-short frame (%d bytes) from %s", len(data), addr)
                continue

            raw_sock.send(data)
            count += 1
            logger.info("Injected frame #%d (%d bytes) from %s", count, len(data), addr[0])

    except KeyboardInterrupt:
        logger.info("Shutting down. Injected %d frames total.", count)
    finally:
        raw_sock.close()
        udp_sock.close()


if __name__ == "__main__":
    main()
