#!/usr/bin/env python3
"""
decode_dnp3_pcap.py — Independent DNP3 response decoder

Reads a pcap file and decodes DNP3 responses without Wireshark.
Prints human-readable output: breaker states, voltages, currents,
frequency, and counter values from each decoy's integrity poll response.

Usage:
    python3 decode_dnp3_pcap.py /tmp/dnp3_e2e_test.pcap

No dependencies beyond Python 3 standard library.
"""

import struct
import sys


# DNP3 constants
DNP3_START = b'\x05\x64'
DNP3_FC_RESPONSE = 0x81

# DNP3 object groups we care about
GROUP_BINARY_INPUT = 0x01
GROUP_COUNTER      = 0x14
GROUP_ANALOG_INPUT = 0x1E

# Human labels for analog points (by position in the profile)
ANALOG_LABELS = {
    0: "Voltage A",
    1: "Voltage B",
    2: "Current A",
    3: "Current B",
    4: "Frequency",
}

ANALOG_UNITS = {
    0: "V",
    1: "V",
    2: "A",
    3: "A",
    4: "Hz",
}


def read_pcap_packets(filepath):
    """
    Read a pcap file and yield (timestamp, raw_bytes) for each packet.
    Supports the standard pcap format (not pcapng).
    """
    with open(filepath, 'rb') as f:
        # Global header: 24 bytes
        magic = f.read(4)
        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            print(f"Error: not a pcap file (magic: {magic.hex()})")
            sys.exit(1)

        header = f.read(20)
        version_major, version_minor, _, _, snaplen, link_type = \
            struct.unpack(endian + 'HHiIII', header)

        # Read packets
        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = \
                struct.unpack(endian + 'IIII', pkt_header)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            yield (ts_sec + ts_usec / 1e6, pkt_data)


def parse_ethernet(data):
    """Parse Ethernet header, return (src_mac, dst_mac, ethertype, payload)."""
    if len(data) < 14:
        return None
    dst = ':'.join(f'{b:02x}' for b in data[0:6])
    src = ':'.join(f'{b:02x}' for b in data[6:12])
    ethertype = struct.unpack('!H', data[12:14])[0]
    return src, dst, ethertype, data[14:]


def parse_ipv4(data):
    """Parse IPv4 header, return (src_ip, dst_ip, protocol, ttl, payload)."""
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    total_len = struct.unpack('!H', data[2:4])[0]
    ttl = data[8]
    protocol = data[9]
    src = '.'.join(str(b) for b in data[12:16])
    dst = '.'.join(str(b) for b in data[16:20])
    return src, dst, protocol, ttl, data[ihl:total_len]


def parse_tcp(data):
    """Parse TCP header, return (src_port, dst_port, flags, payload)."""
    if len(data) < 20:
        return None
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    data_offset = (data[12] >> 4) * 4
    flags = data[13]
    return src_port, dst_port, flags, data[data_offset:]


def strip_dnp3_crcs(raw_frame):
    """
    Remove CRC bytes from a DNP3 frame, returning clean user data.

    DNP3 structure:
      - 10-byte DLL header (8 header bytes + 2-byte CRC)
      - User data in 16-byte blocks, each followed by 2-byte CRC
      - Last block may be shorter than 16 bytes
    """
    if len(raw_frame) < 10:
        return b'', 0, 0, 0

    # DLL header
    length = raw_frame[2]
    control = raw_frame[3]
    dst_addr = struct.unpack('<H', raw_frame[4:6])[0]
    src_addr = struct.unpack('<H', raw_frame[6:8])[0]
    # Skip header CRC (bytes 8-9)

    # User data starts at byte 10
    user_data_len = length - 5  # subtract control(1) + dst(2) + src(2)
    user_data = b''
    pos = 10
    remaining = user_data_len

    while remaining > 0 and pos < len(raw_frame):
        block_len = min(16, remaining)
        if pos + block_len > len(raw_frame):
            block_len = len(raw_frame) - pos
        user_data += raw_frame[pos:pos + block_len]
        pos += block_len + 2  # skip 2-byte CRC
        remaining -= block_len

    return user_data, control, dst_addr, src_addr


def decode_dnp3_objects(obj_data):
    """
    Decode DNP3 object headers and point values.
    Returns a list of (group, variation, points) tuples.
    """
    objects = []
    p = 0

    while p + 5 <= len(obj_data):
        group = obj_data[p]
        variation = obj_data[p + 1]
        qualifier = obj_data[p + 2]
        start_idx = obj_data[p + 3]
        stop_idx = obj_data[p + 4]
        count = stop_idx - start_idx + 1
        p += 5

        points = []

        if group == GROUP_BINARY_INPUT and variation == 2:
            # Binary Input with flags: 1 byte per point
            for j in range(count):
                if p >= len(obj_data):
                    break
                flags = obj_data[p]
                value = flags & 0x01
                online = (flags >> 7) & 0x01
                points.append({
                    'index': start_idx + j,
                    'value': value,
                    'online': online,
                })
                p += 1

        elif group == GROUP_ANALOG_INPUT and variation == 5:
            # Analog Input 32-bit signed with flag: 5 bytes per point
            for j in range(count):
                if p + 5 > len(obj_data):
                    break
                flag = obj_data[p]
                value = struct.unpack('<i', obj_data[p + 1:p + 5])[0]
                points.append({
                    'index': start_idx + j,
                    'value': value,
                    'scaled': value / 100.0,
                    'online': flag & 0x01,
                })
                p += 5

        elif group == GROUP_COUNTER and variation == 5:
            # Counter 32-bit unsigned with flag: 5 bytes per point
            for j in range(count):
                if p + 5 > len(obj_data):
                    break
                flag = obj_data[p]
                value = struct.unpack('<I', obj_data[p + 1:p + 5])[0]
                points.append({
                    'index': start_idx + j,
                    'value': value,
                    'online': flag & 0x01,
                })
                p += 5
        else:
            # Unknown object group — stop parsing
            break

        objects.append((group, variation, points))

    return objects


def format_objects(objects):
    """Format decoded DNP3 objects as human-readable text."""
    lines = []

    for group, variation, points in objects:
        if group == GROUP_BINARY_INPUT:
            lines.append(f"  Binary Inputs (Group {group}, Var {variation}):")
            for pt in points:
                state = "CLOSED" if pt['value'] else "OPEN"
                status = "online" if pt['online'] else "OFFLINE"
                lines.append(f"    Point {pt['index']:2d}: {state:6s}  ({status})")

        elif group == GROUP_ANALOG_INPUT:
            lines.append(f"  Analog Inputs (Group {group}, Var {variation}):")
            for pt in points:
                idx = pt['index']
                label = ANALOG_LABELS.get(idx, f"Analog {idx}")
                unit = ANALOG_UNITS.get(idx, "")
                status = "online" if pt['online'] else "OFFLINE"
                lines.append(
                    f"    Point {idx}: {label:12s} = "
                    f"{pt['scaled']:10.2f} {unit:3s}  "
                    f"(raw={pt['value']}, {status})"
                )

        elif group == GROUP_COUNTER:
            lines.append(f"  Counters (Group {group}, Var {variation}):")
            for pt in points:
                status = "online" if pt['online'] else "OFFLINE"
                lines.append(
                    f"    Point {pt['index']:2d}: {pt['value']:10d}  ({status})"
                )

    return '\n'.join(lines)


# Known decoy devices (for display)
DECOY_NAMES = {
    10: "SEL-3530 RTAC",
    11: "GE D20MX",
    12: "ABB REC670",
}

DECOY_IPS = {
    "10.0.1.20": "SEL-3530 RTAC",
    "10.0.1.21": "GE D20MX",
    "10.0.2.20": "ABB REC670",
}


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 decode_dnp3_pcap.py <pcap_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"Reading: {filepath}")
    print()

    response_count = 0
    attack_count = 0

    for timestamp, pkt_data in read_pcap_packets(filepath):
        # Parse Ethernet → IPv4 → TCP
        eth = parse_ethernet(pkt_data)
        if eth is None or eth[2] != 0x0800:
            continue

        ipv4 = parse_ipv4(eth[3])
        if ipv4 is None or ipv4[2] != 6:  # TCP
            continue

        tcp = parse_tcp(ipv4[4])
        if tcp is None:
            continue

        src_port, dst_port, tcp_flags, tcp_payload = tcp

        # Only look at packets FROM port 20000 (responses from decoys)
        if src_port != 20000:
            continue

        # Must have enough data for a DNP3 frame
        if len(tcp_payload) < 12:
            continue

        # Check DNP3 start bytes
        if tcp_payload[0:2] != DNP3_START:
            continue

        # Parse DNP3 frame
        user_data, control, dst_addr, src_addr = strip_dnp3_crcs(tcp_payload)

        if len(user_data) < 5:
            continue

        # Transport layer
        transport = user_data[0]
        # Application layer
        app_control = user_data[1]
        func_code = user_data[2]
        iin1 = user_data[3]
        iin2 = user_data[4]

        src_ip = ipv4[0]
        dst_ip = ipv4[1]
        ttl = ipv4[3]
        device_name = DECOY_IPS.get(src_ip, f"Unknown ({src_ip})")

        if func_code == DNP3_FC_RESPONSE:
            response_count += 1
            print(f"--- Response #{response_count} from {device_name} ---")
            print(f"  Source IP: {src_ip}  TTL: {ttl}")
            print(f"  Source MAC: {eth[0]}")
            print(f"  DNP3 src_addr: {src_addr}  dst_addr: {dst_addr}")
            print(f"  Function Code: 0x{func_code:02X} (Response)")
            print(f"  IIN: 0x{iin1:02X} 0x{iin2:02X}")
            print()

            # Decode objects (skip transport + app_control + FC + IIN)
            obj_data = user_data[5:]
            objects = decode_dnp3_objects(obj_data)

            if objects:
                print(format_objects(objects))
            else:
                print("  (no data objects)")
            print()

    if response_count == 0:
        print("No DNP3 responses found in the capture.")
        print("Make sure the controller and inject helper are running.")
    else:
        print(f"Total: {response_count} DNP3 response(s) decoded.")


if __name__ == '__main__':
    main()
