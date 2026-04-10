"""
dnp3_frames.py — DNP3 Frame Builder
=====================================

This module constructs valid DNP3 response frames that can be injected
back through the Tofino switch via PacketOut.  Every frame includes
correct CRC-16/DNP checksums so that the attacker's DNP3 stack accepts
the response as genuine.

DNP3 Frame Anatomy (Response)
-----------------------------

  +------+------+--------+---------+------+------+-------+
  | 0x05 | 0x64 | Length | Control | Dst  | Src  | CRC   |
  |      |      | 1 byte | 1 byte  | 2 LE | 2 LE | 2 LE  |
  +------+------+--------+---------+------+------+-------+
  |<--- start -->|<------- 6 bytes covered by CRC ------->|

  Then one or more User Data Blocks:
  +------- up to 16 bytes of payload -------+-------+
  | Transport + Application layer data      | CRC   |
  |                                         | 2 LE  |
  +-----------------------------------------+-------+

CRC-16/DNP
----------
  Polynomial : 0x3D65
  Reflected  : yes (process LSB first — "reversed" table)
  Init       : 0x0000
  Final XOR  : 0xFFFF (take one's complement of result)

  We use a pre-computed 256-entry lookup table for speed.
"""

import struct
import logging

logger = logging.getLogger(__name__)

# ===========================================================================
# CRC-16/DNP Lookup Table (reflected polynomial 0xA6BC)
# ===========================================================================
# The "reflected" form of poly 0x3D65 is 0xA6BC.
# This table is the standard DNP3 CRC table found in IEEE 1815.

_CRC_TABLE = [0] * 256

def _build_crc_table():
    """Pre-compute the CRC-16/DNP lookup table (reflected algorithm)."""
    poly = 0xA6BC  # reflected form of 0x3D65
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        _CRC_TABLE[i] = crc & 0xFFFF

_build_crc_table()


def crc16_dnp(data: bytes) -> int:
    """
    Compute CRC-16/DNP over a byte sequence.

    Parameters
    ----------
    data : bytes
        The input data block (e.g. 6-byte DLL header or 16-byte user block).

    Returns
    -------
    int
        16-bit CRC value, already XORed with 0xFFFF (one's complement).
    """
    crc = 0x0000
    for byte in data:
        crc = (_CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)) & 0xFFFF
    # Final XOR — one's complement
    return crc ^ 0xFFFF


def _append_crc(data: bytes) -> bytes:
    """Append little-endian CRC-16/DNP to a data block."""
    crc = crc16_dnp(data)
    return data + struct.pack("<H", crc)


# ===========================================================================
# DNP3 Data Object Encoders
# ===========================================================================
# Each function returns raw bytes for the object header + point values.
# These go inside the Application Layer portion of the response.

def encode_binary_inputs(values: list) -> bytes:
    """
    Encode Binary Input objects — Group 1, Variation 2 (with flags).

    Each point is 1 byte:  bit 7 = ONLINE flag (0x80), bit 0 = value.

    Parameters
    ----------
    values : list of int
        List of 0 or 1 values for each binary input point.

    Returns
    -------
    bytes
        Object header + packed point values.
    """
    if not values:
        return b""

    count = len(values)

    # Object header: Group=1, Var=2, Qualifier=0x01 (8-bit start/stop)
    #   Qualifier 0x01 means "start index, stop index" each 1 byte
    header = struct.pack("BBBBB",
        0x01,           # Group 1: Binary Input
        0x02,           # Variation 2: with flags
        0x01,           # Qualifier: 8-bit start-stop index
        0x00,           # Start index: 0
        count - 1,      # Stop index
    )

    # Each point: flags byte.  Bit 7 = ONLINE, Bit 0 = value.
    point_data = b""
    for val in values:
        flags = 0x80 | (val & 0x01)  # ONLINE + value
        point_data += struct.pack("B", flags)

    return header + point_data


def encode_analog_inputs(values: list) -> bytes:
    """
    Encode Analog Input objects — Group 30, Variation 5 (32-bit with flag).

    Each point is 5 bytes: 1 flag byte + 4-byte signed int (little-endian).

    Parameters
    ----------
    values : list of int
        List of analog values (already scaled as needed).

    Returns
    -------
    bytes
        Object header + packed point values.
    """
    if not values:
        return b""

    count = len(values)

    # Object header: Group=30, Var=5, Qualifier=0x01 (8-bit start/stop)
    header = struct.pack("BBBBB",
        0x1E,           # Group 30 (0x1E): Analog Input
        0x05,           # Variation 5: 32-bit with flag
        0x01,           # Qualifier: 8-bit start-stop index
        0x00,           # Start index: 0
        count - 1,      # Stop index
    )

    # Each point: 1 flag byte (ONLINE=0x01) + 4-byte signed LE value
    point_data = b""
    for val in values:
        point_data += struct.pack("<Bi", 0x01, val)  # flag=ONLINE, value

    return header + point_data


def encode_counters(values: list) -> bytes:
    """
    Encode Counter objects — Group 20, Variation 5 (32-bit with flag).

    Each point is 5 bytes: 1 flag byte + 4-byte unsigned int (LE).

    Parameters
    ----------
    values : list of int
        List of counter values.

    Returns
    -------
    bytes
        Object header + packed point values.
    """
    if not values:
        return b""

    count = len(values)

    # Object header: Group=20, Var=5, Qualifier=0x01 (8-bit start/stop)
    header = struct.pack("BBBBB",
        0x14,           # Group 20 (0x14): Counter
        0x05,           # Variation 5: 32-bit with flag
        0x01,           # Qualifier: 8-bit start-stop index
        0x00,           # Start index: 0
        count - 1,      # Stop index
    )

    # Each point: 1 flag byte (ONLINE=0x01) + 4-byte unsigned LE value
    point_data = b""
    for val in values:
        point_data += struct.pack("<BI", 0x01, val)  # flag=ONLINE, value

    return header + point_data


# ===========================================================================
# Application Layer Builder
# ===========================================================================

def build_app_layer(func_code: int, iin1: int = 0x00, iin2: int = 0x00,
                    object_data: bytes = b"") -> bytes:
    """
    Build the DNP3 Application Layer (no CRC — that's added at DLL level).

    Parameters
    ----------
    func_code : int
        Application function code (e.g. 0x81 = Response).
    iin1 : int
        Internal Indications byte 1.
    iin2 : int
        Internal Indications byte 2.
    object_data : bytes
        Encoded data objects (binary inputs, analogs, counters, etc.).

    Returns
    -------
    bytes
        Application Control + Function Code + IIN + object data.
    """
    # Application Control: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
    app_control = 0xC0  # 1100_0000 = FIR + FIN

    app_layer = struct.pack("BBBB",
        app_control,
        func_code,
        iin1,
        iin2,
    ) + object_data

    return app_layer


# ===========================================================================
# Full DNP3 Frame Builder
# ===========================================================================

def build_response_frame(dst_addr: int, src_addr: int,
                         app_layer: bytes) -> bytes:
    """
    Build a complete DNP3 response frame with DLL header, transport
    header, user data blocks, and CRCs.

    This is the final byte sequence that goes inside the TCP payload.

    Parameters
    ----------
    dst_addr : int
        DNP3 destination address (the master who sent the request).
    src_addr : int
        DNP3 source address (the decoy outstation).
    app_layer : bytes
        The application layer payload (from build_app_layer).

    Returns
    -------
    bytes
        Complete DNP3 frame ready for transmission.
    """

    # ----- Step 1: Prepend transport header to application layer -----------
    # Transport byte: FIR=1, FIN=1, sequence=0 → 0xC0
    # (Single-fragment response — FIR and FIN both set)
    transport_byte = 0xC0
    user_data = struct.pack("B", transport_byte) + app_layer

    # ----- Step 2: Split user data into 16-byte blocks + CRC each ----------
    # DNP3 DLL rule: user data is sent in blocks of up to 16 bytes,
    # each followed by a 2-byte CRC.
    crc_blocks = b""
    offset = 0
    while offset < len(user_data):
        block = user_data[offset : offset + 16]
        crc_blocks += _append_crc(block)   # block + 2-byte CRC
        offset += 16

    # ----- Step 3: Build DLL header ----------------------------------------
    # Length field = number of bytes from Control through end of user data
    # (NOT counting start bytes, NOT counting CRCs in the user data area)
    # Formula: 5 (Control + Dst + Src + header_CRC... wait, no.)
    # Actually: Length = 5 + len(user_data)
    #   5 = 1 (Control) + 2 (Destination) + 2 (Source)
    #   plus the actual user data bytes (without CRCs).
    # The Length field counts from the Control byte through the last user
    # data byte, but does NOT count any CRC bytes.
    length = 5 + len(user_data)

    if length > 255:
        logger.warning("DNP3 frame too large (%d bytes), truncating", length)
        length = 255

    # Control byte for response:
    #   DIR=1 (from outstation), PRM=0 (secondary), FC=4 (unconfirmed user data)
    #   Binary: 0_1_000_100 = 0x44
    control = 0x44

    # Pack header fields (everything between start bytes and header CRC)
    header_fields = struct.pack("<BBH H",
        length,                    # Length
        control,                   # Control
        dst_addr & 0xFFFF,         # Destination (LE)
        src_addr & 0xFFFF,         # Source (LE)
    )
    # That's 6 bytes: Length(1) + Control(1) + Dst(2) + Src(2)

    # CRC covers these 6 bytes
    header_crc = crc16_dnp(header_fields)

    # Full DLL header = start bytes + header fields + CRC
    dll_header = struct.pack("BB", 0x05, 0x64) + header_fields + struct.pack("<H", header_crc)
    # dll_header is now 10 bytes: 0x05, 0x64, Length, Control, DstL, DstH, SrcL, SrcH, CRCL, CRCH

    # ----- Step 4: Concatenate DLL header + CRC'd user data blocks ----------
    frame = dll_header + crc_blocks

    logger.debug("Built DNP3 frame: %d bytes, dst_addr=%d, src_addr=%d",
                 len(frame), dst_addr, src_addr)
    return frame


# ===========================================================================
# High-Level Response Builders
# ===========================================================================
# These are the functions the controller calls directly.  Each one
# corresponds to a specific DNP3 scenario.

def build_integrity_poll_response(profile: dict, master_addr: int) -> bytes:
    """
    Build a full Integrity Poll response (FC 0x81) containing all data
    points from the device profile: binary inputs, analog inputs, counters.

    This is the response to Function Code 0x01 (Read) when the master
    requests Class 0 data (all static values).

    Parameters
    ----------
    profile : dict
        Device profile from DEVICE_PROFILES.
    master_addr : int
        DNP3 address of the requesting master.

    Returns
    -------
    bytes
        Complete DNP3 frame.
    """
    # Encode all data objects from the profile
    obj_data = b""
    obj_data += encode_binary_inputs(profile.get("binary_inputs", []))
    obj_data += encode_analog_inputs(profile.get("analog_inputs", []))
    obj_data += encode_counters(profile.get("counters", []))

    # Build application layer: FC 0x81 = Response, IIN = normal
    app = build_app_layer(func_code=0x81, iin1=0x00, iin2=0x00,
                          object_data=obj_data)

    return build_response_frame(
        dst_addr=master_addr,
        src_addr=profile["dnp3_addr"],
        app_layer=app,
    )


def build_error_response(profile: dict, master_addr: int,
                         iin1: int = 0x00, iin2: int = 0x00) -> bytes:
    """
    Build an error/status response with no data objects.
    The IIN bits communicate the error type.

    Common IIN2 error bits:
      bit 0 (0x01) = Class 1 data available
      bit 2 (0x04) = Object unknown
      bit 5 (0x20) = Parameter error
      bit 7 (0x80) = Function not supported

    Parameters
    ----------
    profile : dict
        Device profile.
    master_addr : int
        DNP3 address of the requesting master.
    iin1 : int
        IIN byte 1.
    iin2 : int
        IIN byte 2 — set the appropriate error bit.

    Returns
    -------
    bytes
        Complete DNP3 frame.
    """
    app = build_app_layer(func_code=0x81, iin1=iin1, iin2=iin2,
                          object_data=b"")

    return build_response_frame(
        dst_addr=master_addr,
        src_addr=profile["dnp3_addr"],
        app_layer=app,
    )


def build_control_response(profile: dict, master_addr: int,
                           status: int = 0x00) -> bytes:
    """
    Build a control response (for Select, Operate, Direct Operate).

    The response echoes back a CROB (Control Relay Output Block) with a
    status byte.  Status 0x00 = success.

    Parameters
    ----------
    profile : dict
        Device profile.
    master_addr : int
        DNP3 address of the requesting master.
    status : int
        Control status code (0x00 = success, 0x04 = not supported, etc.).

    Returns
    -------
    bytes
        Complete DNP3 frame.
    """
    # Build a minimal CROB echo: Group 12, Var 1, one point
    # CROB = Control Code(1) + Count(1) + On-time(4) + Off-time(4) + Status(1)
    crob_data = struct.pack("BBBBB",
        0x0C,       # Group 12: CROB
        0x01,       # Variation 1
        0x07,       # Qualifier: single-value, 1-byte index, 1-byte count
        0x01,       # Count: 1 object
        0x00,       # Index: 0
    )
    crob_obj = struct.pack("<BB I I B",
        0x03,       # Control code: latch-on (typical)
        0x01,       # Count: 1 trip
        1000,       # On-time ms
        1000,       # Off-time ms
        status,     # Status (0x00 = success)
    )

    app = build_app_layer(func_code=0x81, iin1=0x00, iin2=0x00,
                          object_data=crob_data + crob_obj)

    return build_response_frame(
        dst_addr=master_addr,
        src_addr=profile["dnp3_addr"],
        app_layer=app,
    )


# ===========================================================================
# Quick Self-Test
# ===========================================================================
# Run this file directly to verify CRC computation against known test vectors.

if __name__ == "__main__":
    # Test vector: CRC-16/DNP of empty input should be 0xFFFF
    assert crc16_dnp(b"") == 0xFFFF, "CRC of empty data should be 0xFFFF"

    # Test vector: CRC-16/DNP of "123456789" = 0xEA82
    # (from the CRC catalogue: poly=0x3D65, init=0, refin=True, refout=True, xorout=0xFFFF)
    test_crc = crc16_dnp(b"123456789")
    assert test_crc == 0xEA82, f"CRC of '123456789' expected 0xEA82, got 0x{test_crc:04X}"

    # Build a sample frame and verify it starts with 0x05 0x64
    from device_profiles import DEVICE_PROFILES
    profile = DEVICE_PROFILES["10.0.1.20"]
    frame = build_integrity_poll_response(profile, master_addr=1)
    assert frame[0] == 0x05 and frame[1] == 0x64, "Frame must start with 0x05 0x64"

    print(f"CRC self-test PASSED")
    print(f"Sample frame ({len(frame)} bytes): {frame.hex()}")
