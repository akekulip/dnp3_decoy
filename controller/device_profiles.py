"""
device_profiles.py — Decoy Device Configurations
==================================================

Each entry in DEVICE_PROFILES represents a virtual (non-existent) DNP3
outstation that the Tofino switch will impersonate.  When an attacker
sends a DNP3 query to one of these IPs, the controller looks up the
matching profile and builds a response that mimics the real device.

Fields
------
name            Human-readable device name (for logging)
dnp3_addr       DNP3 Data-Link-Layer address of the virtual outstation
mac             Ethernet MAC the response should carry as src
ttl             IP TTL — must match the real device's OS fingerprint
tcp_window      TCP window size — another OS-fingerprint field
response_ms     Target response latency in milliseconds (for timing
                emulation so the decoy doesn't answer "too fast")

binary_inputs   List of 0/1 values representing breaker/switch states
                  Object Group 1, Variation 2 (Binary Input with flags)
analog_inputs   List of integer values (scaled x100 for transmission)
                  Object Group 30, Variation 5 (32-bit analog, flag)
counters        List of integer counter values
                  Object Group 20, Variation 5 (32-bit counter, flag)
"""

# ---------------------------------------------------------------------------
# Device Profile Dictionary
# ---------------------------------------------------------------------------
# Key = decoy IP address (string)
# The P4 program maps attacker-destined packets to these IPs via a match
# table and sends a digest to the controller with the dst_ip field.

DEVICE_PROFILES = {

    # --- Substation 1: Distribution feeder protection -----------------------
    "10.0.1.20": {
        "name": "SEL-3530 RTAC",
        "dnp3_addr": 10,
        "mac": "00:30:a7:00:00:01",       # SEL OUI prefix 00:30:A7
        "ttl": 255,                         # SEL devices use TTL=255
        "tcp_window": 8192,
        "response_ms": 8.0,                 # typical RTAC response ~5-12 ms

        # 8 breaker/switch states: 1=closed, 0=open
        "binary_inputs": [1, 1, 0, 1, 0, 0, 1, 1],

        # Scaled analog values (x100):
        #   13800 = 138.00 V (line voltage phase A)
        #   13750 = 137.50 V (line voltage phase B)
        #   425   = 4.25 A  (current phase A)
        #   410   = 4.10 A  (current phase B)
        #   5998  = 59.98 Hz (frequency)
        "analog_inputs": [13800, 13750, 425, 410, 5998],

        # Accumulated event counters
        "counters": [147, 23, 891],
    },

    # --- Substation 2: Bus tie / capacitor bank ----------------------------
    "10.0.1.21": {
        "name": "GE D20MX",
        "dnp3_addr": 11,
        "mac": "00:60:35:00:00:01",       # GE OUI prefix 00:60:35
        "ttl": 64,                          # Linux-based, TTL=64
        "tcp_window": 4096,
        "response_ms": 12.0,               # D20MX is slower, ~8-15 ms

        "binary_inputs": [1, 0, 1, 1],
        "analog_inputs": [6920, 6880, 312, 5999],
        "counters": [52, 8],
    },

    # --- Substation 3: Transmission line relay -----------------------------
    "10.0.2.20": {
        "name": "ABB REC670",
        "dnp3_addr": 12,
        "mac": "00:15:ac:00:00:01",       # ABB OUI prefix 00:15:AC
        "ttl": 128,                         # VxWorks-based, TTL=128
        "tcp_window": 8760,
        "response_ms": 6.0,                # REC670 is fast, ~3-8 ms

        "binary_inputs": [1, 1, 1, 0, 0, 1],
        "analog_inputs": [23100, 23050, 180, 175, 6001],
        "counters": [234, 67, 12],
    },
}


# ---------------------------------------------------------------------------
# Master Station Address
# ---------------------------------------------------------------------------
# The SCADA master that polls these outstations.  In digests from the P4
# program, the dnp3_src_addr from the request becomes the destination
# address in the response.  This constant is a fallback if the digest
# doesn't include it.

DEFAULT_MASTER_ADDR = 1


# ---------------------------------------------------------------------------
# Helper: look up a profile by IP
# ---------------------------------------------------------------------------

def get_profile(ip: str) -> dict:
    """Return the device profile for the given decoy IP, or None."""
    return DEVICE_PROFILES.get(ip)
