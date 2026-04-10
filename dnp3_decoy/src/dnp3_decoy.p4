/*******************************************************************************
 * dnp3_decoy.p4
 *
 * P4-based DNP3 decoy for ICS/SCADA deception research.
 *
 * What this does:
 *   - Intercepts ARP requests and DNP3/TCP traffic aimed at decoy IPs
 *   - Synthesizes ARP replies with vendor-appropriate MACs
 *   - Synthesizes ICMP echo replies for decoy IPs (ping response)
 *   - Rewrites TTL and TCP window to match decoy device OS fingerprint
 *   - Parses DNP3 over TCP (port 20000) to extract function code + objects
 *   - Sends digest to controller with DNP3 metadata, then drops the packet
 *     (controller builds and injects the full DNP3 response)
 *   - Forwards non-decoy traffic normally via IPv4 LPM
 *
 * Target: Tofino 1 (TNA), BF-SDE 9.13.x
 * Author: Philip
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IP_PROTO_TCP   = 6;
const bit<8>  IP_PROTO_ICMP  = 1;
const bit<16> DNP3_TCP_PORT  = 20000;  // DNP3 over TCP standard port

// DNP3 start bytes: 0x05 then 0x64
const bit<8>  DNP3_START_0   = 0x05;
const bit<8>  DNP3_START_1   = 0x64;

// ARP opcodes
const bit<16> ARP_REQUEST    = 1;
const bit<16> ARP_REPLY      = 2;

// ICMP types
const bit<8>  ICMP_ECHO_REQUEST = 8;
const bit<8>  ICMP_ECHO_REPLY   = 0;

// TCP flag bits (within the 8-bit TCP flags field)
const bit<8>  TCP_FLAG_SYN     = 0x02;
const bit<8>  TCP_FLAG_SYNACK  = 0x12;
const bit<8>  TCP_FLAG_RSTACK  = 0x14;  // RST + ACK (closed port)

// Switch MAC used as source MAC for ARP replies to non-decoy queries.
// Decoy ARP replies use vendor-specific MACs from the table.
const bit<48> SWITCH_MAC = 0x00_00_00_00_00_01;

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_addr_len;
    bit<8>  proto_addr_len;
    bit<16> opcode;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

// RST marker — only used as a 1-bit deparser condition for checksum.
// Set valid in the RST path; never emitted.
header tcp_rst_marker_h {
    bit<8> _pad;
}

// TCP MSS option (4 bytes) — included in SYN-ACK for OS fingerprint
header tcp_mss_option_h {
    bit<8>  kind;    // 2 = Maximum Segment Size
    bit<8>  length;  // 4
    bit<16> mss;     // 1460 typical for Ethernet
}

header icmp_h {
    bit<8>  type_;
    bit<8>  code;
    bit<16> checksum;
    // Rest of ICMP header (identifier + sequence for echo)
    bit<16> identifier;
    bit<16> seq_num;
}

// DNP3 Data Link Layer header (10 bytes total, but we skip CRC in parsing)
// NOTE: DNP3 addresses are little-endian on the wire, but P4 extracts
// them as big-endian bit<16>. The controller must byte-swap when interpreting.
header dnp3_datalink_h {
    bit<8>  start_0;        // 0x05
    bit<8>  start_1;        // 0x64
    bit<8>  length;         // Length of user data + CRCs after this header
    bit<8>  ctrl;            // Direction, PRM, FCB, FCV, function code
    bit<16> dst_addr;       // Destination address (little-endian on wire)
    bit<16> src_addr;       // Source address (little-endian on wire)
    bit<16> crc;            // CRC-16 of bytes 0-7, we just extract and ignore
}

// DNP3 Transport Layer (1 byte)
header dnp3_transport_h {
    bit<1>  fin;            // Final fragment
    bit<1>  fir;            // First fragment
    bit<6>  seq;            // Sequence number
}

// DNP3 Application Layer (we only need the first 4 bytes)
header dnp3_application_h {
    bit<8>  app_control;    // FIR, FIN, CON, UNS + 4-bit sequence
    bit<8>  func_code;      // 0x01=Read, 0x03=Select, 0x04=Operate, etc.
    bit<8>  obj_group;      // Object group number (if present)
    bit<8>  obj_variation;  // Object variation (if present)
}

/*==============================================================================
 * METADATA
 *============================================================================*/

// Digest sent to the controller when we intercept a DNP3 query to a decoy
struct dnp3_digest_t {
    bit<32> src_ip;
    bit<16> src_port;
    bit<32> dst_ip;
    bit<16> dst_port;
    bit<8>  dnp3_func_code;
    bit<8>  dnp3_obj_group;
    bit<16> dnp3_dst_addr;   // DNP3 destination address
    bit<16> dnp3_src_addr;   // DNP3 source address
    bit<48> src_mac;         // Attacker's MAC (for response injection)
    bit<32> tcp_seq;         // Attacker's TCP sequence number
    bit<32> tcp_ack;         // Attacker's TCP ACK (reveals our ISN)
    bit<16> tcp_payload_len; // TCP payload length (for ACK computation)
    PortId_t ingress_port;
}

struct metadata_t {
    bit<1>  is_decoy;        // 1 if dst IP matches a decoy
    bit<48> decoy_mac;       // Vendor MAC for this decoy device
    bit<8>  decoy_ttl;       // OS fingerprint TTL
    bit<16> decoy_tcp_win;   // OS fingerprint TCP window size
    bit<1>  is_dnp3;         // 1 if this is a DNP3 packet (TCP port 20000)
    bit<32> syn_cookie;      // Hash-based ISN for SYN-ACK
    bit<16> tcp_seg_len;     // TCP segment length for checksum pseudo-header
    bit<16> tcp_payload_len; // TCP payload length (for digest)
    PortId_t ingress_port;   // Saved for deparser (digest needs it)
}

struct headers_t {
    ethernet_h         ethernet;
    arp_h              arp;
    ipv4_h             ipv4;
    tcp_h              tcp;
    tcp_mss_option_h   tcp_mss;        // SYN-ACK MSS option (invalid unless synthesizing)
    tcp_rst_marker_h   tcp_rst_marker; // RST checksum marker (never emitted)
    icmp_h             icmp;
    dnp3_datalink_h    dnp3_dl;
    dnp3_transport_h   dnp3_tp;
    dnp3_application_h dnp3_app;
}

/*==============================================================================
 * INGRESS PARSER
 *============================================================================*/

parser DecoyIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        // Initialize metadata
        meta.is_decoy      = 0;
        meta.decoy_mac      = 0;
        meta.decoy_ttl      = 0;
        meta.decoy_tcp_win  = 0;
        meta.is_dnp3         = 0;
        meta.syn_cookie      = 0;
        meta.tcp_seg_len     = 0;
        meta.tcp_payload_len = 0;
        meta.ingress_port    = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP  : parse_tcp;
            IP_PROTO_ICMP : parse_icmp;
            default       : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        // Only attempt DNP3 parsing for non-SYN packets to port 20000.
        // SYN packets have no DNP3 payload; trying to parse would cause
        // a parser error or extract garbage from TCP options.
        transition select(hdr.tcp.dst_port, hdr.tcp.flags[1:1]) {
            (DNP3_TCP_PORT, 1w0) : skip_tcp_options;  // Not SYN -> skip opts, try DNP3
            default              : accept;              // SYN or other port
        }
    }

    // Skip TCP options before DNP3 payload.
    // Tofino 1 requires constant advance amounts, so we dispatch on
    // data_offset (TCP header length in 32-bit words).  Without this,
    // TCP timestamps would be misinterpreted as DNP3 start bytes and
    // real nmap/TCP-stack traffic would never reach the controller.
    state skip_tcp_options {
        transition select(hdr.tcp.data_offset) {
            5  : parse_dnp3_datalink;  // No options — go straight to DNP3
            6  : skip_opt_4;
            7  : skip_opt_8;
            8  : skip_opt_12;          // Common: timestamps (12 bytes)
            9  : skip_opt_16;
            10 : skip_opt_20;          // Common: MSS+TS+WS+SACK (20 bytes)
            11 : skip_opt_24;
            12 : skip_opt_28;
            13 : skip_opt_32;
            14 : skip_opt_36;
            15 : skip_opt_40;
            default : accept;
        }
    }

    state skip_opt_4  { pkt.advance(32);  transition parse_dnp3_datalink; }
    state skip_opt_8  { pkt.advance(64);  transition parse_dnp3_datalink; }
    state skip_opt_12 { pkt.advance(96);  transition parse_dnp3_datalink; }
    state skip_opt_16 { pkt.advance(128); transition parse_dnp3_datalink; }
    state skip_opt_20 { pkt.advance(160); transition parse_dnp3_datalink; }
    state skip_opt_24 { pkt.advance(192); transition parse_dnp3_datalink; }
    state skip_opt_28 { pkt.advance(224); transition parse_dnp3_datalink; }
    state skip_opt_32 { pkt.advance(256); transition parse_dnp3_datalink; }
    state skip_opt_36 { pkt.advance(288); transition parse_dnp3_datalink; }
    state skip_opt_40 { pkt.advance(320); transition parse_dnp3_datalink; }

    // Parse DNP3 data link header — validate start bytes
    state parse_dnp3_datalink {
        pkt.extract(hdr.dnp3_dl);
        // Verify DNP3 magic bytes: 0x05 0x64
        transition select(hdr.dnp3_dl.start_0, hdr.dnp3_dl.start_1) {
            (DNP3_START_0, DNP3_START_1) : parse_dnp3_transport;
            default                      : accept;  // Not valid DNP3, stop
        }
    }

    state parse_dnp3_transport {
        pkt.extract(hdr.dnp3_tp);
        transition parse_dnp3_application;
    }

    // Extract function code and first object group/variation
    state parse_dnp3_application {
        pkt.extract(hdr.dnp3_app);
        transition accept;
    }
}

/*==============================================================================
 * INGRESS CONTROL
 *============================================================================*/

control DecoyIngress(
        inout headers_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    /* ------------------------------------------------------------------
     * Action: drop a packet
     * ----------------------------------------------------------------*/
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* ------------------------------------------------------------------
     * Hash: SYN cookie — deterministic ISN from the 4-tuple
     * ----------------------------------------------------------------*/
    Hash<bit<32>>(HashAlgorithm_t.CRC32) syn_cookie_hash;

    /* ------------------------------------------------------------------
     * Table: decoy_ips — classify destination IP as a decoy device
     *
     * Populated by controller at runtime, e.g.:
     *   10.0.1.20 -> SEL-3530:  MAC=00:30:a7:xx:xx:01, TTL=255, win=8192
     *   10.0.1.21 -> GE D20MX:  MAC=00:60:35:xx:xx:01, TTL=64,  win=4096
     *   10.0.2.20 -> ABB REC670: MAC=00:15:ac:xx:xx:01, TTL=128, win=8760
     * ----------------------------------------------------------------*/
    action set_decoy_profile(bit<48> mac, bit<8> ttl, bit<16> tcp_win) {
        meta.is_decoy      = 1;
        meta.decoy_mac      = mac;
        meta.decoy_ttl      = ttl;
        meta.decoy_tcp_win  = tcp_win;
    }

    table decoy_ips {
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            set_decoy_profile;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    /* ------------------------------------------------------------------
     * Table: decoy_arp — match ARP requests targeting decoy IPs
     *
     * Same set of IPs as decoy_ips, but matches on ARP target_proto_addr.
     * Returns the vendor MAC to use in the synthesized ARP reply.
     * ----------------------------------------------------------------*/
    action set_arp_decoy(bit<48> mac) {
        meta.is_decoy  = 1;
        meta.decoy_mac = mac;
    }

    table decoy_arp {
        key = {
            hdr.arp.target_proto_addr : exact;
        }
        actions = {
            set_arp_decoy;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    /* ------------------------------------------------------------------
     * Table: ipv4_forward — LPM forwarding for non-decoy traffic
     *
     * Populated by controller with normal routing entries.
     * ----------------------------------------------------------------*/
    action set_egress(PortId_t port, bit<48> dst_mac) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            set_egress;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    /* ------------------------------------------------------------------
     * Table: syn_cookie — compute hash-based ISN via hit path
     *
     * Tofino requires hash operations to go through a table's hit
     * pathway.  This table always matches when is_decoy == 1.
     * ----------------------------------------------------------------*/
    action compute_syn_cookie() {
        meta.syn_cookie = syn_cookie_hash.get({
            hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
            hdr.tcp.src_port,  hdr.tcp.dst_port
        });
    }

    table syn_cookie_tbl {
        key = { meta.is_decoy : exact; }
        actions = { compute_syn_cookie; NoAction; }
        const entries = {
            (1) : compute_syn_cookie();
        }
        default_action = NoAction;
    }

    /* ------------------------------------------------------------------
     * Apply block — the main pipeline logic
     * ----------------------------------------------------------------*/
    apply {

        // ============================================================
        // PATH 1: ARP handling
        // ============================================================
        if (hdr.arp.isValid() && hdr.arp.opcode == ARP_REQUEST) {
            // Check if this ARP request targets a decoy IP
            decoy_arp.apply();

            if (meta.is_decoy == 1) {
                // Synthesize ARP reply in the data plane:
                //   - Swap sender/target
                //   - Fill in the decoy's vendor MAC
                //   - Send back out the ingress port
                hdr.arp.opcode           = ARP_REPLY;
                hdr.arp.target_hw_addr   = hdr.arp.sender_hw_addr;
                bit<32> tmp_ip           = hdr.arp.sender_proto_addr;
                hdr.arp.sender_proto_addr = hdr.arp.target_proto_addr;
                hdr.arp.target_proto_addr = tmp_ip;
                hdr.arp.sender_hw_addr   = meta.decoy_mac;

                // Ethernet: reply goes back to whoever asked
                hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
                hdr.ethernet.src_addr = meta.decoy_mac;

                // Send back out the port it came in on
                ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            } else {
                // Non-decoy ARP: drop (or you could broadcast via multicast)
                drop();
            }

        // ============================================================
        // PATH 2: IPv4 traffic
        // ============================================================
        } else if (hdr.ipv4.isValid()) {

            // Save ingress port for the deparser (digest needs it)
            meta.ingress_port = ig_intr_md.ingress_port;

            // Step 1: Check if destination IP is a decoy
            decoy_ips.apply();
            syn_cookie_tbl.apply();  // Pre-compute ISN (only fires for decoys)

            if (meta.is_decoy == 1) {

                // --------------------------------------------------------
                // DECOY PATH: traffic aimed at a virtual device
                // --------------------------------------------------------

                // Step 2: ICMP echo reply synthesis
                if (hdr.icmp.isValid() && hdr.icmp.type_ == ICMP_ECHO_REQUEST) {
                    // Convert echo request to echo reply in the data plane.
                    // Swap IP src/dst, change ICMP type, fix TTL.
                    hdr.icmp.type_ = ICMP_ECHO_REPLY;
                    // Incremental checksum update: type changed from 8 to 0,
                    // difference is 0x0800. Add to existing checksum.
                    hdr.icmp.checksum = hdr.icmp.checksum + 16w0x0800;

                    bit<32> tmp_src     = hdr.ipv4.src_addr;
                    hdr.ipv4.src_addr   = hdr.ipv4.dst_addr;
                    hdr.ipv4.dst_addr   = tmp_src;
                    hdr.ipv4.ttl        = meta.decoy_ttl;

                    // Swap Ethernet MACs
                    bit<48> tmp_mac         = hdr.ethernet.src_addr;
                    hdr.ethernet.src_addr   = meta.decoy_mac;
                    hdr.ethernet.dst_addr   = tmp_mac;

                    // Send back out ingress port
                    ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

                // Step 3: TCP SYN to DNP3 port -> SYN-ACK in data plane
                //   nmap sees "open" instead of "filtered".  Uses a CRC32
                //   hash of the 4-tuple as ISN (SYN-cookie pattern).
                } else if (hdr.tcp.isValid()
                           && (hdr.tcp.flags & 8w0x12) == TCP_FLAG_SYN
                           && hdr.tcp.dst_port == DNP3_TCP_PORT) {

                    // TCP: SYN-ACK flags, sequence numbers, window
                    hdr.tcp.ack_no      = hdr.tcp.seq_no + 1;
                    hdr.tcp.seq_no      = meta.syn_cookie;
                    hdr.tcp.flags       = TCP_FLAG_SYNACK;
                    hdr.tcp.window      = meta.decoy_tcp_win;
                    hdr.tcp.data_offset = 4w6;  // 24 bytes (20 hdr + 4 MSS)
                    hdr.tcp.res         = 0;
                    hdr.tcp.urgent_ptr  = 0;

                    // MSS option — required for OS fingerprint (VxWorks)
                    hdr.tcp_mss.setValid();
                    hdr.tcp_mss.kind   = 2;
                    hdr.tcp_mss.length = 4;
                    hdr.tcp_mss.mss    = 1460;

                    // Swap TCP ports
                    bit<16> tmp_port      = hdr.tcp.src_port;
                    hdr.tcp.src_port      = hdr.tcp.dst_port;
                    hdr.tcp.dst_port      = tmp_port;

                    // Swap IPs, set OS-fingerprint TTL, trim to header-only
                    bit<32> tmp_ip2       = hdr.ipv4.src_addr;
                    hdr.ipv4.src_addr     = hdr.ipv4.dst_addr;
                    hdr.ipv4.dst_addr     = tmp_ip2;
                    hdr.ipv4.ttl          = meta.decoy_ttl;
                    hdr.ipv4.total_len    = 44;    // 20 IP + 24 TCP (with MSS)
                    hdr.ipv4.flags        = 3w0x2; // Don't Fragment

                    // Swap MACs, use vendor MAC as source
                    bit<48> tmp_mac2      = hdr.ethernet.src_addr;
                    hdr.ethernet.src_addr = meta.decoy_mac;
                    hdr.ethernet.dst_addr = tmp_mac2;

                    // Invalidate any partially-parsed DNP3 headers
                    hdr.dnp3_dl.setInvalid();
                    hdr.dnp3_tp.setInvalid();
                    hdr.dnp3_app.setInvalid();

                    // tcp_mss validity signals deparser to compute SYN-ACK checksum
                    meta.tcp_seg_len = 24;  // 20 hdr + 4 MSS

                    ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

                // Step 3b: TCP SYN to any other port -> RST+ACK (closed)
                //   nmap OS detection needs a closed-port RST probe.
                //   A real RTU only listens on 20000; everything else is
                //   closed.  RST carries the device TTL for fingerprinting.
                } else if (hdr.tcp.isValid()
                           && (hdr.tcp.flags & 8w0x12) == TCP_FLAG_SYN) {

                    hdr.tcp.ack_no      = hdr.tcp.seq_no + 1;
                    hdr.tcp.seq_no      = 0;
                    hdr.tcp.flags       = TCP_FLAG_RSTACK;
                    hdr.tcp.window      = 0;     // RST convention
                    hdr.tcp.data_offset = 4w5;   // 20 bytes, no options
                    hdr.tcp.res         = 0;
                    hdr.tcp.urgent_ptr  = 0;

                    bit<16> tmp_port2     = hdr.tcp.src_port;
                    hdr.tcp.src_port      = hdr.tcp.dst_port;
                    hdr.tcp.dst_port      = tmp_port2;

                    bit<32> tmp_ip3       = hdr.ipv4.src_addr;
                    hdr.ipv4.src_addr     = hdr.ipv4.dst_addr;
                    hdr.ipv4.dst_addr     = tmp_ip3;
                    hdr.ipv4.ttl          = meta.decoy_ttl;
                    hdr.ipv4.total_len    = 40;     // 20 IP + 20 TCP
                    hdr.ipv4.flags        = 3w0x2;  // Don't Fragment

                    bit<48> tmp_mac3      = hdr.ethernet.src_addr;
                    hdr.ethernet.src_addr = meta.decoy_mac;
                    hdr.ethernet.dst_addr = tmp_mac3;

                    // rst_marker validity signals deparser to compute RST checksum
                    meta.tcp_seg_len = 20;  // 20 hdr, no options
                    hdr.tcp_rst_marker.setValid();
                    hdr.tcp_rst_marker._pad = 0;

                    ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

                // Step 4: DNP3 data -> digest to controller, then drop
                } else if (hdr.tcp.isValid() && hdr.tcp.dst_port == DNP3_TCP_PORT
                           && hdr.dnp3_app.isValid()) {
                    // Parsed DNP3 application layer — send metadata to
                    // controller via digest.  TCP payload = total_len minus
                    // headers.  Use constant 40 (IHL=5 + data_offset=5) to
                    // stay within Tofino's single-stage ALU limit.
                    meta.tcp_payload_len = hdr.ipv4.total_len - 40;

                    ig_dprsr_md.digest_type = 1;

                    // Drop the original packet — controller handles the reply
                    drop();

                // Step 5: Any other TCP to decoy -> drop silently
                //   (handshake ACKs, FINs, RSTs, non-DNP3 data)
                } else if (hdr.tcp.isValid()) {
                    drop();

                } else {
                    // Other IP traffic to decoy (e.g. UDP) — just drop
                    drop();
                }

            } else {
                // --------------------------------------------------------
                // NORMAL PATH: non-decoy traffic — forward via LPM table
                // --------------------------------------------------------
                ipv4_forward.apply();
            }
        }
        // Anything else (non-ARP, non-IPv4) is dropped by default
        // because ig_tm_md.ucast_egress_port is not set.
    }
}

/*==============================================================================
 * INGRESS DEPARSER
 *============================================================================*/

control DecoyIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    // Digest instance for sending DNP3 metadata to the controller
    Digest<dnp3_digest_t>() dnp3_digest;

    // Checksum for IPv4 — recomputed because we modify TTL, src/dst
    Checksum() ipv4_checksum;

    // Checksum for TCP SYN-ACK (24 bytes: 20 hdr + 4 MSS option)
    Checksum() tcp_csum_sa;

    // Checksum for TCP RST+ACK (20 bytes: header only)
    Checksum() tcp_csum_rst;

    apply {
        // Pack the digest when the control block set digest_type = 1
        if (ig_dprsr_md.digest_type == 1) {
            dnp3_digest.pack({
                hdr.ipv4.src_addr,
                hdr.tcp.src_port,
                hdr.ipv4.dst_addr,
                hdr.tcp.dst_port,
                hdr.dnp3_app.func_code,
                hdr.dnp3_app.obj_group,
                hdr.dnp3_dl.dst_addr,
                hdr.dnp3_dl.src_addr,
                hdr.ethernet.src_addr,    // src_mac
                hdr.tcp.seq_no,           // tcp_seq
                hdr.tcp.ack_no,           // tcp_ack
                meta.tcp_payload_len,     // tcp_payload_len
                meta.ingress_port
            });
        }

        // Recompute IPv4 checksum (needed after TTL/address rewrites)
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        // TCP checksum for SYN-ACK (24-byte segment: 20 hdr + 4 MSS)
        if (hdr.tcp_mss.isValid()) {
            hdr.tcp.checksum = tcp_csum_sa.update({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0, hdr.ipv4.protocol,
                meta.tcp_seg_len,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgent_ptr,
                hdr.tcp_mss.kind, hdr.tcp_mss.length, hdr.tcp_mss.mss
            });
        }

        // TCP checksum for RST+ACK (20-byte segment: header only)
        if (hdr.tcp_rst_marker.isValid()) {
            hdr.tcp.checksum = tcp_csum_rst.update({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0, hdr.ipv4.protocol,
                meta.tcp_seg_len,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgent_ptr
            });
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_mss);   // Only emitted when valid (SYN-ACK path)
        pkt.emit(hdr.icmp);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/*==============================================================================
 * EGRESS (pass-through — all logic is in ingress)
 *============================================================================*/

struct egress_headers_t {
}

struct egress_metadata_t {
}

parser DecoyEgressParser(
        packet_in pkt,
        out egress_headers_t hdr,
        out egress_metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control DecoyEgress(
        inout egress_headers_t hdr,
        inout egress_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    apply { }
}

control DecoyEgressDeparser(
        packet_out pkt,
        inout egress_headers_t hdr,
        in egress_metadata_t meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

/*==============================================================================
 * PIPELINE ASSEMBLY
 *============================================================================*/

Pipeline(
    DecoyIngressParser(),
    DecoyIngress(),
    DecoyIngressDeparser(),
    DecoyEgressParser(),
    DecoyEgress(),
    DecoyEgressDeparser()
) pipe;

Switch(pipe) main;
