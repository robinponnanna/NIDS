use std::net::{Ipv4Addr, Ipv6Addr};

// =============================================================================
// LINK TYPE
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LinkType {
    Ethernet,
    Wifi80211,
    RadiotapWifi,
    Unknown,
}

// =============================================================================
// PACKET METADATA  (populated by caller / capture engine, not from wire bytes)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    Ingress,
    Egress,
    Unknown,
}

/// Capture-engine metadata. Callers fill this and pass it into [`parse_packet`].
#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub timestamp_sec: u64,
    pub timestamp_nsec: u32,
    /// Number of bytes actually captured (snap length)
    pub captured_len: u32,
    /// Original wire length before truncation
    pub original_len: u32,
    pub interface_index: u32,
    pub interface_name: String,
    pub packet_number: u64,
    pub direction: Direction,
}

// =============================================================================
// ETHERNET
// =============================================================================

#[derive(Debug, Clone)]
pub struct EthernetInfo {
    /// EtherType after all VLAN tag stripping
    pub ether_type: u16,
    /// Inner 802.1Q VLAN ID (12-bit)
    pub vlan_id: Option<u16>,
    /// Inner 802.1Q Priority Code Point (3-bit)
    pub pcp: Option<u8>,
    /// Inner 802.1Q Drop Eligible Indicator
    pub dei: Option<bool>,
    /// Outer QinQ (802.1ad / 0x88A8) VLAN ID
    pub outer_vlan_id: Option<u16>,
    /// Outer QinQ Priority Code Point
    pub outer_pcp: Option<u8>,
    /// Total raw frame length in bytes (as received)
    pub frame_length: usize,
    /// Frame Check Sequence – only populated when the NIC exposes it
    pub fcs: Option<u32>,
}

// =============================================================================
// RADIOTAP
// =============================================================================

#[derive(Debug, Clone)]
pub struct RadiotapInfo {
    pub header_len: usize,
    /// dBm Antenna Signal (presence bit 5)
    pub dbm_antsignal: Option<i8>,
    /// Channel centre frequency in MHz (presence bit 3, bytes 0–1)
    pub channel: Option<u16>,
    /// Channel flags (presence bit 3, bytes 2–3)
    pub channel_flags: Option<u16>,
    /// Data rate in 500 Kbps units (presence bit 2)
    pub data_rate: Option<u16>,
    /// dBm Antenna Noise (presence bit 6)
    pub noise_level: Option<i8>,
    /// dBm TX Power (presence bit 10)
    pub tx_power: Option<i8>,
    /// RX Flags (presence bit 14)
    pub rx_flags: Option<u16>,
    /// Antenna index (presence bit 11)
    pub antenna_index: Option<u8>,
    /// MCS index (presence bit 19, byte 2 of the MCS field)
    pub mcs_index: Option<u8>,
    /// Bandwidth from MCS flags bits [1:0]: 0=20 MHz, 1=40 MHz, 2=20L, 3=20U
    pub bandwidth: Option<u8>,
    /// Hardware timestamp in microseconds (presence bit 22)
    pub timestamp: Option<u64>,
}

// =============================================================================
// IEEE 802.11 FRAME CONTROL
// =============================================================================

#[derive(Debug, Clone)]
pub struct Wifi80211Header {
    pub protocol_version: u8,
    pub frame_type: u8,
    pub frame_subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_fragments: bool,
    pub retry: bool,
    pub power_management: bool,
    pub more_data: bool,
    pub protected_frame: bool,
    pub order: bool,
    pub duration: u16,
    pub sequence_number: u16,
    pub fragment_number: u8,
    /// QoS Control field – present only for QoS data subtype frames
    pub qos_control: Option<u16>,
    /// HT Control field – present when Order bit is set in QoS data frames
    pub ht_control: Option<u32>,
}

// =============================================================================
// WI-FI MANAGEMENT IE SUPPORTING TYPES
// =============================================================================

#[derive(Debug, Clone)]
pub struct CountryInfo {
    pub country_code: [u8; 2],
    pub environment: u8,
    /// Raw triplet bytes (3 bytes each: first channel, channel count, max power)
    pub triplets: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TimInfo {
    pub dtim_count: u8,
    pub dtim_period: u8,
    pub bitmap_control: u8,
    pub partial_virtual_bitmap: Vec<u8>,
}

/// HT Capabilities IE (type 45). Full raw bytes preserved for detailed decode.
#[derive(Debug, Clone)]
pub struct HtCapabilities {
    pub ht_cap_info: u16,
    pub ampdu_params: u8,
    pub raw: Vec<u8>,
}

/// HT Operation IE (type 61). Full raw bytes preserved.
#[derive(Debug, Clone)]
pub struct HtOperation {
    pub primary_channel: u8,
    pub raw: Vec<u8>,
}

/// VHT Capabilities IE (type 191). Full raw bytes preserved.
#[derive(Debug, Clone)]
pub struct VhtCapabilities {
    pub vht_cap_info: u32,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VendorIe {
    pub oui: [u8; 3],
    pub oui_type: u8,
    pub data: Vec<u8>,
}

// =============================================================================
// RSN (WPA2/WPA3)
// =============================================================================

#[derive(Debug, Clone)]
pub struct RsnInfo {
    pub group_cipher: Option<u32>,
    pub pairwise_ciphers: Vec<u32>,
    pub akm_suites: Vec<u32>,
    pub capabilities: Option<u16>,
}

// =============================================================================
// WI-FI MANAGEMENT FRAME
// =============================================================================

#[derive(Debug, Clone)]
pub struct WifiMgmtFrame {
    // --- Original fields ---
    pub subtype: u8,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub rsn_info: Option<RsnInfo>,
    pub reason_code: Option<u16>,
    pub status_code: Option<u16>,
    pub bssid: [u8; 6],
    pub client_mac: Option<[u8; 6]>,
    /// Full management frame body (owned copy for zero-lifetime-constraint storage)
    pub raw_body: Vec<u8>,

    // --- Extended fields ---
    /// Beacon interval in TUs (1 TU = 1024 µs) – present in Beacon/Probe Response
    pub beacon_interval: Option<u16>,
    /// Capability Information bitmask
    pub capability_info: Option<u16>,
    /// IE type 1 – supported rates in 500 Kbps units (MSB = basic rate flag)
    pub supported_rates: Vec<u8>,
    /// IE type 50 – extended supported rates
    pub extended_supported_rates: Vec<u8>,
    /// IE type 7 – Country Information
    pub country_info: Option<CountryInfo>,
    /// IE type 5 – Traffic Indication Map
    pub tim: Option<TimInfo>,
    /// IE type 42 – ERP Information byte
    pub erp_info: Option<u8>,
    /// IE type 45 – HT Capabilities
    pub ht_capabilities: Option<HtCapabilities>,
    /// IE type 61 – HT Operation
    pub ht_operation: Option<HtOperation>,
    /// IE type 191 – VHT Capabilities
    pub vht_capabilities: Option<VhtCapabilities>,
    /// IE type 221 – all Vendor-Specific IEs collected in order
    pub vendor_ies: Vec<VendorIe>,
}

// =============================================================================
// NETWORK LAYER
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct ArpInfo {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct Ipv4Info<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    /// Flags bits: bit 1 = DF (Don't Fragment), bit 0 = MF (More Fragments)
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    /// IPv4 options bytes (empty when IHL == 5)
    pub options: Vec<u8>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Ipv6ExtHeader {
    pub header_type: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Ipv6Info<'a> {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    /// Next header in the fixed header (may point to an extension header)
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    /// All extension headers (Hop-by-Hop, Routing, Fragment, Destination, Mobility) in order
    pub extension_headers: Vec<Ipv6ExtHeader>,
    /// Next header value after walking all extension headers (the upper-layer protocol)
    pub final_next_header: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub enum NetworkLayer<'a> {
    Arp(ArpInfo),
    Ipv4(Ipv4Info<'a>),
    Ipv6(Ipv6Info<'a>),
    None,
}

// =============================================================================
// TRANSPORT LAYER
// =============================================================================

#[derive(Debug, Clone, Default)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_blocks: Vec<(u32, u32)>,
    /// (TSval, TSecr) from TCP Timestamp option (kind 8)
    pub timestamp: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct TcpInfo<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    /// Reserved bits (3 bits between data-offset and the NS flag)
    pub reserved: u8,
    /// Flag bits [8:0] = NS|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct UdpInfo<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct IcmpInfo<'a> {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    /// Present in Echo Request/Reply (type 8/0) and ICMPv6 Echo (128/129)
    pub identifier: Option<u16>,
    /// Present in Echo Request/Reply
    pub sequence_number: Option<u16>,
    /// Present in Destination Unreachable "Fragmentation Needed" (type 3, code 4)
    /// and ICMPv6 "Packet Too Big" (type 2)
    pub mtu: Option<u16>,
    /// Up to 28 bytes of the original IP header + 8 bytes of transport header
    /// (present in Destination Unreachable / Time Exceeded)
    pub embedded_header: Option<Vec<u8>>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpInfo<'a>),
    Udp(UdpInfo<'a>),
    Icmp(IcmpInfo<'a>),
    None,
}

// =============================================================================
// APPLICATION LAYER
// =============================================================================

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    /// Raw RDATA bytes – interpret per rtype in the detection layer
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    /// First question name (dot-separated)
    pub query: Option<String>,
    pub query_type: Option<u16>,
    pub query_class: Option<u16>,
    /// Answer records (up to answer_count)
    pub answers: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct DhcpInfo {
    /// xid – Transaction ID
    pub transaction_id: u32,
    /// ciaddr – Client IP address (non-zero in Request/Renew)
    pub client_ip: Ipv4Addr,
    /// yiaddr – Your (offered) IP address
    pub your_ip: Ipv4Addr,
    /// giaddr – Relay agent IP address
    pub relay_ip: Ipv4Addr,
    /// chaddr – Client hardware address (first 6 bytes)
    pub client_mac: [u8; 6],
    /// Option 53 – DHCP Message Type
    pub message_type: Option<u8>,
    /// Option 54 – Server Identifier
    pub server_ip: Option<Ipv4Addr>,
    /// Option 12 – Hostname
    pub hostname: Option<String>,
    /// Option 51 – IP Address Lease Time (seconds)
    pub lease_time: Option<u32>,
    /// Option 58 – Renewal Time T1 (seconds)
    pub renewal_time: Option<u32>,
    /// Option 60 – Vendor Class Identifier
    pub vendor_class: Option<String>,
    /// Option 55 – Parameter Request List
    pub parameter_request_list: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EapolInfo<'a> {
    pub version: u8,
    pub packet_type: u8,
    pub key_desc_type: u8,
    pub key_info: u16,

    // ── key_info bit fields ──────────────────────────────────────────────────
    /// Bits [2:0] – descriptor version
    /// 1 = RC4 / HMAC-MD5 (WPA1)
    /// 2 = AES / HMAC-SHA-1-128 (WPA2)
    /// 3 = AES / AES-128-CMAC (WPA3)
    pub descriptor_version: u8,
    pub install: bool,
    pub key_ack: bool,
    pub key_mic: bool,
    pub secure: bool,
    pub error: bool,
    pub request: bool,
    pub encrypted_key_data: bool,
    // ────────────────────────────────────────────────────────────────────────

    pub replay_counter: u64,
    /// Key Nonce (ANonce or SNonce, 32 bytes)
    pub key_nonce: [u8; 32],
    /// Key IV (16 bytes, all-zeros in WPA2)
    pub key_iv: [u8; 16],
    /// MIC (16 bytes)
    pub mic: [u8; 16],
    pub raw_key_data: &'a [u8],
}

#[derive(Debug, Clone)]
pub enum AppLayer<'a> {
    Dns(DnsInfo),
    Dhcp(DhcpInfo),
    Eapol(EapolInfo<'a>),
    None,
}

// =============================================================================
// TOP-LEVEL PARSED PACKET
// =============================================================================

#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    /// Capture-engine metadata – `None` when the caller does not supply it
    pub meta: Option<PacketMeta>,
    pub link_type: LinkType,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub bssid: Option<[u8; 6]>,
    pub signal_dbm: Option<i8>,
    pub channel: Option<u16>,
    pub malformed: bool,
    /// Ethernet-specific fields – `None` on pure Wi-Fi paths
    pub ethernet: Option<EthernetInfo>,
    /// 802.11 frame-control decoded fields – `None` on Ethernet paths
    pub wifi_header: Option<Wifi80211Header>,
    pub network: NetworkLayer<'a>,
    pub transport: TransportLayer<'a>,
    pub app: AppLayer<'a>,
    pub wifi_mgmt: Option<WifiMgmtFrame>,
    pub raw_payload: &'a [u8],
}

// =============================================================================
// PUBLIC ENTRY POINT
// =============================================================================

/// Parse a raw packet buffer into a [`ParsedPacket`].
///
/// * `data`         – raw bytes from the capture ring buffer (zero-copy sliced)
/// * `default_link` – link-layer type hint from pcap / socket metadata
/// * `meta`         – optional capture-engine metadata (timestamp, iface, etc.)
pub fn parse_packet<'a>(
    data: &'a [u8],
    default_link: LinkType,
    meta: Option<PacketMeta>,
) -> ParsedPacket<'a> {
    let mut pkt = ParsedPacket {
        meta,
        link_type: default_link,
        src_mac: [0; 6],
        dst_mac: [0; 6],
        bssid: None,
        signal_dbm: None,
        channel: None,
        malformed: false,
        ethernet: None,
        wifi_header: None,
        network: NetworkLayer::None,
        transport: TransportLayer::None,
        app: AppLayer::None,
        wifi_mgmt: None,
        raw_payload: &[],
    };

    if data.is_empty() {
        pkt.malformed = true;
        return pkt;
    }

    match default_link {
        LinkType::RadiotapWifi => {
            if let Some(rt_info) = parse_radiotap(data) {
                pkt.signal_dbm = rt_info.dbm_antsignal;
                pkt.channel = rt_info.channel;
                let offset = rt_info.header_len;
                if offset < data.len() {
                    parse_80211_frame(&data[offset..], &mut pkt);
                } else {
                    pkt.malformed = true;
                }
            } else {
                pkt.malformed = true;
            }
        }
        LinkType::Wifi80211 => {
            parse_80211_frame(data, &mut pkt);
        }
        LinkType::Ethernet => {
            parse_ethernet_frame(data, &mut pkt);
        }
        LinkType::Unknown => {
            // Auto-detect: radiotap starts with version byte == 0
            if data.len() >= 8 && data[0] == 0 {
                pkt.link_type = LinkType::RadiotapWifi;
                if let Some(rt_info) = parse_radiotap(data) {
                    pkt.signal_dbm = rt_info.dbm_antsignal;
                    pkt.channel = rt_info.channel;
                    let offset = rt_info.header_len;
                    if offset < data.len() {
                        parse_80211_frame(&data[offset..], &mut pkt);
                    } else {
                        pkt.malformed = true;
                    }
                } else {
                    pkt.malformed = true;
                }
            } else if data.len() >= 14 {
                pkt.link_type = LinkType::Ethernet;
                parse_ethernet_frame(data, &mut pkt);
            } else {
                pkt.malformed = true;
            }
        }
    }

    pkt
}

// =============================================================================
// 1. RADIOTAP PARSER
// =============================================================================

fn parse_radiotap(data: &[u8]) -> Option<RadiotapInfo> {
    if data.len() < 8 || data[0] != 0 {
        return None;
    }
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if header_len > data.len() || header_len < 8 {
        return None;
    }

    // Walk the chained presence-flags words.
    // Bit 31 of each word means "another word follows".
    // We only use the *first* word for field iteration (standard namespace).
    let mut presence = 0u32;
    let mut fp_off = 4usize;
    loop {
        if fp_off + 4 > header_len {
            break;
        }
        let f = u32::from_le_bytes([
            data[fp_off],
            data[fp_off + 1],
            data[fp_off + 2],
            data[fp_off + 3],
        ]);
        if presence == 0 {
            presence = f;
        }
        fp_off += 4;
        if (f & 0x8000_0000) == 0 {
            break;
        }
    }
    // fp_off now points to the first field byte (past all presence words)
    let mut off = fp_off;

    // ── Macros to keep field parsing concise ─────────────────────────────────
    macro_rules! skip {
        ($n:expr) => {
            if off + $n <= header_len {
                off += $n;
            } else {
                off = header_len;
            }
        };
    }
    macro_rules! align_to {
        ($a:expr) => {
            off = (off + $a - 1) & !($a - 1);
        };
    }
    macro_rules! present {
        ($bit:expr) => {
            (presence & (1u32 << $bit)) != 0
        };
    }
    // ─────────────────────────────────────────────────────────────────────────

    let mut dbm_antsignal = None;
    let mut channel = None;
    let mut channel_flags = None;
    let mut data_rate = None;
    let mut noise_level = None;
    let mut tx_power = None;
    let mut rx_flags = None;
    let mut antenna_index = None;
    let mut mcs_index = None;
    let mut bandwidth = None;
    let mut timestamp = None;

    // Bit 0: TSFT (8 bytes, align-8)
    if present!(0) {
        align_to!(8);
        skip!(8);
    }
    // Bit 1: Flags (1 byte)
    if present!(1) {
        skip!(1);
    }
    // Bit 2: Rate (1 byte, 500 Kbps units)
    if present!(2) {
        if off < header_len {
            data_rate = Some(data[off] as u16);
        }
        skip!(1);
    }
    // Bit 3: Channel (freq u16 + flags u16, align-2)
    if present!(3) {
        align_to!(2);
        if off + 4 <= header_len {
            channel = Some(u16::from_le_bytes([data[off], data[off + 1]]));
            channel_flags = Some(u16::from_le_bytes([data[off + 2], data[off + 3]]));
        }
        skip!(4);
    }
    // Bit 4: FHSS (2 bytes)
    if present!(4) {
        skip!(2);
    }
    // Bit 5: dBm Antenna Signal (1 byte, signed)
    if present!(5) {
        if off < header_len {
            dbm_antsignal = Some(data[off] as i8);
        }
        skip!(1);
    }
    // Bit 6: dBm Antenna Noise (1 byte, signed)
    if present!(6) {
        if off < header_len {
            noise_level = Some(data[off] as i8);
        }
        skip!(1);
    }
    // Bit 7: Lock Quality (2 bytes, align-2)
    if present!(7) {
        align_to!(2);
        skip!(2);
    }
    // Bit 8: TX Attenuation (2 bytes, align-2)
    if present!(8) {
        align_to!(2);
        skip!(2);
    }
    // Bit 9: dB TX Attenuation (2 bytes, align-2)
    if present!(9) {
        align_to!(2);
        skip!(2);
    }
    // Bit 10: dBm TX Power (1 byte, signed)
    if present!(10) {
        if off < header_len {
            tx_power = Some(data[off] as i8);
        }
        skip!(1);
    }
    // Bit 11: Antenna Index (1 byte)
    if present!(11) {
        if off < header_len {
            antenna_index = Some(data[off]);
        }
        skip!(1);
    }
    // Bit 12: dB Antenna Signal (1 byte) – not stored
    if present!(12) {
        skip!(1);
    }
    // Bit 13: dB Antenna Noise (1 byte) – not stored
    if present!(13) {
        skip!(1);
    }
    // Bit 14: RX Flags (2 bytes, align-2)
    if present!(14) {
        align_to!(2);
        if off + 2 <= header_len {
            rx_flags = Some(u16::from_le_bytes([data[off], data[off + 1]]));
        }
        skip!(2);
    }
    // Bit 15: TX Flags (2 bytes, align-2) – not stored
    if present!(15) {
        align_to!(2);
        skip!(2);
    }
    // Bit 16: RTS Retries (1 byte) – not stored
    if present!(16) {
        skip!(1);
    }
    // Bit 17: Data Retries (1 byte) – not stored
    if present!(17) {
        skip!(1);
    }
    // Bit 18: XChannel (8 bytes, align-4) – deprecated, not stored
    if present!(18) {
        align_to!(4);
        skip!(8);
    }
    // Bit 19: MCS (3 bytes: known, flags, index)
    if present!(19) {
        if off + 3 <= header_len {
            let mcs_flags = data[off + 1];
            mcs_index = Some(data[off + 2]);
            bandwidth = Some(mcs_flags & 0x03); // bits[1:0]
        }
        skip!(3);
    }
    // Bit 20: A-MPDU Status (8 bytes, align-4) – not stored
    if present!(20) {
        align_to!(4);
        skip!(8);
    }
    // Bit 21: VHT (12 bytes, align-2) – not stored
    if present!(21) {
        align_to!(2);
        skip!(12);
    }
    // Bit 22: Radiotap Timestamp (12 bytes, align-8)
    if present!(22) {
        align_to!(8);
        if off + 8 <= header_len {
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&data[off..off + 8]);
            timestamp = Some(u64::from_le_bytes(ts));
        }
        skip!(12); // 8 value + 2 accuracy + 1 unit + 1 flags
    }

    let _ = off;

    Some(RadiotapInfo {
        header_len,
        dbm_antsignal,
        channel,
        channel_flags,
        data_rate,
        noise_level,
        tx_power,
        rx_flags,
        antenna_index,
        mcs_index,
        bandwidth,
        timestamp,
    })
}

// =============================================================================
// 2. IEEE 802.11 FRAME PARSER
// =============================================================================

fn parse_80211_frame<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 24 {
        pkt.malformed = true;
        return;
    }

    let fc0 = data[0];
    let fc1 = data[1];
    let protocol_version = fc0 & 0x03;
    let frame_type = (fc0 >> 2) & 0x03;
    let frame_subtype = (fc0 >> 4) & 0x0F;

    let to_ds = (fc1 & 0x01) != 0;
    let from_ds = (fc1 & 0x02) != 0;
    let more_fragments = (fc1 & 0x04) != 0;
    let retry = (fc1 & 0x08) != 0;
    let power_management = (fc1 & 0x10) != 0;
    let more_data = (fc1 & 0x20) != 0;
    let protected_frame = (fc1 & 0x40) != 0;
    let order = (fc1 & 0x80) != 0;

    let duration = u16::from_le_bytes([data[2], data[3]]);

    // Sequence control is at bytes [22..24] for all frame types
    let seq_ctrl = u16::from_le_bytes([data[22], data[23]]);
    let fragment_number = (seq_ctrl & 0x000F) as u8;
    let sequence_number = seq_ctrl >> 4;

    // For 4-address frames (to_ds && from_ds) the base header ends at byte 30
    let addr4_present = to_ds && from_ds;
    let base_end = if addr4_present && data.len() >= 30 { 30 } else { 24 };

    // QoS Control: present for QoS data subtype frames (type=2, subtype bit3 set)
    let qos_control = if frame_type == 2
        && (frame_subtype & 0x08) != 0
        && data.len() >= base_end + 2
    {
        Some(u16::from_le_bytes([data[base_end], data[base_end + 1]]))
    } else {
        None
    };
    let after_qos = if qos_control.is_some() {
        base_end + 2
    } else {
        base_end
    };

    // HT Control: present when Order bit set in QoS data frames
    let ht_control = if order && qos_control.is_some() && data.len() >= after_qos + 4 {
        Some(u32::from_le_bytes([
            data[after_qos],
            data[after_qos + 1],
            data[after_qos + 2],
            data[after_qos + 3],
        ]))
    } else {
        None
    };

    pkt.wifi_header = Some(Wifi80211Header {
        protocol_version,
        frame_type,
        frame_subtype,
        to_ds,
        from_ds,
        more_fragments,
        retry,
        power_management,
        more_data,
        protected_frame,
        order,
        duration,
        sequence_number,
        fragment_number,
        qos_control,
        ht_control,
    });

    // ── MAC address resolution ────────────────────────────────────────────────
    let addr1 = copy_mac(&data[4..10]);
    let addr2 = copy_mac(&data[10..16]);
    let addr3 = copy_mac(&data[16..22]);

    let (src, dst, bssid) = match (to_ds, from_ds) {
        (false, false) => (addr2, addr1, Some(addr3)),
        (true, false) => (addr2, addr3, Some(addr1)),
        (false, true) => (addr3, addr1, Some(addr2)),
        (true, true) => {
            if data.len() >= 30 {
                let addr4 = copy_mac(&data[24..30]);
                (addr4, addr3, Some(addr1))
            } else {
                (addr2, addr1, Some(addr3))
            }
        }
    };

    pkt.src_mac = src;
    pkt.dst_mac = dst;
    pkt.bssid = bssid;

    match frame_type {
        0 => {
            // ── Management frame ─────────────────────────────────────────────
            let header_len = 24;
            if data.len() < header_len {
                pkt.malformed = true;
                return;
            }
            let body = &data[header_len..];

            let mut mgmt = WifiMgmtFrame {
                subtype: frame_subtype,
                ssid: None,
                channel: None,
                rsn_info: None,
                reason_code: None,
                status_code: None,
                bssid: bssid.unwrap_or([0; 6]),
                client_mac: None,
                raw_body: body.to_vec(),
                beacon_interval: None,
                capability_info: None,
                supported_rates: Vec::new(),
                extended_supported_rates: Vec::new(),
                country_info: None,
                tim: None,
                erp_info: None,
                ht_capabilities: None,
                ht_operation: None,
                vht_capabilities: None,
                vendor_ies: Vec::new(),
            };

            match frame_subtype {
                // Assoc Request (0), Reassoc Request (2), Probe Request (4), Probe Response (5),
                // Assoc Response (1), Reassoc Response (3)
                0 | 1 | 2 | 3 | 4 | 5 => {
                    if frame_subtype == 0
                        || frame_subtype == 2
                        || frame_subtype == 4
                        || frame_subtype == 5
                    {
                        mgmt.client_mac = Some(src);
                    }

                    let tag_offset = match frame_subtype {
                        0 => {
                            // Assoc Request: Capability Info (2) + Listen Interval (2)
                            if body.len() >= 2 {
                                mgmt.capability_info = Some(u16::from_le_bytes([body[0], body[1]]));
                            }
                            4
                        }
                        2 => {
                            // Reassoc Request: Capability Info (2) + Listen Interval (2) + Current AP (6)
                            if body.len() >= 2 {
                                mgmt.capability_info = Some(u16::from_le_bytes([body[0], body[1]]));
                            }
                            10
                        }
                        1 | 3 => {
                            // Assoc/Reassoc Response: Capability Info (2) + Status Code (2) + AID (2)
                            if body.len() >= 6 {
                                mgmt.capability_info =
                                    Some(u16::from_le_bytes([body[0], body[1]]));
                                mgmt.status_code =
                                    Some(u16::from_le_bytes([body[2], body[3]]));
                            }
                            6
                        }
                        5 => {
                            // Probe Response: Timestamp (8) + Beacon Interval (2) + Capability (2)
                            if body.len() >= 12 {
                                mgmt.beacon_interval =
                                    Some(u16::from_le_bytes([body[8], body[9]]));
                                mgmt.capability_info =
                                    Some(u16::from_le_bytes([body[10], body[11]]));
                            }
                            12
                        }
                        _ => 0, // Probe Request (4) – IEs start immediately
                    };

                    if body.len() >= tag_offset {
                        parse_wifi_ies(&body[tag_offset..], &mut mgmt);
                    }
                }
                8 => {
                    // Beacon: Timestamp (8) + Beacon Interval (2) + Capability (2)
                    if body.len() >= 12 {
                        mgmt.beacon_interval = Some(u16::from_le_bytes([body[8], body[9]]));
                        mgmt.capability_info = Some(u16::from_le_bytes([body[10], body[11]]));
                    }
                    if body.len() >= 12 {
                        parse_wifi_ies(&body[12..], &mut mgmt);
                    }
                }
                10 | 12 => {
                    // Disassociation (10) / Deauthentication (12)
                    if body.len() >= 2 {
                        mgmt.reason_code = Some(u16::from_le_bytes([body[0], body[1]]));
                    }
                    mgmt.client_mac = Some(if frame_subtype == 12 { dst } else { src });
                }
                11 => {
                    // Authentication
                    if body.len() >= 6 {
                        mgmt.status_code = Some(u16::from_le_bytes([body[4], body[5]]));
                    }
                    mgmt.client_mac = Some(src);
                }
                _ => {}
            }

            pkt.wifi_mgmt = Some(mgmt);
        }
        2 => {
            // ── Data frame ───────────────────────────────────────────────────
            let mut header_len = base_end;
            if qos_control.is_some() {
                header_len += 2;
            }
            if ht_control.is_some() {
                header_len += 4;
            }
            if data.len() > header_len {
                let payload = &data[header_len..];
                pkt.raw_payload = payload;
                if !protected_frame {
                    // LLC/SNAP header: AA AA 03 OUI(3) EtherType(2)
                    if payload.len() >= 8
                        && payload[0] == 0xAA
                        && payload[1] == 0xAA
                    {
                        let eth_type = u16::from_be_bytes([payload[6], payload[7]]);
                        let ip_payload = &payload[8..];
                        parse_ethernet_payload(eth_type, ip_payload, pkt);
                    }
                }
            }
        }
        _ => {}
    }
}

// =============================================================================
// 2a. WI-FI INFORMATION ELEMENTS PARSER
// =============================================================================

fn parse_wifi_ies(mut data: &[u8], mgmt: &mut WifiMgmtFrame) {
    while data.len() >= 2 {
        let ie_type = data[0];
        let ie_len = data[1] as usize;
        if 2 + ie_len > data.len() {
            break;
        }
        let ie_data = &data[2..2 + ie_len];

        match ie_type {
            0 => {
                // SSID
                mgmt.ssid = Some(String::from_utf8_lossy(ie_data).into_owned());
            }
            1 => {
                // Supported Rates
                mgmt.supported_rates = ie_data.to_vec();
            }
            3 => {
                // DS Parameter Set (current channel)
                if ie_len >= 1 {
                    mgmt.channel = Some(ie_data[0]);
                }
            }
            5 => {
                // TIM (Traffic Indication Map)
                if ie_len >= 4 {
                    mgmt.tim = Some(TimInfo {
                        dtim_count: ie_data[0],
                        dtim_period: ie_data[1],
                        bitmap_control: ie_data[2],
                        partial_virtual_bitmap: ie_data[3..].to_vec(),
                    });
                }
            }
            7 => {
                // Country Information
                if ie_len >= 3 {
                    mgmt.country_info = Some(CountryInfo {
                        country_code: [ie_data[0], ie_data[1]],
                        environment: ie_data[2],
                        triplets: ie_data[3..].to_vec(),
                    });
                }
            }
            42 => {
                // ERP Information
                if ie_len >= 1 {
                    mgmt.erp_info = Some(ie_data[0]);
                }
            }
            45 => {
                // HT Capabilities
                if ie_len >= 2 {
                    let ht_cap_info = u16::from_le_bytes([ie_data[0], ie_data[1]]);
                    let ampdu_params = if ie_len >= 3 { ie_data[2] } else { 0 };
                    mgmt.ht_capabilities = Some(HtCapabilities {
                        ht_cap_info,
                        ampdu_params,
                        raw: ie_data.to_vec(),
                    });
                }
            }
            48 => {
                // RSN (Robust Security Network / WPA2/3)
                mgmt.rsn_info = parse_rsn_ie(ie_data);
            }
            50 => {
                // Extended Supported Rates
                mgmt.extended_supported_rates = ie_data.to_vec();
            }
            61 => {
                // HT Operation
                if ie_len >= 1 {
                    mgmt.ht_operation = Some(HtOperation {
                        primary_channel: ie_data[0],
                        raw: ie_data.to_vec(),
                    });
                }
            }
            191 => {
                // VHT Capabilities
                if ie_len >= 4 {
                    let vht_cap_info = u32::from_le_bytes([
                        ie_data[0], ie_data[1], ie_data[2], ie_data[3],
                    ]);
                    mgmt.vht_capabilities = Some(VhtCapabilities {
                        vht_cap_info,
                        raw: ie_data.to_vec(),
                    });
                }
            }
            221 => {
                // Vendor Specific
                if ie_len >= 4 {
                    mgmt.vendor_ies.push(VendorIe {
                        oui: [ie_data[0], ie_data[1], ie_data[2]],
                        oui_type: ie_data[3],
                        data: ie_data[4..].to_vec(),
                    });
                }
            }
            _ => {}
        }

        data = &data[2 + ie_len..];
    }
}

// =============================================================================
// 2b. RSN IE PARSER
// =============================================================================

fn parse_rsn_ie(data: &[u8]) -> Option<RsnInfo> {
    if data.len() < 6 {
        return None;
    }
    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return None;
    }

    let group_cipher = Some(u32::from_be_bytes([data[2], data[3], data[4], data[5]]));
    let mut offset = 6;

    if data.len() < offset + 2 {
        return Some(RsnInfo {
            group_cipher,
            pairwise_ciphers: vec![],
            akm_suites: vec![],
            capabilities: None,
        });
    }
    let pairwise_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let mut pairwise_ciphers = Vec::new();
    for _ in 0..pairwise_count {
        if data.len() < offset + 4 {
            break;
        }
        pairwise_ciphers.push(u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]));
        offset += 4;
    }

    if data.len() < offset + 2 {
        return Some(RsnInfo {
            group_cipher,
            pairwise_ciphers,
            akm_suites: vec![],
            capabilities: None,
        });
    }
    let akm_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let mut akm_suites = Vec::new();
    for _ in 0..akm_count {
        if data.len() < offset + 4 {
            break;
        }
        akm_suites.push(u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]));
        offset += 4;
    }

    let capabilities = if data.len() >= offset + 2 {
        Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
    } else {
        None
    };

    Some(RsnInfo {
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        capabilities,
    })
}

// =============================================================================
// 3. ETHERNET FRAME PARSER
// =============================================================================

fn parse_ethernet_frame<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 14 {
        pkt.malformed = true;
        return;
    }

    pkt.dst_mac = copy_mac(&data[0..6]);
    pkt.src_mac = copy_mac(&data[6..12]);

    let mut eth_type = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;

    let mut outer_vlan_id: Option<u16> = None;
    let mut outer_pcp: Option<u8> = None;
    let mut vlan_id: Option<u16> = None;
    let mut pcp: Option<u8> = None;
    let mut dei: Option<bool> = None;

    // QinQ outer tag (802.1ad 0x88A8, or proprietary 0x9100)
    if (eth_type == 0x88A8 || eth_type == 0x9100) && data.len() >= offset + 4 {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        outer_pcp = Some((tci >> 13) as u8);
        outer_vlan_id = Some(tci & 0x0FFF);
        eth_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    // Inner 802.1Q tag
    if eth_type == 0x8100 && data.len() >= offset + 4 {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        pcp = Some((tci >> 13) as u8);
        dei = Some(((tci >> 12) & 0x01) != 0);
        vlan_id = Some(tci & 0x0FFF);
        eth_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    pkt.ethernet = Some(EthernetInfo {
        ether_type: eth_type,
        vlan_id,
        pcp,
        dei,
        outer_vlan_id,
        outer_pcp,
        frame_length: data.len(),
        fcs: None, // FCS is stripped by the NIC in nearly all capture paths
    });

    if offset < data.len() {
        let payload = &data[offset..];
        pkt.raw_payload = payload;
        parse_ethernet_payload(eth_type, payload, pkt);
    } else {
        pkt.malformed = true;
    }
}

fn parse_ethernet_payload<'a>(eth_type: u16, payload: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    match eth_type {
        0x0800 => parse_ipv4(payload, pkt),
        0x86DD => parse_ipv6(payload, pkt),
        0x0806 => parse_arp(payload, pkt),
        0x888E => parse_eapol(payload, pkt),
        _ => {}
    }
}

// =============================================================================
// 4. IPv4 PARSER
// =============================================================================

fn parse_ipv4<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 20 {
        pkt.malformed = true;
        return;
    }

    let ver_ihl = data[0];
    let version = ver_ihl >> 4;
    let ihl = (ver_ihl & 0x0F) as usize;

    if version != 4 || ihl < 5 || ihl * 4 > data.len() {
        pkt.malformed = true;
        return;
    }

    let tos = data[1];
    let dscp = tos >> 2;
    let ecn = tos & 0x03;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_frag >> 13) as u8;
    let fragment_offset = flags_frag & 0x1FFF;
    let ttl = data[8];
    let protocol = data[9];
    let header_checksum = u16::from_be_bytes([data[10], data[11]]);
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let header_len = ihl * 4;
    let options = if header_len > 20 {
        data[20..header_len].to_vec()
    } else {
        Vec::new()
    };

    let packet_len = std::cmp::min(data.len(), total_length as usize);
    if packet_len < header_len {
        pkt.malformed = true;
        return;
    }
    let payload = &data[header_len..packet_len];

    pkt.network = NetworkLayer::Ipv4(Ipv4Info {
        version,
        ihl: ihl as u8,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_ip,
        dst_ip,
        options,
        payload,
    });

    parse_transport(protocol, payload, pkt);
}

// =============================================================================
// 5. IPv6 PARSER
// =============================================================================

fn parse_ipv6<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 40 {
        pkt.malformed = true;
        return;
    }

    let version = data[0] >> 4;
    if version != 6 {
        pkt.malformed = true;
        return;
    }

    let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
    let flow_label =
        u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]);
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header_initial = data[6];
    let hop_limit = data[7];

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    let src_ip = Ipv6Addr::from(src_bytes);

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&data[24..40]);
    let dst_ip = Ipv6Addr::from(dst_bytes);

    let end_offset = std::cmp::min(data.len(), 40 + payload_length as usize);
    if end_offset < 40 {
        pkt.malformed = true;
        return;
    }

    // Walk extension headers
    let mut extension_headers: Vec<Ipv6ExtHeader> = Vec::new();
    let mut next_hdr = next_header_initial;
    let mut off = 40usize;

    loop {
        match next_hdr {
            0   // Hop-by-Hop Options
            | 43  // Routing
            | 44  // Fragment
            | 60  // Destination Options
            | 135 // Mobility
            => {
                if off + 2 > end_offset {
                    break;
                }
                let ext_next = data[off];
                // Length in 8-octet units, not counting the first 8 octets
                let ext_len = (data[off + 1] as usize + 1) * 8;
                if off + ext_len > end_offset {
                    break;
                }
                extension_headers.push(Ipv6ExtHeader {
                    header_type: next_hdr,
                    data: data[off..off + ext_len].to_vec(),
                });
                next_hdr = ext_next;
                off += ext_len;
            }
            _ => break, // Upper-layer protocol
        }
    }

    let payload = &data[off..end_offset];
    let final_next_header = next_hdr;

    pkt.network = NetworkLayer::Ipv6(Ipv6Info {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header: next_header_initial,
        hop_limit,
        src_ip,
        dst_ip,
        extension_headers,
        final_next_header,
        payload,
    });

    parse_transport(final_next_header, payload, pkt);
}

// =============================================================================
// 6. ARP PARSER
// =============================================================================

fn parse_arp<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 28 {
        pkt.malformed = true;
        return;
    }

    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    let proto_type = u16::from_be_bytes([data[2], data[3]]);
    let hw_addr_len = data[4];
    let proto_addr_len = data[5];
    let opcode = u16::from_be_bytes([data[6], data[7]]);

    // Only parse Ethernet / IPv4 ARP (the standard case)
    if hw_type == 1 && proto_type == 0x0800 && hw_addr_len == 6 && proto_addr_len == 4 {
        let sender_mac = copy_mac(&data[8..14]);
        let sender_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
        let target_mac = copy_mac(&data[18..24]);
        let target_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        pkt.network = NetworkLayer::Arp(ArpInfo {
            hw_type,
            proto_type,
            hw_addr_len,
            proto_addr_len,
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        });
    }
}

// =============================================================================
// 7. TRANSPORT LAYER PARSER
// =============================================================================

fn parse_transport<'a>(proto: u8, data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    match proto {
        6 => parse_tcp(data, pkt),
        17 => parse_udp(data, pkt),
        1 | 58 => parse_icmp(data, pkt), // 1 = ICMP, 58 = ICMPv6
        _ => {}
    }
}

fn parse_tcp<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 20 {
        pkt.malformed = true;
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset_byte = data[12];
    let data_offset = (data_offset_byte >> 4) as usize;
    // Bits [3:1] of the high nibble's lower bits are reserved
    let reserved = (data_offset_byte & 0x0E) >> 1;
    let flags = u16::from_be_bytes([data_offset_byte & 0x01, data[13]]);
    let window_size = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

    if data_offset < 5 || data_offset * 4 > data.len() {
        pkt.malformed = true;
        return;
    }

    let options_bytes = &data[20..data_offset * 4];
    let options = parse_tcp_options(options_bytes);
    let payload = &data[data_offset * 4..];

    let src = src_port;
    let dst = dst_port;

    pkt.transport = TransportLayer::Tcp(TcpInfo {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset: data_offset as u8,
        reserved,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        options,
        payload,
    });

    parse_app_layer(src, dst, payload, pkt);
}

fn parse_tcp_options(mut data: &[u8]) -> TcpOptions {
    let mut opts = TcpOptions::default();

    while !data.is_empty() {
        let kind = data[0];
        match kind {
            0 => break, // End of Options List
            1 => {
                // NOP
                data = &data[1..];
                continue;
            }
            2 => {
                // Maximum Segment Size
                if data.len() >= 4 {
                    opts.mss = Some(u16::from_be_bytes([data[2], data[3]]));
                }
            }
            3 => {
                // Window Scale
                if data.len() >= 3 {
                    opts.window_scale = Some(data[2]);
                }
            }
            4 => {
                // SACK Permitted
                opts.sack_permitted = true;
            }
            5 => {
                // SACK blocks
                if data.len() >= 2 {
                    let len = data[1] as usize;
                    if len >= 2 && data.len() >= len {
                        let block_data = &data[2..len];
                        let mut i = 0;
                        while i + 8 <= block_data.len() {
                            let left = u32::from_be_bytes([
                                block_data[i],
                                block_data[i + 1],
                                block_data[i + 2],
                                block_data[i + 3],
                            ]);
                            let right = u32::from_be_bytes([
                                block_data[i + 4],
                                block_data[i + 5],
                                block_data[i + 6],
                                block_data[i + 7],
                            ]);
                            opts.sack_blocks.push((left, right));
                            i += 8;
                        }
                    }
                }
            }
            8 => {
                // Timestamp
                if data.len() >= 10 {
                    let val = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                    let echo = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
                    opts.timestamp = Some((val, echo));
                }
            }
            _ => {}
        }

        // All options except NOP and EOL have a length byte
        if data.len() < 2 {
            break;
        }
        let len = data[1] as usize;
        if len < 2 || len > data.len() {
            break;
        }
        data = &data[len..];
    }

    opts
}

fn parse_udp<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 8 {
        pkt.malformed = true;
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    let len = length as usize;
    if len < 8 || len > data.len() {
        pkt.malformed = true;
        return;
    }
    let payload = &data[8..len];

    let src = src_port;
    let dst = dst_port;

    pkt.transport = TransportLayer::Udp(UdpInfo {
        src_port,
        dst_port,
        length,
        checksum,
        payload,
    });

    parse_app_layer(src, dst, payload, pkt);
}

fn parse_icmp<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 4 {
        pkt.malformed = true;
        return;
    }

    let icmp_type = data[0];
    let icmp_code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    let mut identifier = None;
    let mut sequence_number = None;
    let mut mtu = None;
    let mut embedded_header: Option<Vec<u8>> = None;

    match icmp_type {
        0 | 8 => {
            // Echo Reply / Echo Request
            if data.len() >= 8 {
                identifier = Some(u16::from_be_bytes([data[4], data[5]]));
                sequence_number = Some(u16::from_be_bytes([data[6], data[7]]));
            }
        }
        3 => {
            // Destination Unreachable
            if icmp_code == 4 && data.len() >= 8 {
                // Fragmentation Needed – next-hop MTU in bytes [6..8]
                mtu = Some(u16::from_be_bytes([data[6], data[7]]));
            }
            if data.len() > 8 {
                let embed_end = std::cmp::min(data.len(), 8 + 28);
                embedded_header = Some(data[8..embed_end].to_vec());
            }
        }
        11 => {
            // Time Exceeded
            if data.len() > 8 {
                let embed_end = std::cmp::min(data.len(), 8 + 28);
                embedded_header = Some(data[8..embed_end].to_vec());
            }
        }
        2 => {
            // ICMPv6 Packet Too Big
            if data.len() >= 8 {
                mtu = Some(u16::from_be_bytes([data[6], data[7]]));
            }
        }
        128 | 129 => {
            // ICMPv6 Echo Request / Reply
            if data.len() >= 8 {
                identifier = Some(u16::from_be_bytes([data[4], data[5]]));
                sequence_number = Some(u16::from_be_bytes([data[6], data[7]]));
            }
        }
        _ => {}
    }

    let payload = if data.len() > 4 { &data[4..] } else { &[] };

    pkt.transport = TransportLayer::Icmp(IcmpInfo {
        icmp_type,
        icmp_code,
        checksum,
        identifier,
        sequence_number,
        mtu,
        embedded_header,
        payload,
    });
}

// =============================================================================
// 8. APPLICATION LAYER DISPATCHER
// =============================================================================

fn parse_app_layer<'a>(
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
    pkt: &mut ParsedPacket<'a>,
) {
    if src_port == 53 || dst_port == 53 {
        if let Some(dns) = parse_dns(payload) {
            pkt.app = AppLayer::Dns(dns);
        }
    } else if (src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67) {
        if let Some(dhcp) = parse_dhcp(payload) {
            pkt.app = AppLayer::Dhcp(dhcp);
        }
    }
}

// =============================================================================
// 9. DNS PARSER
// =============================================================================

fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags_word = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags_word & 0x8000) != 0;
    let opcode = ((flags_word >> 11) & 0x0F) as u8;
    let aa = (flags_word & 0x0400) != 0;
    let tc = (flags_word & 0x0200) != 0;
    let rd = (flags_word & 0x0100) != 0;
    let ra = (flags_word & 0x0080) != 0;
    let rcode = (flags_word & 0x000F) as u8;

    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    let answer_count = u16::from_be_bytes([payload[6], payload[7]]);
    let authority_count = u16::from_be_bytes([payload[8], payload[9]]);
    let additional_count = u16::from_be_bytes([payload[10], payload[11]]);

    let mut offset = 12usize;
    let mut query: Option<String> = None;
    let mut query_type: Option<u16> = None;
    let mut query_class: Option<u16> = None;

    // Parse question section
    for _ in 0..question_count {
        match parse_dns_name(payload, offset) {
            Some((name, new_off)) if new_off + 4 <= payload.len() => {
                let qtype =
                    u16::from_be_bytes([payload[new_off], payload[new_off + 1]]);
                let qclass =
                    u16::from_be_bytes([payload[new_off + 2], payload[new_off + 3]]);
                if query.is_none() {
                    query = Some(name);
                    query_type = Some(qtype);
                    query_class = Some(qclass);
                }
                offset = new_off + 4;
            }
            _ => break,
        }
    }

    // Parse answer section
    let mut answers = Vec::new();
    for _ in 0..answer_count {
        match parse_dns_name(payload, offset) {
            Some((name, new_off)) if new_off + 10 <= payload.len() => {
                let rtype =
                    u16::from_be_bytes([payload[new_off], payload[new_off + 1]]);
                let class =
                    u16::from_be_bytes([payload[new_off + 2], payload[new_off + 3]]);
                let ttl = u32::from_be_bytes([
                    payload[new_off + 4],
                    payload[new_off + 5],
                    payload[new_off + 6],
                    payload[new_off + 7],
                ]);
                let rdlen =
                    u16::from_be_bytes([payload[new_off + 8], payload[new_off + 9]])
                        as usize;
                let rdata_start = new_off + 10;
                if rdata_start + rdlen <= payload.len() {
                    let rdata = payload[rdata_start..rdata_start + rdlen].to_vec();
                    answers.push(DnsRecord {
                        name,
                        rtype,
                        class,
                        ttl,
                        rdata,
                    });
                    offset = rdata_start + rdlen;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    Some(DnsInfo {
        transaction_id,
        is_response,
        opcode,
        aa,
        tc,
        rd,
        ra,
        rcode,
        question_count,
        answer_count,
        authority_count,
        additional_count,
        query,
        query_type,
        query_class,
        answers,
    })
}

/// Decode a DNS name (label sequence, supports compression pointers).
/// Returns `(decoded_name, offset_after_name)` or `None` on error.
fn parse_dns_name(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let mut domain = String::new();
    let mut offset = start;
    let mut jumped = false;
    let mut end_offset = start;
    let mut visited = 0usize;

    while offset < payload.len() && visited < 128 {
        let label_len = payload[offset] as usize;

        if label_len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }

        if (label_len & 0xC0) == 0xC0 {
            // Compression pointer
            if offset + 2 > payload.len() {
                return None;
            }
            if !jumped {
                end_offset = offset + 2;
            }
            let ptr = ((label_len & 0x3F) << 8) | payload[offset + 1] as usize;
            if ptr >= payload.len() || ptr >= offset {
                // Guard against forward references that could loop
                return None;
            }
            offset = ptr;
            jumped = true;
        } else {
            if offset + 1 + label_len > payload.len() {
                return None;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(
                &String::from_utf8_lossy(&payload[offset + 1..offset + 1 + label_len]),
            );
            offset += 1 + label_len;
            if !jumped {
                end_offset = offset;
            }
        }

        visited += 1;
    }

    Some((domain, end_offset))
}

// =============================================================================
// 10. DHCP PARSER
// =============================================================================

fn parse_dhcp(payload: &[u8]) -> Option<DhcpInfo> {
    // Minimum DHCP message: 236 bytes fixed header + 4 bytes magic cookie
    if payload.len() < 240 {
        return None;
    }
    let magic = &payload[236..240];
    if magic != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }

    let transaction_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let client_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let your_ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    // siaddr (server next-boot IP) at [20..24] – not stored separately
    let relay_ip = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);
    let client_mac = copy_mac(&payload[28..34]);

    let mut message_type = None;
    let mut server_ip = None;
    let mut hostname: Option<String> = None;
    let mut lease_time = None;
    let mut renewal_time = None;
    let mut vendor_class: Option<String> = None;
    let mut parameter_request_list = Vec::new();
    let mut offset = 240usize;

    while offset + 1 <= payload.len() {
        let opt_type = payload[offset];
        if opt_type == 255 {
            break; // End option
        }
        if opt_type == 0 {
            // Pad option (no length byte)
            offset += 1;
            continue;
        }
        if offset + 2 > payload.len() {
            break;
        }
        let opt_len = payload[offset + 1] as usize;
        if offset + 2 + opt_len > payload.len() {
            break;
        }
        let opt_data = &payload[offset + 2..offset + 2 + opt_len];

        match opt_type {
            12 => {
                // Hostname
                hostname = Some(String::from_utf8_lossy(opt_data).into_owned());
            }
            51 => {
                // IP Address Lease Time
                if opt_len >= 4 {
                    lease_time = Some(u32::from_be_bytes([
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ]));
                }
            }
            53 => {
                // DHCP Message Type
                if opt_len >= 1 {
                    message_type = Some(opt_data[0]);
                }
            }
            54 => {
                // Server Identifier
                if opt_len >= 4 {
                    server_ip = Some(Ipv4Addr::new(
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ));
                }
            }
            55 => {
                // Parameter Request List
                parameter_request_list = opt_data.to_vec();
            }
            58 => {
                // Renewal Time (T1)
                if opt_len >= 4 {
                    renewal_time = Some(u32::from_be_bytes([
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ]));
                }
            }
            60 => {
                // Vendor Class Identifier
                vendor_class = Some(String::from_utf8_lossy(opt_data).into_owned());
            }
            _ => {}
        }

        offset += 2 + opt_len;
    }

    Some(DhcpInfo {
        transaction_id,
        client_ip,
        your_ip,
        relay_ip,
        client_mac,
        message_type,
        server_ip,
        hostname,
        lease_time,
        renewal_time,
        vendor_class,
        parameter_request_list,
    })
}

// =============================================================================
// 11. EAPOL PARSER
// =============================================================================

fn parse_eapol<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 4 {
        pkt.malformed = true;
        return;
    }

    let version = data[0];
    let packet_type = data[1];
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;

    if 4 + len > data.len() {
        pkt.malformed = true;
        return;
    }

    let body = &data[4..4 + len];

    // packet_type 3 = EAPOL-Key
    if packet_type == 3 && body.len() >= 97 {
        let key_desc_type = body[0];
        let key_info = u16::from_be_bytes([body[1], body[2]]);

        // ── Decode key_info bit fields ────────────────────────────────────────
        let descriptor_version = (key_info & 0x0007) as u8;
        let install = (key_info & (1 << 6)) != 0;
        let key_ack = (key_info & (1 << 7)) != 0;
        let key_mic = (key_info & (1 << 8)) != 0;
        let secure = (key_info & (1 << 9)) != 0;
        let error = (key_info & (1 << 10)) != 0;
        let request = (key_info & (1 << 11)) != 0;
        let encrypted_key_data = (key_info & (1 << 12)) != 0;
        // ─────────────────────────────────────────────────────────────────────

        // Replay counter: body[9..17]
        let mut rc_bytes = [0u8; 8];
        rc_bytes.copy_from_slice(&body[9..17]);
        let replay_counter = u64::from_be_bytes(rc_bytes);

        // Key Nonce: body[17..49]
        let mut key_nonce = [0u8; 32];
        if body.len() >= 49 {
            key_nonce.copy_from_slice(&body[17..49]);
        }

        // Key IV: body[49..65]
        let mut key_iv = [0u8; 16];
        if body.len() >= 65 {
            key_iv.copy_from_slice(&body[49..65]);
        }

        // MIC: body[77..93]
        let mut mic = [0u8; 16];
        if body.len() >= 93 {
            mic.copy_from_slice(&body[77..93]);
        }

        // Key Data: body[97..97+key_data_len]
        let key_data_len = u16::from_be_bytes([body[95], body[96]]) as usize;
        let raw_key_data = if 97 + key_data_len <= body.len() {
            &body[97..97 + key_data_len]
        } else {
            &[]
        };

        pkt.app = AppLayer::Eapol(EapolInfo {
            version,
            packet_type,
            key_desc_type,
            key_info,
            descriptor_version,
            install,
            key_ack,
            key_mic,
            secure,
            error,
            request,
            encrypted_key_data,
            replay_counter,
            key_nonce,
            key_iv,
            mic,
            raw_key_data,
        });
    }
}

// =============================================================================
// HELPERS
// =============================================================================

#[inline(always)]
fn copy_mac(slice: &[u8]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    if slice.len() >= 6 {
        mac.copy_from_slice(&slice[0..6]);
    }
    mac
}
