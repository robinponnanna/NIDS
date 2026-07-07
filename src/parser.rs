use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LinkType {
    Ethernet,
    Wifi80211,
    RadiotapWifi,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct RadiotapInfo {
    pub header_len: usize,
    pub dbm_antsignal: Option<i8>,
    pub channel: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct WifiMgmtFrame<'a> {
    pub subtype: u8,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub rsn_info: Option<RsnInfo>,
    pub reason_code: Option<u16>,
    pub status_code: Option<u16>,
    pub bssid: [u8; 6],
    pub client_mac: Option<[u8; 6]>,
    pub raw_body: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct RsnInfo {
    pub group_cipher: Option<u32>,
    pub pairwise_ciphers: Vec<u32>,
    pub akm_suites: Vec<u32>,
    pub capabilities: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkLayer<'a> {
    Arp(ArpInfo),
    Ipv4 {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        proto: u8,
        payload: &'a [u8],
    },
    Ipv6 {
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        next_hdr: u8,
        payload: &'a [u8],
    },
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArpInfo {
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportLayer<'a> {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u16,
        seq: u32,
        ack: u32,
        payload: &'a [u8],
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    Icmp {
        icmp_type: u8,
        icmp_code: u8,
        payload: &'a [u8],
    },
    None,
}

#[derive(Debug, Clone)]
pub enum AppLayer<'a> {
    Dns(DnsInfo),
    Dhcp(DhcpInfo),
    Eapol(EapolInfo<'a>),
    None,
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub is_response: bool,
    pub rcode: u8,
    pub query: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DhcpInfo {
    pub message_type: Option<u8>,
    pub server_ip: Option<Ipv4Addr>,
    pub client_mac: [u8; 6],
}

#[derive(Debug, Clone)]
pub struct EapolInfo<'a> {
    pub version: u8,
    pub packet_type: u8,
    pub key_desc_type: u8,
    pub key_info: u16,
    pub replay_counter: u64,
    pub raw_key_data: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    pub link_type: LinkType,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub bssid: Option<[u8; 6]>,
    pub signal_dbm: Option<i8>,
    pub channel: Option<u16>,
    pub malformed: bool,
    pub network: NetworkLayer<'a>,
    pub transport: TransportLayer<'a>,
    pub app: AppLayer<'a>,
    pub wifi_mgmt: Option<WifiMgmtFrame<'a>>,
    pub raw_payload: &'a [u8],
}

// Zero-copy parsing entry point
pub fn parse_packet<'a>(data: &'a [u8], default_link: LinkType) -> ParsedPacket<'a> {
    let mut pkt = ParsedPacket {
        link_type: default_link,
        src_mac: [0; 6],
        dst_mac: [0; 6],
        bssid: None,
        signal_dbm: None,
        channel: None,
        malformed: false,
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
        _ => {
            // Check if we can auto-detect: does it start with radiotap version 0?
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
                // Guess Ethernet as fallback
                pkt.link_type = LinkType::Ethernet;
                parse_ethernet_frame(data, &mut pkt);
            } else {
                pkt.malformed = true;
            }
        }
    }

    pkt
}

// 1. Radiotap Parser
fn parse_radiotap(data: &[u8]) -> Option<RadiotapInfo> {
    if data.len() < 8 {
        return None;
    }
    let version = data[0];
    if version != 0 {
        return None;
    }
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if header_len > data.len() || header_len < 8 {
        return None;
    }

    // Parse presence flags to find dbm antenna signal and channel
    let mut flags_offset = 4;
    let mut presence_flags = u32::from_le_bytes([
        data[flags_offset],
        data[flags_offset + 1],
        data[flags_offset + 2],
        data[flags_offset + 3],
    ]);
    
    // Skip multiple presence flags fields if bit 31 is set
    while (presence_flags & 0x80000000) != 0 && flags_offset + 8 <= header_len {
        flags_offset += 4;
        if flags_offset + 4 > header_len { break; }
        presence_flags = u32::from_le_bytes([
            data[flags_offset],
            data[flags_offset + 1],
            data[flags_offset + 2],
            data[flags_offset + 3],
        ]);
    }
    
    let mut field_offset = flags_offset + 4;
    
    // Check fields using presence flags
    // Bit 0: TSFT (8 bytes, aligned to 8)
    if (presence_flags & (1 << 0)) != 0 {
        field_offset = (field_offset + 7) & !7; // Align to 8
        field_offset += 8;
    }
    // Bit 1: Flags (1 byte)
    if (presence_flags & (1 << 1)) != 0 {
        field_offset += 1;
    }
    // Bit 2: Rate (1 byte)
    if (presence_flags & (1 << 2)) != 0 {
        field_offset += 1;
    }
    
    // Bit 3: Channel (4 bytes, aligned to 2)
    let mut channel = None;
    if (presence_flags & (1 << 3)) != 0 {
        field_offset = (field_offset + 1) & !1; // Align to 2
        if field_offset + 2 <= header_len {
            channel = Some(u16::from_le_bytes([data[field_offset], data[field_offset + 1]]));
        }
        field_offset += 4;
    }
    // Bit 4: FHSS (2 bytes)
    if (presence_flags & (1 << 4)) != 0 {
        field_offset += 2;
    }
    
    // Bit 5: dBm Antenna Signal (1 byte)
    let mut dbm_antsignal = None;
    if (presence_flags & (1 << 5)) != 0 {
        if field_offset < header_len {
            dbm_antsignal = Some(data[field_offset] as i8);
        }
    }

    Some(RadiotapInfo {
        header_len,
        dbm_antsignal,
        channel,
    })
}

// 2. 802.11 Frame Parser
fn parse_80211_frame<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 24 {
        pkt.malformed = true;
        return;
    }

    let fc0 = data[0];
    let fc1 = data[1];
    let frame_type = (fc0 >> 2) & 0x03;
    let frame_subtype = (fc0 >> 4) & 0x0F;

    let to_ds = (fc1 & 0x01) != 0;
    let from_ds = (fc1 & 0x02) != 0;

    // MAC Addresses
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
            // Management frame
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
                raw_body: body,
            };

            // Parse Management frames subtypes
            match frame_subtype {
                0 | 1 | 2 | 3 | 4 | 5 => {
                    // Assoc Request, Assoc Response, Reassoc Request, Reassoc Response, Probe Request, Probe Response
                    if frame_subtype == 0 || frame_subtype == 2 || frame_subtype == 4 || frame_subtype == 5 {
                        mgmt.client_mac = Some(src);
                    }
                    
                    let tag_offset = if frame_subtype == 0 || frame_subtype == 2 {
                        4 // skip Capability Info (2), Listen Interval (2)
                    } else if frame_subtype == 1 || frame_subtype == 3 {
                        6 // skip Capability Info (2), Status Code (2), AID (2)
                    } else if frame_subtype == 5 {
                        12 // skip Timestamp (8), Beacon Interval (2), Capability (2)
                    } else {
                        0 // Probe Request starts immediately with tags
                    };
                    
                    if body.len() >= tag_offset {
                        parse_wifi_ies(&body[tag_offset..], &mut mgmt);
                    }
                }
                8 => {
                    // Beacon
                    let tag_offset = 12; // Timestamp (8) + Beacon Interval (2) + Capability (2)
                    if body.len() >= tag_offset {
                        parse_wifi_ies(&body[tag_offset..], &mut mgmt);
                    }
                }
                10 | 12 => {
                    // Disassociation, Deauthentication
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
            // Data frame
            let mut header_len = 24;
            let qos_data = (frame_subtype & 0x08) != 0;
            if qos_data {
                header_len += 2; // QoS control
            }
            // Check if protected (encrypted)
            let protected = (fc1 & 0x40) != 0;
            if protected {
                header_len += 8; // CCMP/TKIP header
            }
            
            if data.len() > header_len {
                let payload = &data[header_len..];
                pkt.raw_payload = payload;
                if !protected {
                    // Parse LLC layer (usually 8 bytes SNAP/LLC header)
                    if payload.len() >= 8 && payload[0] == 0xAA && payload[1] == 0xAA {
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

fn parse_wifi_ies(mut data: &[u8], mgmt: &mut WifiMgmtFrame) {
    while data.len() >= 2 {
        let ie_type = data[0];
        let ie_len = data[1] as usize;
        if 2 + ie_len > data.len() {
            break; // Malformed tag
        }
        let ie_data = &data[2..2 + ie_len];
        match ie_type {
            0 => {
                // SSID
                mgmt.ssid = Some(String::from_utf8_lossy(ie_data).into_owned());
            }
            3 => {
                // DS Parameter Set (Channel)
                if ie_len >= 1 {
                    mgmt.channel = Some(ie_data[0]);
                }
            }
            48 => {
                // RSN
                mgmt.rsn_info = parse_rsn_ie(ie_data);
            }
            _ => {}
        }
        data = &data[2 + ie_len..];
    }
}

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
        return Some(RsnInfo { group_cipher, pairwise_ciphers: vec![], akm_suites: vec![], capabilities: None });
    }
    let pairwise_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    let mut pairwise_ciphers = Vec::new();
    for _ in 0..pairwise_count {
        if data.len() < offset + 4 { break; }
        pairwise_ciphers.push(u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]));
        offset += 4;
    }
    
    if data.len() < offset + 2 {
        return Some(RsnInfo { group_cipher, pairwise_ciphers, akm_suites: vec![], capabilities: None });
    }
    let akm_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    let mut akm_suites = Vec::new();
    for _ in 0..akm_count {
        if data.len() < offset + 4 { break; }
        akm_suites.push(u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]));
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

fn parse_ethernet_frame<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 14 {
        pkt.malformed = true;
        return;
    }
    pkt.dst_mac = copy_mac(&data[0..6]);
    pkt.src_mac = copy_mac(&data[6..12]);
    let mut eth_type = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;

    if eth_type == 0x8100 && data.len() >= 18 {
        eth_type = u16::from_be_bytes([data[16], data[17]]);
        offset = 18;
    }

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
        0x0800 => {
            parse_ipv4(payload, pkt);
        }
        0x86DD => {
            parse_ipv6(payload, pkt);
        }
        0x0806 => {
            parse_arp(payload, pkt);
        }
        0x888E => {
            parse_eapol(payload, pkt);
        }
        _ => {}
    }
}

fn parse_ipv4<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 20 {
        pkt.malformed = true;
        return;
    }
    let ver_ihl = data[0];
    let ver = ver_ihl >> 4;
    let ihl = (ver_ihl & 0x0F) as usize;
    
    if ver != 4 || ihl < 5 || ihl * 4 > data.len() {
        pkt.malformed = true;
        return;
    }
    
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let header_len = ihl * 4;
    let packet_len = std::cmp::min(data.len(), total_len);
    
    if packet_len < header_len {
        pkt.malformed = true;
        return;
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let proto = data[9];
    let payload = &data[header_len..packet_len];

    pkt.network = NetworkLayer::Ipv4 {
        src_ip,
        dst_ip,
        proto,
        payload,
    };

    parse_transport(proto, payload, pkt);
}

fn parse_ipv6<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 40 {
        pkt.malformed = true;
        return;
    }
    let ver = data[0] >> 4;
    if ver != 6 {
        pkt.malformed = true;
        return;
    }

    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_hdr = data[6];
    
    let mut src_ip_bytes = [0u8; 16];
    src_ip_bytes.copy_from_slice(&data[8..24]);
    let src_ip = Ipv6Addr::from(src_ip_bytes);
    
    let mut dst_ip_bytes = [0u8; 16];
    dst_ip_bytes.copy_from_slice(&data[24..40]);
    let dst_ip = Ipv6Addr::from(dst_ip_bytes);

    let end_offset = std::cmp::min(data.len(), 40 + payload_len);
    if end_offset < 40 {
        pkt.malformed = true;
        return;
    }
    let payload = &data[40..end_offset];

    pkt.network = NetworkLayer::Ipv6 {
        src_ip,
        dst_ip,
        next_hdr,
        payload,
    };

    parse_transport(next_hdr, payload, pkt);
}

fn parse_arp<'a>(data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    if data.len() < 28 {
        pkt.malformed = true;
        return;
    }
    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    let proto_type = u16::from_be_bytes([data[2], data[3]]);
    let hw_len = data[4];
    let proto_len = data[5];
    let opcode = u16::from_be_bytes([data[6], data[7]]);

    if hw_type == 1 && proto_type == 0x0800 && hw_len == 6 && proto_len == 4 {
        let sender_mac = copy_mac(&data[8..14]);
        let sender_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
        let target_mac = copy_mac(&data[18..24]);
        let target_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        pkt.network = NetworkLayer::Arp(ArpInfo {
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        });
    }
}

fn parse_transport<'a>(proto: u8, data: &'a [u8], pkt: &mut ParsedPacket<'a>) {
    match proto {
        6 => {
            if data.len() < 20 {
                pkt.malformed = true;
                return;
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let data_offset = (data[12] >> 4) as usize;
            
            if data_offset < 5 || data_offset * 4 > data.len() {
                pkt.malformed = true;
                return;
            }
            let flags = u16::from_be_bytes([data[12] & 0x0F, data[13]]);
            let payload = &data[data_offset * 4..];

            pkt.transport = TransportLayer::Tcp {
                src_port,
                dst_port,
                flags,
                seq,
                ack,
                payload,
            };

            parse_app_layer(src_port, dst_port, payload, pkt);
        }
        17 => {
            if data.len() < 8 {
                pkt.malformed = true;
                return;
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let len = u16::from_be_bytes([data[4], data[5]]) as usize;
            
            if len < 8 || len > data.len() {
                pkt.malformed = true;
                return;
            }
            let payload = &data[8..len];

            pkt.transport = TransportLayer::Udp {
                src_port,
                dst_port,
                payload,
            };

            parse_app_layer(src_port, dst_port, payload, pkt);
        }
        1 | 58 => {
            if data.len() < 4 {
                pkt.malformed = true;
                return;
            }
            pkt.transport = TransportLayer::Icmp {
                icmp_type: data[0],
                icmp_code: data[1],
                payload: &data[4..],
            };
        }
        _ => {}
    }
}

fn parse_app_layer<'a>(src_port: u16, dst_port: u16, payload: &'a [u8], pkt: &mut ParsedPacket<'a>) {
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

fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }
    let is_response = (payload[2] & 0x80) != 0;
    let rcode = payload[3] & 0x0F;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

    let mut query = None;
    if qdcount > 0 && payload.len() > 12 {
        let mut offset = 12;
        let mut domain = String::new();
        let mut visited = 0;
        while offset < payload.len() && visited < 100 {
            let len = payload[offset] as usize;
            if len == 0 {
                break;
            }
            if (len & 0xC0) == 0xC0 {
                if domain.is_empty() {
                    domain.push_str("<compressed>");
                }
                break;
            }
            if offset + 1 + len > payload.len() {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(&String::from_utf8_lossy(&payload[offset + 1..offset + 1 + len]));
            offset += 1 + len;
            visited += 1;
        }
        if !domain.is_empty() {
            query = Some(domain);
        }
    }

    Some(DnsInfo {
        is_response,
        rcode,
        query,
    })
}

fn parse_dhcp(payload: &[u8]) -> Option<DhcpInfo> {
    if payload.len() < 240 {
        return None;
    }
    let magic_cookie = &payload[236..240];
    if magic_cookie != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }

    let client_mac = copy_mac(&payload[28..34]);
    let mut message_type = None;
    let mut server_ip = None;
    let mut offset = 240;

    while offset + 2 <= payload.len() {
        let opt_type = payload[offset];
        if opt_type == 255 {
            break;
        }
        let opt_len = payload[offset + 1] as usize;
        if offset + 2 + opt_len > payload.len() {
            break;
        }
        let opt_data = &payload[offset + 2..offset + 2 + opt_len];

        match opt_type {
            53 => {
                if opt_len >= 1 {
                    message_type = Some(opt_data[0]);
                }
            }
            54 => {
                if opt_len >= 4 {
                    server_ip = Some(Ipv4Addr::new(opt_data[0], opt_data[1], opt_data[2], opt_data[3]));
                }
            }
            _ => {}
        }
        offset += 2 + opt_len;
    }

    Some(DhcpInfo {
        message_type,
        server_ip,
        client_mac,
    })
}

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
    if packet_type == 3 && body.len() >= 97 {
        let key_desc_type = body[0];
        let key_info = u16::from_be_bytes([body[1], body[2]]);
        let mut replay_counter_bytes = [0u8; 8];
        replay_counter_bytes.copy_from_slice(&body[9..17]);
        let replay_counter = u64::from_be_bytes(replay_counter_bytes);
        
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
            replay_counter,
            raw_key_data,
        });
    }
}

#[inline(always)]
fn copy_mac(slice: &[u8]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    if slice.len() >= 6 {
        mac.copy_from_slice(&slice[0..6]);
    }
    mac
}
