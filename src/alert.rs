use serde::{Serialize, Deserialize};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: u64,
    pub timestamp: String,
    pub timestamp_epoch_ms: u64,
    pub rule_name: &'static str,
    pub severity: &'static str,
    pub confidence: u32,
    pub affected_device: String,
    pub suspected_attacker: String,
    pub reason: String,
    pub evidence: String,
    pub timeline: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdsmCompressedAlert {
    pub alert_id: u64,
    pub timestamp: String,
    pub rule_name: String,
    pub severity: String,
    pub confidence: u32,
    pub affected_device: String,
    pub suspected_attacker: String,
    pub raw_payload_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f32,
    pub compressed_payload: Vec<u8>,
    pub reconstructed_json: String,
}

#[derive(Serialize, Deserialize)]
pub struct SemanticPacketSummary {
    pub time_offset_ms: u32,
    pub len: u32,
    pub protocol: String,
    pub info: String,
}

#[derive(Serialize, Deserialize)]
pub struct CompressedAlertPayload {
    pub alert_id: u64,
    pub rule_name: String,
    pub severity: String,
    pub confidence: u32,
    pub affected_device: String,
    pub suspected_attacker: String,
    pub reason: String,
    pub evidence: String,
    pub timeline: Vec<String>,
    pub packets: Vec<SemanticPacketSummary>,
}

pub struct IDSM;

impl IDSM {
    /// Compresses a SecurityAlert and its associated packets into an IdsmCompressedAlert.
    pub fn compress(alert: &SecurityAlert, packets: &[crate::parser::ParsedPacket]) -> IdsmCompressedAlert {
        
        let semantic_packets: Vec<SemanticPacketSummary> = packets.iter().map(|p| {
            let proto = match p.link_type {
                crate::parser::LinkType::Wifi80211 | crate::parser::LinkType::RadiotapWifi => {
                    if let Some(mgmt) = &p.wifi_mgmt {
                        format!("802.11 Mgmt Subtype {}", mgmt.subtype)
                    } else {
                        "802.11 Data".to_string()
                    }
                }
                crate::parser::LinkType::Ethernet => {
                    match &p.network {
                        crate::parser::NetworkLayer::Arp(_) => "ARP".to_string(),
                        crate::parser::NetworkLayer::Ipv4 { proto, .. } => {
                            match proto {
                                6 => "TCP".to_string(),
                                17 => "UDP".to_string(),
                                1 => "ICMP".to_string(),
                                _ => format!("IP({})", proto),
                            }
                        }
                        crate::parser::NetworkLayer::Ipv6 { next_hdr, .. } => {
                            match next_hdr {
                                6 => "TCP".to_string(),
                                17 => "UDP".to_string(),
                                58 => "ICMPv6".to_string(),
                                _ => format!("IPv6({})", next_hdr),
                            }
                        }
                        crate::parser::NetworkLayer::None => "Ethernet".to_string(),
                    }
                }
                _ => "Unknown".to_string(),
            };

            let info = match &p.network {
                crate::parser::NetworkLayer::Arp(arp) => {
                    format!("Opcode: {}, Sender: {:?}, Target: {:?}", arp.opcode, arp.sender_ip, arp.target_ip)
                }
                _ => {
                    match &p.transport {
                        crate::parser::TransportLayer::Tcp { src_port, dst_port, flags, .. } => {
                            format!("TCP Port {} -> {} [Flags: {:X}]", src_port, dst_port, flags)
                        }
                        crate::parser::TransportLayer::Udp { src_port, dst_port, .. } => {
                            format!("UDP Port {} -> {}", src_port, dst_port)
                        }
                        crate::parser::TransportLayer::Icmp { icmp_type, icmp_code, .. } => {
                            format!("ICMP Type {} Code {}", icmp_type, icmp_code)
                        }
                        _ => "".to_string(),
                    }
                }
            };

            // Calculate timestamp offset
            // Under simulation, use base_time
            SemanticPacketSummary {
                time_offset_ms: 0, 
                len: p.raw_payload.len() as u32,
                protocol: proto,
                info,
            }
        }).collect();

        let payload = CompressedAlertPayload {
            alert_id: alert.id,
            rule_name: alert.rule_name.to_string(),
            severity: alert.severity.to_string(),
            confidence: alert.confidence,
            affected_device: alert.affected_device.clone(),
            suspected_attacker: alert.suspected_attacker.clone(),
            reason: alert.reason.clone(),
            evidence: alert.evidence.clone(),
            timeline: alert.timeline.clone(),
            packets: semantic_packets,
        };

        // Serialize to JSON
        let serialized = serde_json::to_vec(&payload).unwrap_or_default();
        let raw_payload_size = serialized.len();

        // Compress JSON payload using zlib
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        let _ = encoder.write_all(&serialized);
        let compressed_payload = encoder.finish().unwrap_or_default();
        let compressed_size = compressed_payload.len();

        let compression_ratio = if raw_payload_size > 0 {
            (1.0 - (compressed_size as f32 / raw_payload_size as f32)) * 100.0
        } else {
            0.0
        };

        let reconstructed_json = serde_json::to_string_pretty(&payload).unwrap_or_default();

        IdsmCompressedAlert {
            alert_id: alert.id,
            timestamp: alert.timestamp.clone(),
            rule_name: alert.rule_name.to_string(),
            severity: alert.severity.to_string(),
            confidence: alert.confidence,
            affected_device: alert.affected_device.clone(),
            suspected_attacker: alert.suspected_attacker.clone(),
            raw_payload_size,
            compressed_size,
            compression_ratio,
            compressed_payload,
            reconstructed_json,
        }
    }
}
