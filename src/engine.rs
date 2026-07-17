use std::collections::HashMap;
use chrono::Local;
use crate::parser::{ParsedPacket, NetworkLayer, TransportLayer, AppLayer};
use crate::alert::*;

#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid: [u8; 6],
    pub ssid: String,
    pub channel: u8,
    pub security: String,
    pub last_seen: f64,
    pub beacon_count: u64,
    pub last_rssi: i8,
}

#[derive(Debug, Clone)]
pub struct ClientState {
    pub mac: [u8; 6],
    pub probe_timestamps: Vec<f64>,
    pub probed_ssids: Vec<String>,
    pub assoc_timestamps: Vec<f64>,
    pub auth_failures: Vec<f64>,
    pub deauth_timestamps: Vec<f64>,
    pub last_seen: f64,
    pub last_rssi: i8,
    pub last_seq_num: u16,
    
    // Traffic monitoring states (Rule 9 & 10)
    pub ip_address: Option<std::net::IpAddr>,
    pub tcp_scans: HashMap<u16, f64>, // port -> timestamp
    pub udp_scans: HashMap<u16, f64>, // port -> timestamp
    pub dns_queries: Vec<(String, f64)>, // domain -> timestamp
    pub diag_port_attempts: u32,
    pub infotainment_attempts: u32,
}

impl ClientState {
    pub fn new(mac: [u8; 6], rssi: i8, seq: u16, timestamp: f64) -> Self {
        ClientState {
            mac,
            probe_timestamps: Vec::new(),
            probed_ssids: Vec::new(),
            assoc_timestamps: Vec::new(),
            auth_failures: Vec::new(),
            deauth_timestamps: Vec::new(),
            last_seen: timestamp,
            last_rssi: rssi,
            last_seq_num: seq,
            ip_address: None,
            tcp_scans: HashMap::new(),
            udp_scans: HashMap::new(),
            dns_queries: Vec::new(),
            diag_port_attempts: 0,
            infotainment_attempts: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub client_mac: [u8; 6],
    pub bssid: [u8; 6],
    pub handshake_step: u8,
    pub last_step_time: f64,
    pub replay_count: u64,
    pub pmkid_attempts: u32,
}

struct PendingAlert {
    event_id: &'static str,
    event_name: &'static str,
    severity: Severity,
    payload: EventPayload,
}

pub struct StatefulDetectionEngine {
    pub alert_counter: u64,
    pub access_points: HashMap<[u8; 6], AccessPoint>,
    pub clients: HashMap<[u8; 6], ClientState>,
    pub sessions: HashMap<[u8; 6], SessionState>,
    
    // Vehicle configurations (Rule 5 & 6)
    pub vehicle_hotspot_enabled: bool,
    pub hotspot_ssid: String,
    pub hotspot_bssid: [u8; 6],
    pub hotspot_channel: u8,
    pub carplay_active: bool,
    
    // Time tracking for cleanup
    pub last_cleanup_time: f64,
    pub iface: String,
}

impl StatefulDetectionEngine {
    pub fn new(iface: String) -> Self {
        StatefulDetectionEngine {
            alert_counter: 0,
            access_points: HashMap::new(),
            clients: HashMap::new(),
            sessions: HashMap::new(),
            vehicle_hotspot_enabled: true,
            hotspot_ssid: "Enterprise_Secure".to_string(),
            hotspot_bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            hotspot_channel: 6,
            carplay_active: false,
            last_cleanup_time: 0.0,
            iface,
        }
    }

    /// Performs pruning of old state information in O(N) where N is active state entries.
    /// Cleans up state lists to prevent memory leaks during packet processing.
    pub fn expire_states(&mut self, now: f64) {
        if now - self.last_cleanup_time < 5.0 {
            return; // Run every 5 seconds to reduce CPU overhead
        }
        self.last_cleanup_time = now;

        let window = 60.0; // 60 seconds correlation window

        for client in self.clients.values_mut() {
            client.probe_timestamps.retain(|&t| now - t < window);
            client.assoc_timestamps.retain(|&t| now - t < window);
            client.auth_failures.retain(|&t| now - t < window);
            client.deauth_timestamps.retain(|&t| now - t < window);
            client.tcp_scans.retain(|_, &mut t| now - t < window);
            client.udp_scans.retain(|_, &mut t| now - t < window);
            client.dns_queries.retain(|(_, t)| now - *t < window);
        }

        // Expire inactive clients, APs, and sessions
        self.clients.retain(|_, client| now - client.last_seen < 300.0);
        self.access_points.retain(|_, ap| now - ap.last_seen < 300.0);
        self.sessions.retain(|_, sess| now - sess.last_step_time < 300.0);
    }

    /// Process a parsed packet and update the state machine.
    /// Returns a list of generated IdsmMessages.
    pub fn process_packet(&mut self, pkt: &ParsedPacket, now: f64) -> Vec<IdsmMessage> {
        self.expire_states(now);
        
        let mut alerts = Vec::new();
        let mut pending = Vec::new();

        // 1. Extract raw signal strength and sequence numbers
        let rssi = pkt.signal_dbm.unwrap_or(-50);
        let seq = 0; // standard sequence number if parsed (fallback)

        // 2. Track Access Point State
        if let Some(bssid) = pkt.bssid {
            if let Some(mgmt) = &pkt.wifi_mgmt {
                if mgmt.subtype == 8 { // Beacon frame
                    let ssid = mgmt.ssid.clone().unwrap_or_default();
                    let chan = mgmt.channel.unwrap_or(0);
                    let sec = if mgmt.rsn_info.is_some() { "WPA2/WPA3" } else { "Open" };

                    let ap = self.access_points.entry(bssid).or_insert_with(|| AccessPoint {
                        bssid,
                        ssid: ssid.clone(),
                        channel: chan,
                        security: sec.to_string(),
                        last_seen: now,
                        beacon_count: 0,
                        last_rssi: rssi,
                    });
                    
                    ap.beacon_count += 1;
                    ap.last_seen = now;
                    ap.last_rssi = rssi;
                    ap.channel = chan;
                    ap.security = sec.to_string();
                }
            }
        }

        // 3. Track Client State
        let client_mac = pkt.src_mac;
        if client_mac != [0; 6] && client_mac != [0xFF; 6] {
            let client = self.clients.entry(client_mac).or_insert_with(|| {
                ClientState::new(client_mac, rssi, seq, now)
            });
            client.last_seen = now;
            client.last_rssi = rssi;
            client.last_seq_num = seq;

            if let NetworkLayer::Ipv4 { src_ip, .. } = &pkt.network {
                client.ip_address = Some(std::net::IpAddr::V4(*src_ip));
            } else if let NetworkLayer::Ipv6 { src_ip, .. } = &pkt.network {
                client.ip_address = Some(std::net::IpAddr::V6(*src_ip));
            }
        }

        // --- EVALUATE BEHAVIORAL DETECTION RULES ---

        // Rule 8: Malformed Frames (evaluated first)
        if pkt.malformed {
            pending.push(PendingAlert {
                event_id: "E8",
                event_name: "Malformed Frame Detected",
                severity: Severity::Critical,
                payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                    packet_signature_hash: format!("{:?}", pkt.link_type),
                    signature_description: "Malformed frame: failed zero-copy bounds parsing".to_string(),
                    sender_list: vec![SenderRate {
                        sender_id: format_mac(pkt.src_mac),
                        pkt_rate_per_sender: 1,
                    }],
                    fingerprint_ids: vec![format_mac(pkt.dst_mac)],
                    recommended_mitigation: "Drop packet and log sender MAC for quarantine".to_string(),
                }),
            });
        }

        // Process 802.11 Management Frame rules
        if let Some(mgmt) = &pkt.wifi_mgmt {
            let client_mac_val = mgmt.client_mac.unwrap_or(pkt.src_mac);
            let bssid_str = format_mac(mgmt.bssid);
            let client_str = format_mac(client_mac_val);

            match mgmt.subtype {
                4 => { // Probe Request (Rule 1)
                    if let Some(client) = self.clients.get_mut(&pkt.src_mac) {
                        client.probe_timestamps.push(now);
                        if let Some(ssid) = &mgmt.ssid {
                            if !client.probed_ssids.contains(ssid) {
                                client.probed_ssids.push(ssid.clone());
                            }
                        }

                        // Rule 1.1: Probe Flooding
                        let probes_count = client.probe_timestamps.len();
                        if probes_count >= 25 {
                            pending.push(PendingAlert {
                                event_id: "E1.1",
                                event_name: "Radio Packet Flood Start",
                                severity: Severity::Medium,
                                payload: EventPayload::RadioPacketFloodStart(RadioPacketFloodStart {
                                    pkt_rate: probes_count as u32,
                                    baseline_rate: 2,
                                    window_duration_s: 60,
                                    rssi_avg: rssi as f32,
                                    modulation: "IEEE 802.11 Probe Request".to_string(),
                                    channel: mgmt.channel.unwrap_or(0) as u16,
                                }),
                            });
                            client.probe_timestamps.clear();
                        }

                        // Rule 1.2: Vehicle SSID Enumeration & Scanning
                        let unique_ssids = client.probed_ssids.len();
                        if unique_ssids >= 5 {
                            let mut vehicle_scan = false;
                            for ssid in &client.probed_ssids {
                                if ssid.contains("Tesla") || ssid.contains("Audi") || ssid.contains("Vehicle") || ssid.contains("MyCar") {
                                    vehicle_scan = true;
                                }
                            }
                            if vehicle_scan {
                                pending.push(PendingAlert {
                                    event_id: "E1.2",
                                    event_name: "Anomalous Burst Pattern",
                                    severity: Severity::High,
                                    payload: EventPayload::AnomalousBurstPattern(AnomalousBurstPattern {
                                        burst_start_ts: Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
                                        burst_duration_s: 60,
                                        targeted_message_ids: client.probed_ssids.clone(),
                                        missed_count: 0,
                                        timing_trace_uri: None,
                                    }),
                                });
                                client.probed_ssids.clear();
                            }
                        }
                    }
                }
                11 => { // Authentication (Rule 2)
                    if let Some(status) = mgmt.status_code {
                        if status != 0 { // Fail
                            if let Some(client) = self.clients.get_mut(&client_mac_val) {
                                client.auth_failures.push(now);
                                let fails = client.auth_failures.len();
                                if fails >= 5 {
                                    pending.push(PendingAlert {
                                        event_id: "E2.1",
                                        event_name: "High Broadcast Storm",
                                        severity: Severity::Medium,
                                        payload: EventPayload::HighBroadcastStorm(HighBroadcastStorm {
                                            broadcast_ratio: 0.0,
                                            pkt_rate: fails as u32,
                                            top_broadcast_srcs: vec![client_str.clone()],
                                            top_broadcast_pkt_counts: vec![fails as u32],
                                            mitigation_applied: false,
                                            mitigation_type: None,
                                        }),
                                    });
                                    client.auth_failures.clear();
                                }
                            }
                        }
                    }
                }
                0 => { // Association Request (Rule 2 & 6)
                    if let Some(client) = self.clients.get_mut(&client_mac_val) {
                        client.assoc_timestamps.push(now);
                        let reconnects = client.assoc_timestamps.len();
                        
                        // Rule 2: Association Flood / Reconnect Abuse
                        if reconnects >= 8 {
                            pending.push(PendingAlert {
                                event_id: "E2.2",
                                event_name: "High Broadcast Storm",
                                severity: Severity::Medium,
                                payload: EventPayload::HighBroadcastStorm(HighBroadcastStorm {
                                    broadcast_ratio: 0.1,
                                    pkt_rate: reconnects as u32,
                                    top_broadcast_srcs: vec![client_str.clone()],
                                    top_broadcast_pkt_counts: vec![reconnects as u32],
                                    mitigation_applied: false,
                                    mitigation_type: None,
                                }),
                            });
                            client.assoc_timestamps.clear();
                        }

                        // Rule 6: Wireless Projection (Android Auto / CarPlay Onboarding Check)
                        if let Some(ssid) = &mgmt.ssid {
                            if ssid.contains("CarPlay") || ssid.contains("AndroidAuto") {
                                if !self.carplay_active {
                                    pending.push(PendingAlert {
                                        event_id: "E6",
                                        event_name: "Protocol Conformant Flood",
                                        severity: Severity::High,
                                        payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                                            packet_signature_hash: format!("ssid_hash_{}", ssid),
                                            signature_description: format!("Unauthenticated Wireless Projection Link setup targeting SSID: {}", ssid),
                                            sender_list: vec![SenderRate {
                                                sender_id: client_str.clone(),
                                                pkt_rate_per_sender: 1,
                                            }],
                                            fingerprint_ids: vec![bssid_str.clone()],
                                            recommended_mitigation: "Enforce Bluetooth handoff confirmation before projection association".to_string(),
                                        }),
                                    });
                                }
                            }
                        }
                    }
                }
                8 => { // Beacon Frame (Rule 4 & 5)
                    let ssid = mgmt.ssid.clone().unwrap_or_default();
                    let chan = mgmt.channel.unwrap_or(0);
                    
                    // Rule 4.2: Beacon Spoofing / Twin AP Impersonation
                    if ssid == self.hotspot_ssid && mgmt.bssid != self.hotspot_bssid {
                        pending.push(PendingAlert {
                            event_id: "E4.2",
                            event_name: "Protocol Conformant Flood",
                            severity: Severity::Critical,
                            payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                                packet_signature_hash: format!("twin_ap_{}", ssid),
                                signature_description: format!("Rogue AP / Evil Twin detected! Unauthorized BSSID '{}' is broadcasting authorized hotspot SSID '{}'.", bssid_str, ssid),
                                sender_list: vec![SenderRate {
                                    sender_id: bssid_str.clone(),
                                    pkt_rate_per_sender: 1,
                                }],
                                fingerprint_ids: vec![format_mac(self.hotspot_bssid)],
                                recommended_mitigation: "Block rogue BSSID and alert operator of active Evil Twin".to_string(),
                            }),
                        });
                    }

                    // Rule 5: Vehicle Hotspot Monitoring
                    if mgmt.bssid == self.hotspot_bssid {
                        let sec = if mgmt.rsn_info.is_some() { "WPA2/WPA3" } else { "Open" };
                        if sec == "Open" {
                            pending.push(PendingAlert {
                                event_id: "E5.1",
                                event_name: "Control Channel Starvation",
                                severity: Severity::Critical,
                                payload: EventPayload::ControlChannelStarvation(ControlChannelStarvation {
                                    channel_id: chan.to_string(),
                                    loss_rate: 0.0,
                                    median_latency_ms: 0,
                                    missing_message_ids: vec!["RSN_Tag_Missing".to_string()],
                                    recent_message_samples: vec!["Security Downgrade to Open".to_string()],
                                    safety_escalation_flag: true,
                                }),
                            });
                        }
                        if chan != self.hotspot_channel && chan != 0 {
                            pending.push(PendingAlert {
                                event_id: "E5.2",
                                event_name: "Channel Jamming Indication",
                                severity: Severity::High,
                                payload: EventPayload::ChannelJammingIndication(ChannelJammingIndication {
                                    noise_floor_dbm: rssi as f32,
                                    crc_error_rate: 0.0,
                                    affected_channels: vec![self.hotspot_channel as u16, chan as u16],
                                    spectrogram_id: None,
                                    rf_scan_snapshot_uri: None,
                                    mitigation_recommendation: "Investigate gateway controller for unauthorized channel changes".to_string(),
                                }),
                            });
                            self.hotspot_channel = chan;
                        }
                    }
                }
                10 | 12 => { // Disassociation / Deauthentication (Rule 4)
                    if let Some(client) = self.clients.get_mut(&client_mac_val) {
                        client.deauth_timestamps.push(now);
                        let deauths = client.deauth_timestamps.len();
                        
                        // Rule 4.1: Deauthentication Flood
                        if deauths >= 10 {
                            pending.push(PendingAlert {
                                event_id: "E4.1",
                                event_name: "Radio Packet Flood Start",
                                severity: Severity::Critical,
                                payload: EventPayload::RadioPacketFloodStart(RadioPacketFloodStart {
                                    pkt_rate: deauths as u32,
                                    baseline_rate: 1,
                                    window_duration_s: 10,
                                    rssi_avg: rssi as f32,
                                    modulation: "802.11 Deauth/Disassoc".to_string(),
                                    channel: 0,
                                }),
                            });
                            client.deauth_timestamps.clear();
                        }
                    }
                }
                _ => {}
            }
        }

        // Process EAPOL Handshakes (Rule 3)
        if let AppLayer::Eapol(eapol) = &pkt.app {
            let client_mac_val = pkt.src_mac;
            let client_str = format_mac(client_mac_val);
            let bssid_str = format_mac(pkt.bssid.unwrap_or([0; 6]));

            let session = self.sessions.entry(client_mac_val).or_insert_with(|| SessionState {
                client_mac: client_mac_val,
                bssid: pkt.bssid.unwrap_or([0; 6]),
                handshake_step: 0,
                last_step_time: now,
                replay_count: 0,
                pmkid_attempts: 0,
            });

            session.last_step_time = now;

            let key_info = eapol.key_info;
            let error = (key_info & 0x0100) != 0;
            
            // Rule 3.1: Rekey and Handshake anomalies
            if error {
                pending.push(PendingAlert {
                    event_id: "E3.1",
                    event_name: "Protocol Conformant Flood",
                    severity: Severity::High,
                    payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                        packet_signature_hash: format!("key_info_{:04X}", key_info),
                        signature_description: "EAPOL Handshake Error flag set. Potential brute-force dictionary attack against PSK.".to_string(),
                        sender_list: vec![SenderRate {
                            sender_id: client_str.clone(),
                            pkt_rate_per_sender: 1,
                        }],
                        fingerprint_ids: vec![bssid_str.clone()],
                        recommended_mitigation: "Trigger temporary MAC lockout for candidate client".to_string(),
                    }),
                });
            }

            // KRACK retransmission indicators
            if eapol.replay_counter <= session.replay_count && session.replay_count > 0 {
                pending.push(PendingAlert {
                    event_id: "E3.2",
                    event_name: "Packet Replay Flood",
                    severity: Severity::Critical,
                    payload: EventPayload::PacketReplayFlood(PacketReplayFlood {
                        payload_hash: format!("replay_{}_{}", eapol.replay_counter, session.replay_count),
                        repeat_count: 2,
                        involved_srcs: vec![client_str.clone(), bssid_str.clone()],
                        exemplar_packet_reference: Some("EAPOL Message 3 Replay".to_string()),
                    }),
                });
            }
            session.replay_count = eapol.replay_counter;
        }

        // Process IP / TCP / UDP Network Traffic Rules (Rule 9 & 10)
        let client_mac_val = pkt.src_mac;
        if let Some(client) = self.clients.get_mut(&client_mac_val) {
            match &pkt.transport {
                TransportLayer::Tcp { dst_port, flags, .. } => {
                    let d_port = *dst_port;
                    let is_syn = (flags & 0x0002) != 0 && (flags & 0x0010) == 0; // SYN set, ACK clear

                    if is_syn {
                        client.tcp_scans.insert(d_port, now);
                        
                        // Rule 9.1: TCP Port Scans
                        let scan_ports_count = client.tcp_scans.len();
                        if scan_ports_count >= 20 {
                            let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client_mac_val));
                            let target_ports: Vec<String> = client.tcp_scans.keys().map(|p| p.to_string()).collect();
                            pending.push(PendingAlert {
                                event_id: "E9.1",
                                event_name: "Rapid Source Switching",
                                severity: Severity::High,
                                payload: EventPayload::RapidSourceSwitching(RapidSourceSwitching {
                                    unique_src_count: 1,
                                    aggregate_pkt_rate: scan_ports_count as u32,
                                    top_srcs_summary: vec![ip_or_mac],
                                    sample_rate: 1,
                                    cluster_id: Some(format!("TCP Ports: {:?}", target_ports)),
                                }),
                            });
                            client.tcp_scans.clear();
                        }

                        // Rule 9.2: Diagnostic API sweep
                        if d_port == 13400 || d_port == 8080 || d_port == 8081 || d_port == 9000 {
                            client.diag_port_attempts += 1;
                            if client.diag_port_attempts >= 5 {
                                let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client_mac_val));
                                pending.push(PendingAlert {
                                    event_id: "E9.2",
                                    event_name: "Anomalous Burst Pattern",
                                    severity: Severity::Critical,
                                    payload: EventPayload::AnomalousBurstPattern(AnomalousBurstPattern {
                                        burst_start_ts: Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
                                        burst_duration_s: 5,
                                        targeted_message_ids: vec![format!("DoIP/Diag Port {}", d_port)],
                                        missed_count: client.diag_port_attempts,
                                        timing_trace_uri: Some(format!("diagnostics://{}", ip_or_mac)),
                                    }),
                                });
                                client.diag_port_attempts = 0;
                            }
                        }

                        // Rule 10: Infotainment Services Unauthorized Access
                        if d_port == 9000 || d_port == 8081 || d_port == 8008 {
                            let unauthorized = match client.ip_address {
                                Some(std::net::IpAddr::V4(ip)) => {
                                    let octets = ip.octets();
                                    octets[3] < 5 || octets[3] > 20
                                }
                                _ => true,
                            };
                            if unauthorized {
                                client.infotainment_attempts += 1;
                                if client.infotainment_attempts >= 3 {
                                    let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client_mac_val));
                                    pending.push(PendingAlert {
                                        event_id: "E10",
                                        event_name: "Protocol Conformant Flood",
                                        severity: Severity::High,
                                        payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                                            packet_signature_hash: format!("infotainment_port_{}", d_port),
                                            signature_description: format!("Abnormal access to infotainment maintenance endpoint. Host outside whitelisted subnet attempted connection to port {}.", d_port),
                                            sender_list: vec![SenderRate {
                                                sender_id: ip_or_mac.clone(),
                                                pkt_rate_per_sender: client.infotainment_attempts,
                                            }],
                                            fingerprint_ids: vec![format!("Port {}", d_port)],
                                            recommended_mitigation: "Block connection and log unauthorized subnet access attempt".to_string(),
                                        }),
                                    });
                                    client.infotainment_attempts = 0;
                                }
                            }
                        }
                    }
                }
                TransportLayer::Udp { dst_port, .. } => {
                    let d_port = *dst_port;
                    client.udp_scans.insert(d_port, now);
                    
                    // Rule 9.1: UDP Port Scans
                    let scan_ports_count = client.udp_scans.len();
                    if scan_ports_count >= 20 {
                        let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client_mac_val));
                        let target_ports: Vec<String> = client.udp_scans.keys().map(|p| p.to_string()).collect();
                        pending.push(PendingAlert {
                            event_id: "E9.1U",
                            event_name: "Rapid Source Switching",
                            severity: Severity::High,
                            payload: EventPayload::RapidSourceSwitching(RapidSourceSwitching {
                                unique_src_count: 1,
                                aggregate_pkt_rate: scan_ports_count as u32,
                                top_srcs_summary: vec![ip_or_mac],
                                sample_rate: 1,
                                cluster_id: Some(format!("UDP Ports: {:?}", target_ports)),
                            }),
                        });
                        client.udp_scans.clear();
                    }
                }
                _ => {}
            }

            // Rule 9.3: DNS Tunneling Detection
            if let AppLayer::Dns(dns) = &pkt.app {
                if let Some(query) = &dns.query {
                    client.dns_queries.push((query.clone(), now));
                    
                    let tunnel_queries = client.dns_queries.iter()
                        .filter(|(q, _)| q.len() > 30 || q.contains("tunnel") || q.contains("aGVsZG93b3JsZE9pcHVz"))
                        .count();
                        
                    if tunnel_queries >= 25 {
                        let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client_mac_val));
                        pending.push(PendingAlert {
                            event_id: "E9.3",
                            event_name: "Protocol Conformant Flood",
                            severity: Severity::High,
                            payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                                packet_signature_hash: "dns_tunneling_ratio_high".to_string(),
                                signature_description: format!("DNS Tunneling activity detected. Associated client generated {} anomalous high-length subdomain requests.", tunnel_queries),
                                sender_list: vec![SenderRate {
                                    sender_id: ip_or_mac,
                                    pkt_rate_per_sender: tunnel_queries as u32,
                                }],
                                fingerprint_ids: client.dns_queries.iter().take(3).map(|(q,_)| q.clone()).collect(),
                                recommended_mitigation: "Quarantine host and block DNS server domain routing".to_string(),
                            }),
                        });
                        client.dns_queries.clear();
                    }
                }
            }
        }

        // 4. Create actual IdsmMessage objects once all client state borrows are released
        for p in pending {
            alerts.push(self.create_message(
                p.event_id,
                p.event_name,
                p.severity,
                p.payload,
            ));
        }

        alerts
    }

    fn create_message(
        &mut self,
        event_id: &'static str,
        event_name: &'static str,
        severity: Severity,
        payload: EventPayload,
    ) -> IdsmMessage {
        self.alert_counter += 1;
        let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string();

        IdsmMessage {
            seq_no: self.alert_counter,
            ttl_ms: 5000,
            sensor_id: "sensor-Wi-Fi/Ethernet-01".to_string(),
            sensor_cert_id: "cert-abc-123".to_string(),
            signature: Vec::new(),
            event: SensorEvent {
                event_id,
                event_name,
                severity,
                timestamp,
                vehicle_id_hash: "vehhash001".to_string(),
                iface: self.iface.clone(),
                capture_id: Some(format!("cap-{}", self.alert_counter)),
                evidence_uri: Some(format!("evidence://cap-{}", self.alert_counter)),
                payload,
            },
        }
    }
}

// Helpers
fn format_mac(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
