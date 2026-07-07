use std::collections::HashMap;
use chrono::Local;
use crate::parser::{ParsedPacket, NetworkLayer, TransportLayer, AppLayer};
use crate::alert::SecurityAlert;

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
    rule_name: &'static str,
    severity: &'static str,
    confidence: u32,
    affected_device: String,
    suspected_attacker: String,
    reason: String,
    evidence: String,
    timeline: Vec<String>,
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
}

impl StatefulDetectionEngine {
    pub fn new() -> Self {
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
    /// Returns a list of generated SecurityAlerts.
    pub fn process_packet(&mut self, pkt: &ParsedPacket, now: f64) -> Vec<SecurityAlert> {
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
                rule_name: "Rule 8: Malformed Frame",
                severity: "Critical",
                confidence: 95,
                affected_device: format_mac(pkt.src_mac),
                suspected_attacker: format_mac(pkt.dst_mac),
                reason: "Malformed packet header or invalid fields matching firmware exception crash pattern.".to_string(),
                evidence: format!("Packet failed zero-copy bounds parsing. LinkType: {:?}", pkt.link_type),
                timeline: vec![format!("Malformed frame received from source MAC: {}", format_mac(pkt.src_mac))]
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
                            let conf = std::cmp::min(100, 50 + (probes_count as u32 - 25) * 2);
                            pending.push(PendingAlert {
                                rule_name: "Rule 1: Scan and Probe Activity",
                                severity: "Medium",
                                confidence: conf,
                                affected_device: "Broadcast".to_string(),
                                suspected_attacker: client_str.clone(),
                                reason: format!("Excessive probe requests ({} requests in last 60s) indicating aggressive Wi-Fi scanning.", probes_count),
                                evidence: format!("Probe requests exceed normal discovery rate. Source MAC: {}", client_str),
                                timeline: vec![format!("Probe storm initiated by: {}", client_str)]
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
                                    rule_name: "Rule 1: Scan and Probe Activity",
                                    severity: "High",
                                    confidence: 90,
                                    affected_device: "Gateway".to_string(),
                                    suspected_attacker: client_str.clone(),
                                    reason: format!("Automotive SSID enumeration detected. Client probed for {} unique SSIDs, querying vehicle profile names.", unique_ssids),
                                    evidence: format!("Probed SSIDs: {:?}", client.probed_ssids),
                                    timeline: vec![format!("Vehicle-directed scanning from: {}", client_str)]
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
                                        rule_name: "Rule 2: Association and Authentication",
                                        severity: "Medium",
                                        confidence: 80 + (fails as u32 - 5) * 3,
                                        affected_device: bssid_str.clone(),
                                        suspected_attacker: client_str.clone(),
                                        reason: format!("Wi-Fi authentication brute-force attempt. Client failed authentication {} times.", fails),
                                        evidence: format!("Failed authentication attempts to AP: {}. Error Code: {}", bssid_str, status),
                                        timeline: vec![format!("Client {} brute-forcing association on AP {}", client_str, bssid_str)]
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
                                rule_name: "Rule 2: Association and Authentication",
                                severity: "Medium",
                                confidence: 85,
                                affected_device: bssid_str.clone(),
                                suspected_attacker: client_str.clone(),
                                reason: format!("Rapid reconnect abuse detected ({} associations in 60s). Possible driver exhaustion attempt.", reconnects),
                                evidence: format!("Frequent association requests targeting AP BSSID: {}", bssid_str),
                                timeline: vec![format!("Association flood from client MAC: {}", client_str)]
                            });
                            client.assoc_timestamps.clear();
                        }

                        // Rule 6: Wireless Projection (Android Auto / CarPlay Onboarding Check)
                        if let Some(ssid) = &mgmt.ssid {
                            if ssid.contains("CarPlay") || ssid.contains("AndroidAuto") {
                                if !self.carplay_active {
                                    pending.push(PendingAlert {
                                        rule_name: "Rule 6: Wireless Projection",
                                        severity: "High",
                                        confidence: 88,
                                        affected_device: "Infotainment".to_string(),
                                        suspected_attacker: client_str.clone(),
                                        reason: format!("Suspicious Wireless Projection onboarding. Phone client connected to SSID '{}' directly without Bluetooth handoff context.", ssid),
                                        evidence: format!("CarPlay / Android Auto link initiated by unauthenticated MAC: {}", client_str),
                                        timeline: vec![format!("CarPlay association request without BT exchange from: {}", client_str)]
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
                            rule_name: "Rule 4: Management Frame Attacks",
                            severity: "Critical",
                            confidence: 95,
                            affected_device: format_mac(self.hotspot_bssid),
                            suspected_attacker: format_mac(mgmt.bssid),
                            reason: format!("Rogue AP / Evil Twin detected! SSID '{}' is broadcasting on unauthorized BSSID '{}' on channel {}.", ssid, bssid_str, chan),
                            evidence: format!("Authorized AP BSSID: {}. Spoofed AP BSSID: {}", format_mac(self.hotspot_bssid), bssid_str),
                            timeline: vec![
                                format!("SSID mismatch detected: authorized BSSID={}, rogue BSSID={}", format_mac(self.hotspot_bssid), bssid_str),
                                format!("Rogue AP signal strength: {} dBm", rssi)
                            ]
                        });
                    }

                    // Rule 5: Vehicle Hotspot Monitoring
                    if mgmt.bssid == self.hotspot_bssid {
                        let sec = if mgmt.rsn_info.is_some() { "WPA2/WPA3" } else { "Open" };
                        if sec == "Open" {
                            pending.push(PendingAlert {
                                rule_name: "Rule 5: Vehicle Hotspot Monitoring",
                                severity: "Critical",
                                confidence: 99,
                                affected_device: bssid_str.clone(),
                                suspected_attacker: "Gateway".to_string(),
                                reason: "Vehicle hotspot security downgraded to Open! Unauthorized modification of wireless gateway configurations.".to_string(),
                                evidence: format!("Security capabilities in beacon frame missing RSN tags."),
                                timeline: vec![format!("Hotspot security settings changed to Open on AP: {}", bssid_str)]
                            });
                        }
                        if chan != self.hotspot_channel && chan != 0 {
                            pending.push(PendingAlert {
                                rule_name: "Rule 5: Vehicle Hotspot Monitoring",
                                severity: "High",
                                confidence: 90,
                                affected_device: bssid_str.clone(),
                                suspected_attacker: "Gateway".to_string(),
                                reason: format!("Unexpected channel change for vehicle hotspot from channel {} to {}.", self.hotspot_channel, chan),
                                evidence: format!("Beacon advertisement channel mismatch."),
                                timeline: vec![format!("AP channel configuration changed on BSSID: {}", bssid_str)]
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
                                rule_name: "Rule 4: Management Frame Attacks",
                                severity: "Critical",
                                confidence: 98,
                                affected_device: client_str.clone(),
                                suspected_attacker: format_mac(pkt.src_mac),
                                reason: format!("Deauthentication flood targeting client '{}' ({} frames in 10s). Possible Wi-Fi disassociation attack.", client_str, deauths),
                                evidence: format!("Source MAC '{}' sent flood of deauth frames to Target MAC '{}'.", format_mac(pkt.src_mac), client_str),
                                timeline: vec![
                                    format!("Deauth flood targets client: {}", client_str),
                                    format!("Attacker MAC: {}", format_mac(pkt.src_mac))
                                ]
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
                    rule_name: "Rule 3: WPA/WPA2/WPA3 Negotiation",
                    severity: "High",
                    confidence: 85,
                    affected_device: bssid_str.clone(),
                    suspected_attacker: client_str.clone(),
                    reason: "EAPOL Handshake Error flag set. Potential brute-force dictionary attack against PSK.".to_string(),
                    evidence: format!("Key Info flags indicate negotiation error. KeyInfo: {:04X}", key_info),
                    timeline: vec![format!("Handshake failed for client: {}", client_str)]
                });
            }

            // KRACK retransmission indicators
            if eapol.replay_counter <= session.replay_count && session.replay_count > 0 {
                pending.push(PendingAlert {
                    rule_name: "Rule 3: WPA/WPA2/WPA3 Negotiation",
                    severity: "Critical",
                    confidence: 92,
                    affected_device: bssid_str.clone(),
                    suspected_attacker: client_str.clone(),
                    reason: "Suspicious EAPOL Key Replay. Retransmission of handshake message 3 detected (Potential KRACK attack).".to_string(),
                    evidence: format!("EAPOL Replay counter repeat: {} <= {}.", eapol.replay_counter, session.replay_count),
                    timeline: vec![format!("KRACK indicator on client: {}", client_str)]
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
                            pending.push(PendingAlert {
                                rule_name: "Rule 9: Traffic After Association",
                                severity: "High",
                                confidence: 94,
                                affected_device: ip_or_mac.clone(),
                                suspected_attacker: "Internal Subnet".to_string(),
                                reason: format!("TCP SYN Port Scan detected from associated host. Scanned {} unique ports in 60s.", scan_ports_count),
                                evidence: format!("Source IP/MAC: {:?}. Ports targeted: {:?}", client.ip_address, client.tcp_scans.keys()),
                                timeline: vec![format!("Associated client {} port scanning", format_mac(client_mac_val))]
                            });
                            client.tcp_scans.clear();
                        }

                        // Rule 9.2: Diagnostic API sweep
                        if d_port == 13400 || d_port == 8080 || d_port == 8081 || d_port == 9000 {
                            client.diag_port_attempts += 1;
                            if client.diag_port_attempts >= 5 {
                                let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client_mac_val));
                                pending.push(PendingAlert {
                                    rule_name: "Rule 9: Traffic After Association",
                                    severity: "Critical",
                                    confidence: 97,
                                    affected_device: "Vehicle ECU Gateway".to_string(),
                                    suspected_attacker: ip_or_mac,
                                    reason: "Unauthorized vehicle diagnostics sweep. Client repeatedly targeted critical services ports (e.g. DoIP port 13400 or updates port 9000).".to_string(),
                                    evidence: format!("Targeted port: {}", d_port),
                                    timeline: vec![format!("Client accessed diagnostics APIs on port: {}", d_port)]
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
                                        rule_name: "Rule 10: Infotainment Services",
                                        severity: "High",
                                        confidence: 90,
                                        affected_device: format!("Infotainment (Port {})", d_port),
                                        suspected_attacker: ip_or_mac,
                                        reason: format!("Abnormal access to infotainment maintenance endpoint. Host outside whitelisted subnet attempted connection to port {}.", d_port),
                                        evidence: format!("Accessing entity IP: {:?}", client.ip_address),
                                        timeline: vec![format!("Unauthorized infotainment access attempt on port: {}", d_port)]
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
                        pending.push(PendingAlert {
                            rule_name: "Rule 9: Traffic After Association",
                            severity: "High",
                            confidence: 92,
                            affected_device: ip_or_mac,
                            suspected_attacker: "Internal Subnet".to_string(),
                            reason: format!("UDP Port Scan detected from associated host. Scanned {} unique UDP ports in 60s.", scan_ports_count),
                            evidence: format!("Source IP/MAC: {}", format_mac(client_mac_val)),
                            timeline: vec![format!("UDP port scanning by associated client: {}", format_mac(client_mac_val))]
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
                            rule_name: "Rule 9: Traffic After Association",
                            severity: "High",
                            confidence: 89,
                            affected_device: "External DNS Server".to_string(),
                            suspected_attacker: ip_or_mac,
                            reason: format!("DNS Tunneling activity detected. Associated client generated {} anomalous high-length subdomain requests.", tunnel_queries),
                            evidence: format!("Sample tunneling subdomains: {:?}", client.dns_queries.iter().take(3).map(|(q,_)| q).collect::<Vec<_>>()),
                            timeline: vec![format!("DNS Tunneling signature matched from source: {}", format_mac(client_mac_val))]
                        });
                        client.dns_queries.clear();
                    }
                }
            }
        }

        // 4. Create actual SecurityAlert objects once all client state borrows are released
        for p in pending {
            alerts.push(self.create_alert(
                p.rule_name,
                p.severity,
                p.confidence,
                p.affected_device,
                p.suspected_attacker,
                p.reason,
                p.evidence,
                p.timeline,
            ));
        }

        alerts
    }

    fn create_alert(
        &mut self,
        rule_name: &'static str,
        severity: &'static str,
        confidence: u32,
        affected_device: String,
        suspected_attacker: String,
        reason: String,
        evidence: String,
        timeline: Vec<String>,
    ) -> SecurityAlert {
        self.alert_counter += 1;
        let dt = Local::now();
        let timestamp = dt.format("%H:%M:%S%.6f").to_string();
        let timestamp_epoch_ms = SystemTime_now_ms();

        SecurityAlert {
            id: self.alert_counter,
            timestamp,
            timestamp_epoch_ms,
            rule_name,
            severity,
            confidence,
            affected_device,
            suspected_attacker,
            reason,
            evidence,
            timeline,
        }
    }
}

// Helpers
fn format_mac(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

#[allow(non_snake_case)]
fn SystemTime_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
