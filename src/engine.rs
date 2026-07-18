use std::collections::HashMap;
use chrono::Local;
use serde::Deserialize;
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
    pub rule_timestamps: HashMap<u32, Vec<f64>>,
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
            rule_timestamps: HashMap::new(),
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

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: u32,
    pub enabled: bool,
    pub action: String,
    pub message: String,
    pub class: String,
    pub severity: u8,
    pub scope: ScopeConfig,
    #[serde(rename = "match")]
    pub match_config: MatchConfig,
    pub context: ContextConfig,
    pub behaviour: BehaviourConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    pub interfaces: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatchConfig {
    pub ip: IpMatch,
    pub transport: TransportMatch,
    pub direction: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpMatch {
    pub src_ip: String,
    pub dst_ip: String,
    pub ip_version: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransportMatch {
    pub protocol: Vec<String>,
    pub src_port: serde_json::Value,
    pub dst_port: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContextConfig {
    pub flow: FlowConfig,
    pub limits: Option<HashMap<String, LimitConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitConfig {
    pub per: String,
    pub connections: u32,
    pub interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BehaviourConfig {
    pub per_src: Option<PerSrcConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PerSrcConfig {
    pub max_requests_per_minute: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct EvaluatedRule {
    pub id: u32,
    pub event_id: &'static str,
    pub event_name: &'static str,
    pub severity: Severity,
    pub action: String,
    pub class: String,
    pub scope: ScopeConfig,
    pub match_config: MatchConfig,
    pub context: ContextConfig,
    pub behaviour: BehaviourConfig,
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
    
    // Loaded rules from rules.json
    pub rules: Vec<EvaluatedRule>,
}

impl StatefulDetectionEngine {
    pub fn new(iface: String) -> Self {
        let rules_loaded = match std::fs::read_to_string("rules.json") {
            Ok(content) => match serde_json::from_str::<HashMap<String, RuleConfig>>(&content) {
                Ok(raw_rules) => raw_rules.into_values().collect::<Vec<_>>(),
                Err(e) => {
                    eprintln!("[Warning] Failed to parse rules.json: {}", e);
                    Vec::new()
                }
            },
            Err(e) => {
                eprintln!("[Warning] Failed to read rules.json: {}", e);
                Vec::new()
            }
        };

        let mut rules = Vec::new();
        for r in rules_loaded {
            if !r.enabled {
                continue;
            }
            let event_id: &'static str = Box::leak(format!("E_RULE_{}", r.id).into_boxed_str());
            let event_name: &'static str = Box::leak(r.message.clone().into_boxed_str());
            let severity = match r.severity {
                0 => Severity::Info,
                1 => Severity::Low,
                2 => Severity::Medium,
                3 => Severity::High,
                _ => Severity::Critical,
            };
            rules.push(EvaluatedRule {
                id: r.id,
                event_id,
                event_name,
                severity,
                action: r.action,
                class: r.class,
                scope: r.scope,
                match_config: r.match_config,
                context: r.context,
                behaviour: r.behaviour,
            });
        }

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
            rules,
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
            for timestamps in client.rule_timestamps.values_mut() {
                timestamps.retain(|&t| now - t < window);
            }
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

        // --- EVALUATE DYNAMIC RULES FROM rules.json ---
        let client_mac_val = pkt.src_mac;
        if let Some(client) = self.clients.get_mut(&client_mac_val) {
            for rule in &self.rules {
                if matches_rule(rule, pkt, &self.iface) {
                    let timestamps = client.rule_timestamps.entry(rule.id).or_default();
                    timestamps.push(now);

                    let mut triggered = false;
                    let mut count_to_report = timestamps.len();

                    // Check max_requests_per_minute
                    if let Some(per_src) = &rule.behaviour.per_src {
                        if let Some(max_req) = per_src.max_requests_per_minute {
                            let count = timestamps.iter().filter(|&&t| now - t < 60.0).count();
                            count_to_report = count;
                            if count >= max_req as usize {
                                triggered = true;
                            }
                        }
                    }

                    // Check max_conn_rate
                    if !triggered {
                        if let Some(limits) = &rule.context.limits {
                            if let Some(conn_rate) = limits.get("max_conn_rate") {
                                let window = conn_rate.interval_ms as f64 / 1000.0;
                                let count = timestamps.iter().filter(|&&t| now - t < window).count();
                                if count >= conn_rate.connections as usize {
                                    triggered = true;
                                    count_to_report = count;
                                }
                            }
                        }
                    }

                    // Prune old timestamps
                    timestamps.retain(|&t| now - t < 60.0);

                    if triggered {
                        timestamps.clear();
                        let ip_or_mac = client.ip_address.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(client.mac));
                        pending.push(PendingAlert {
                            event_id: rule.event_id,
                            event_name: rule.event_name,
                            severity: rule.severity.clone(),
                            payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                                packet_signature_hash: format!("rule_{}", rule.id),
                                signature_description: format!(
                                    "Rule '{}' (id: {}) triggered for client {}. Behavioral threshold exceeded.",
                                    rule.event_name, rule.id, ip_or_mac
                                ),
                                sender_list: vec![SenderRate {
                                    sender_id: ip_or_mac.clone(),
                                    pkt_rate_per_sender: count_to_report as u32,
                                }],
                                fingerprint_ids: vec![rule.class.clone()],
                                recommended_mitigation: match rule.action.as_str() {
                                    "alert" => "Log alert and monitor host behavior".to_string(),
                                    "drop" => "Drop offending packets".to_string(),
                                    "block" => "Quarantine host and block all traffic".to_string(),
                                    _ => "Monitor host activity".to_string(),
                                },
                            }),
                        });
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

fn matches_rule(rule: &EvaluatedRule, pkt: &ParsedPacket, iface: &str) -> bool {
    // 1. Check scope/interface
    if !rule.scope.interfaces.iter().any(|i| i == "any" || i == iface) {
        return false;
    }

    // 2. Check IP version & IPs
    match &pkt.network {
        NetworkLayer::Ipv4 { src_ip, dst_ip, .. } => {
            if !rule.match_config.ip.ip_version.contains(&4) {
                return false;
            }
            if rule.match_config.ip.src_ip != "any" && rule.match_config.ip.src_ip != src_ip.to_string() {
                return false;
            }
            if rule.match_config.ip.dst_ip != "any" && rule.match_config.ip.dst_ip != dst_ip.to_string() {
                return false;
            }
        }
        NetworkLayer::Ipv6 { src_ip, dst_ip, .. } => {
            if !rule.match_config.ip.ip_version.contains(&6) {
                return false;
            }
            if rule.match_config.ip.src_ip != "any" && rule.match_config.ip.src_ip != src_ip.to_string() {
                return false;
            }
            if rule.match_config.ip.dst_ip != "any" && rule.match_config.ip.dst_ip != dst_ip.to_string() {
                return false;
            }
        }
        NetworkLayer::Arp(arp) => {
            if rule.match_config.ip.src_ip != "any" && rule.match_config.ip.src_ip != arp.sender_ip.to_string() {
                return false;
            }
            if rule.match_config.ip.dst_ip != "any" && rule.match_config.ip.dst_ip != arp.target_ip.to_string() {
                return false;
            }
        }
        NetworkLayer::None => {
            if rule.match_config.ip.src_ip != "any" || rule.match_config.ip.dst_ip != "any" {
                return false;
            }
        }
    }

    // 3. Check class or transport protocol
    let mut matched = false;

    // Check by class
    match rule.class.as_str() {
        "arp" => {
            if let NetworkLayer::Arp(_) = &pkt.network {
                matched = true;
            }
        }
        "eapol" => {
            if let AppLayer::Eapol(_) = &pkt.app {
                matched = true;
            }
        }
        "tcp" => {
            if let TransportLayer::Tcp { .. } = &pkt.transport {
                matched = true;
            }
        }
        "udp" => {
            if let TransportLayer::Udp { .. } = &pkt.transport {
                matched = true;
            }
        }
        _ => {}
    }

    // Check transport protocol if not matched by class
    if !matched {
        for proto in &rule.match_config.transport.protocol {
            match proto.to_lowercase().as_str() {
                "arp" => {
                    if let NetworkLayer::Arp(_) = &pkt.network {
                        matched = true;
                        break;
                    }
                }
                "eapol" => {
                    if let AppLayer::Eapol(_) = &pkt.app {
                        matched = true;
                        break;
                    }
                }
                "tcp" => {
                    if let TransportLayer::Tcp { .. } = &pkt.transport {
                        matched = true;
                        break;
                    }
                }
                "udp" => {
                    if let TransportLayer::Udp { .. } = &pkt.transport {
                        matched = true;
                        break;
                    }
                }
                "http" | "https" | "ssh" | "rdp" | "smb" | "ftp" => {
                    if let TransportLayer::Tcp { src_port, dst_port, .. } = &pkt.transport {
                        let is_proto_port = match proto.to_lowercase().as_str() {
                            "http" => *src_port == 80 || *src_port == 8080 || *src_port == 8081 || *dst_port == 80 || *dst_port == 8080 || *dst_port == 8081,
                            "https" => *src_port == 443 || *dst_port == 443,
                            "ssh" => *src_port == 22 || *dst_port == 22,
                            "rdp" => *src_port == 3389 || *dst_port == 3389,
                            "smb" => *src_port == 445 || *dst_port == 445,
                            "ftp" => *src_port == 20 || *src_port == 21 || *dst_port == 20 || *dst_port == 21,
                            _ => false,
                        };
                        if is_proto_port {
                            matched = true;
                            break;
                        }
                    }
                }
                "any" => {
                    matched = true;
                    break;
                }
                _ => {}
            }
        }
    }

    if !matched {
        return false;
    }

    // 4. Check specific source and destination ports
    if let TransportLayer::Tcp { src_port, dst_port, .. } | TransportLayer::Udp { src_port, dst_port, .. } = &pkt.transport {
        if !port_matches(&rule.match_config.transport.src_port, *src_port) {
            return false;
        }
        if !port_matches(&rule.match_config.transport.dst_port, *dst_port) {
            return false;
        }
    }

    true
}

fn port_matches(val: &serde_json::Value, actual_port: u16) -> bool {
    match val {
        serde_json::Value::String(s) => s == "any" || s.parse::<u16>().map(|p| p == actual_port).unwrap_or(false),
        serde_json::Value::Number(n) => n.as_u64().map(|p| p == actual_port as u64).unwrap_or(false),
        _ => false,
    }
}
