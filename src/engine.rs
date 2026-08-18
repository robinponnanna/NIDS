use crate::alert::*;
use crate::parser::{AppLayer, NetworkLayer, ParsedPacket, TransportLayer};
use chrono::Local;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;

// =============================================================================
// TCP Flag constants (TcpInfo.flags bit positions)
// flags layout [8:0] = NS|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
// =============================================================================
const TCP_FLAG_FIN: u16 = 0x001;
const TCP_FLAG_SYN: u16 = 0x002;
const TCP_FLAG_RST: u16 = 0x004;
const TCP_FLAG_ACK: u16 = 0x010;

// =============================================================================
// TCP Connection State Tracking
// =============================================================================

/// State of a tracked TCP connection.
#[derive(Debug, Clone, PartialEq)]
pub enum TcpConnState {
    /// SYN seen, waiting for SYN-ACK.
    New,
    /// SYN-ACK (or data ACK) seen — full handshake observed.
    Established,
    /// FIN or RST seen — connection is closing.
    Closing,
}

/// 4-tuple uniquely identifying one TCP connection direction.
/// (src_ip_string, src_port, dst_ip_string, dst_port)
type ConnKey = (String, u16, String, u16);

// =============================================================================
// Engine State Structs
// =============================================================================

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

    // Traffic monitoring states
    pub ip_address: Option<std::net::IpAddr>,
    pub tcp_scans: HashMap<u16, f64>,    // port -> timestamp
    pub udp_scans: HashMap<u16, f64>,    // port -> timestamp
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

// =============================================================================
// Rule Config Structs (deserialized from rules.json)
// =============================================================================

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
    /// Accepted values: "any" | "new" | "established"
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitConfig {
    pub per: String,
    pub connections: u32,
    /// Interval in seconds (e.g. 3.0 = 3 seconds)
    pub interval: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BehaviourConfig {
    pub per_src: Option<PerSrcConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PerSrcConfig {
    /// Max new-connection SYN packets per second from a single source.
    pub max_requests_per_second: Option<u32>,
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

// =============================================================================
// Detection Engine
// =============================================================================

pub struct StatefulDetectionEngine {
    pub alert_counter: u64,
    pub access_points: HashMap<[u8; 6], AccessPoint>,
    pub clients: HashMap<[u8; 6], ClientState>,
    pub sessions: HashMap<[u8; 6], SessionState>,

    // Vehicle configurations
    pub vehicle_hotspot_enabled: bool,
    pub hotspot_ssid: String,
    pub hotspot_bssid: [u8; 6],
    pub hotspot_channel: u8,
    pub carplay_active: bool,

    // Time tracking for cleanup
    pub last_cleanup_time: f64,
    pub iface: String,

    /// IP addresses of the monitored interface (used for "self" matching and direction).
    pub self_ips: Vec<IpAddr>,

    // Loaded rules from rules.json
    pub rules: Vec<EvaluatedRule>,

    /// TCP connection state table: ConnKey -> (state, last_seen_timestamp)
    pub tcp_conn_table: HashMap<ConnKey, (TcpConnState, f64)>,

    /// Per-rule, per-tracking-key packet rate tracker (all matching packets).
    /// rule_id -> tracking_key -> Vec<timestamps>
    /// Used for max_requests_per_second evaluation.
    pub rule_rate_tracker: HashMap<u32, HashMap<String, Vec<f64>>>,

    /// Per-rule, per-tracking-key connection rate tracker (TCP SYN packets only).
    /// rule_id -> tracking_key -> Vec<syn_timestamps>
    /// Used for max_conn_rate evaluation.
    pub conn_rate_tracker: HashMap<u32, HashMap<String, Vec<f64>>>,
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
            let event_id: &'static str = Box::leak(format!("RULE-{}", r.id).into_boxed_str());
            let event_name: &'static str = Box::leak(r.message.clone().into_boxed_str());
            let severity = match r.severity {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                3 => Severity::Low,
                _ => Severity::Info,
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

        let self_ips = resolve_iface_ips(&iface);
        if self_ips.is_empty() {
            eprintln!("[Warning] Could not resolve any IP for interface '{}'. Direction matching and 'self' keyword will not work.", iface);
        } else {
            eprintln!("[Info] Sensor IPs on {}: {:?}", iface, self_ips);
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
            self_ips,
            iface,
            rules,
            tcp_conn_table: HashMap::new(),
            rule_rate_tracker: HashMap::new(),
            conn_rate_tracker: HashMap::new(),
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

        // Prune stale entries in the per-rule packet rate tracker
        for per_key_map in self.rule_rate_tracker.values_mut() {
            for timestamps in per_key_map.values_mut() {
                timestamps.retain(|&t| now - t < window);
            }
            per_key_map.retain(|_, v| !v.is_empty());
        }

        // Prune stale entries in the per-rule connection rate tracker
        for per_key_map in self.conn_rate_tracker.values_mut() {
            for timestamps in per_key_map.values_mut() {
                timestamps.retain(|&t| now - t < window);
            }
            per_key_map.retain(|_, v| !v.is_empty());
        }

        // Prune TCP connection table: remove Closing entries and stale connections
        self.tcp_conn_table
            .retain(|_, (state, last_seen)| {
                *state != TcpConnState::Closing && now - *last_seen < 300.0
            });

        // Expire inactive clients, APs, and sessions
        self.clients
            .retain(|_, client| now - client.last_seen < 300.0);
        self.access_points
            .retain(|_, ap| now - ap.last_seen < 300.0);
        self.sessions
            .retain(|_, sess| now - sess.last_step_time < 300.0);
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
                if mgmt.subtype == 8 {
                    // Beacon frame
                    let ssid = mgmt.ssid.clone().unwrap_or_default();
                    let chan = mgmt.channel.unwrap_or(0);
                    let sec = if mgmt.rsn_info.is_some() {
                        "WPA2/WPA3"
                    } else {
                        "Open"
                    };

                    let ap = self
                        .access_points
                        .entry(bssid)
                        .or_insert_with(|| AccessPoint {
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
            let client = self
                .clients
                .entry(client_mac)
                .or_insert_with(|| ClientState::new(client_mac, rssi, seq, now));
            client.last_seen = now;
            client.last_rssi = rssi;
            client.last_seq_num = seq;

            if let NetworkLayer::Ipv4(ip) = &pkt.network {
                client.ip_address = Some(std::net::IpAddr::V4(ip.src_ip));
            } else if let NetworkLayer::Ipv6(ip) = &pkt.network {
                client.ip_address = Some(std::net::IpAddr::V6(ip.src_ip));
            }
        }

        // 4. Update TCP connection state table BEFORE rule evaluation so that
        //    flow.state checks see the correct state for the current packet.
        if let TransportLayer::Tcp(tcp) = &pkt.transport {
            let src_ip = resolve_src_ip(pkt);
            let dst_ip = resolve_dst_ip(pkt);
            let key: ConnKey = (src_ip.clone(), tcp.src_port, dst_ip.clone(), tcp.dst_port);
            let rev_key: ConnKey = (dst_ip, tcp.dst_port, src_ip, tcp.src_port);

            let is_syn = (tcp.flags & TCP_FLAG_SYN) != 0;
            let is_ack = (tcp.flags & TCP_FLAG_ACK) != 0;
            let is_fin = (tcp.flags & TCP_FLAG_FIN) != 0;
            let is_rst = (tcp.flags & TCP_FLAG_RST) != 0;

            if is_syn && !is_ack {
                // Fresh SYN — new connection attempt
                self.tcp_conn_table.insert(key, (TcpConnState::New, now));
            } else if is_syn && is_ack {
                // SYN-ACK — promote the reverse key to Established
                self.tcp_conn_table.insert(rev_key.clone(), (TcpConnState::Established, now));
                self.tcp_conn_table.insert(key, (TcpConnState::Established, now));
            } else if is_fin || is_rst {
                // Teardown
                if let Some(entry) = self.tcp_conn_table.get_mut(&key) {
                    entry.0 = TcpConnState::Closing;
                    entry.1 = now;
                }
            } else {
                // Data packet — if connection exists, keep it alive
                if let Some(entry) = self.tcp_conn_table.get_mut(&key) {
                    entry.1 = now;
                }
            }
        }

        // --- EVALUATE DYNAMIC RULES FROM rules.json ---
        // Rules are evaluated for every packet. Rate tracking is split:
        //   rule_rate_tracker  — counts every matching packet (for max_requests_per_second)
        //   conn_rate_tracker  — counts only TCP SYN packets (for max_conn_rate)
        // The grouping key for both is resolved from the rule's `per` field.
        let self_ips = self.self_ips.clone();
        for rule in &self.rules {
            if matches_rule(rule, pkt, &self.iface, &self_ips, &self.tcp_conn_table) {
                // Resolve tracking key from rule's `per` field
                let tracking_key = resolve_tracking_key(rule, pkt);

                // ── Packet rate tracker (every matching packet) ──────────────
                let pkt_timestamps = self
                    .rule_rate_tracker
                    .entry(rule.id)
                    .or_default()
                    .entry(tracking_key.clone())
                    .or_default();
                pkt_timestamps.push(now);

                // ── Connection rate tracker (TCP SYN only) ────────────────────
                let is_new_tcp_conn = if let TransportLayer::Tcp(tcp) = &pkt.transport {
                    (tcp.flags & TCP_FLAG_SYN) != 0 && (tcp.flags & TCP_FLAG_ACK) == 0
                } else {
                    // For non-TCP protocols (ARP, EAPOL, UDP) every matching
                    // packet is treated as a "new connection" for rate purposes.
                    true
                };

                if is_new_tcp_conn {
                    let conn_timestamps = self
                        .conn_rate_tracker
                        .entry(rule.id)
                        .or_default()
                        .entry(tracking_key.clone())
                        .or_default();
                    conn_timestamps.push(now);
                }

                let mut triggered = false;
                let mut count_to_report = 0usize;

                // Check max_requests_per_second (packet rate, 1-second window)
                if let Some(per_src) = &rule.behaviour.per_src {
                    if let Some(max_rps) = per_src.max_requests_per_second {
                        let pkt_ts = self
                            .rule_rate_tracker
                            .get(&rule.id)
                            .and_then(|m| m.get(&tracking_key));
                        if let Some(ts) = pkt_ts {
                            let count = ts.iter().filter(|&&t| now - t < 1.0).count();
                            if count >= max_rps as usize {
                                triggered = true;
                                count_to_report = count;
                            }
                        }
                    }
                }

                // Check max_conn_rate (new-connection rate, interval in seconds)
                if !triggered {
                    if let Some(limits) = &rule.context.limits {
                        if let Some(conn_rate) = limits.get("max_conn_rate") {
                            let conn_ts = self
                                .conn_rate_tracker
                                .get(&rule.id)
                                .and_then(|m| m.get(&tracking_key));
                            if let Some(ts) = conn_ts {
                                let count = ts
                                    .iter()
                                    .filter(|&&t| now - t < conn_rate.interval)
                                    .count();
                                if count >= conn_rate.connections as usize {
                                    triggered = true;
                                    count_to_report = count;
                                }
                            }
                        }
                    }
                }

                // Prune old timestamps to bound memory (use 60 s as safe upper bound)
                if let Some(ts) = self
                    .rule_rate_tracker
                    .get_mut(&rule.id)
                    .and_then(|m| m.get_mut(&tracking_key))
                {
                    ts.retain(|&t| now - t < 60.0);
                }
                if let Some(ts) = self
                    .conn_rate_tracker
                    .get_mut(&rule.id)
                    .and_then(|m| m.get_mut(&tracking_key))
                {
                    ts.retain(|&t| now - t < 60.0);
                }

                if triggered {
                    // Reset the connection tracker for this source so it can re-arm
                    if let Some(m) = self.conn_rate_tracker.get_mut(&rule.id) {
                        m.remove(&tracking_key);
                    }
                    if let Some(m) = self.rule_rate_tracker.get_mut(&rule.id) {
                        m.remove(&tracking_key);
                    }

                    pending.push(PendingAlert {
                        event_id: rule.event_id,
                        event_name: rule.event_name,
                        severity: rule.severity.clone(),
                        payload: EventPayload::ProtocolConformantFlood(ProtocolConformantFlood {
                            packet_signature_hash: format!("rule_{}", rule.id),
                            signature_description: format!(
                                "Rule: '{}' (id: {}) triggered for {}. Threshold exceeded.",
                                rule.event_name, rule.id, tracking_key
                            ),
                            sender_list: vec![SenderRate {
                                sender_id: tracking_key.clone(),
                                pkt_rate_per_sender: count_to_report as u32,
                            }],
                        }),
                    });
                }
            }
        }

        // 5. Create actual IdsmMessage objects once all state borrows are released
        for p in pending {
            alerts.push(self.create_message(p.event_id, p.event_name, p.severity, p.payload));
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
            sensor_cert_id: "-----".to_string(),
            signature: Vec::new(),
            event: SensorEvent {
                event_id,
                event_name,
                severity,
                timestamp,
                vehicle_id_hash: "AA00BB1234".to_string(),
                iface: self.iface.clone(),
                payload,
            },
        }
    }
}

// =============================================================================
// Helper: resolve sensor interface IPs via libc getifaddrs
// =============================================================================

/// Returns all unicast IP addresses assigned to the given network interface.
/// Falls back to an empty Vec if the interface is not found or has no IPs.
fn resolve_iface_ips(iface: &str) -> Vec<IpAddr> {
    use std::ffi::CStr;

    let mut result = Vec::new();

    // SAFETY: getifaddrs / freeifaddrs are standard POSIX calls.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return result;
        }

        let mut ifa = ifap;
        while !ifa.is_null() {
            let name = CStr::from_ptr((*ifa).ifa_name).to_string_lossy();
            if name == iface {
                let addr_ptr = (*ifa).ifa_addr;
                if !addr_ptr.is_null() {
                    match (*addr_ptr).sa_family as i32 {
                        libc::AF_INET => {
                            let sin = addr_ptr as *const libc::sockaddr_in;
                            let raw = (*sin).sin_addr.s_addr.to_ne_bytes();
                            result.push(IpAddr::V4(std::net::Ipv4Addr::from(raw)));
                        }
                        libc::AF_INET6 => {
                            let sin6 = addr_ptr as *const libc::sockaddr_in6;
                            let raw = (*sin6).sin6_addr.s6_addr;
                            result.push(IpAddr::V6(std::net::Ipv6Addr::from(raw)));
                        }
                        _ => {}
                    }
                }
            }
            ifa = (*ifa).ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    result
}

// =============================================================================
// Helpers: resolve tracking key and packet IPs
// =============================================================================

fn resolve_tracking_key(rule: &EvaluatedRule, pkt: &ParsedPacket) -> String {
    if let Some(limits) = &rule.context.limits {
        if let Some(conn_rate) = limits.get("max_conn_rate") {
            return match conn_rate.per.as_str() {
                "src_ip" => resolve_src_ip(pkt),
                "dst_ip" => resolve_dst_ip(pkt),
                _ => resolve_src_ip(pkt),
            };
        }
    }
    resolve_src_ip(pkt)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Resolve the source IP (or MAC fallback) from a parsed packet.
fn resolve_src_ip(pkt: &ParsedPacket) -> String {
    match &pkt.network {
        NetworkLayer::Ipv4(ip) => ip.src_ip.to_string(),
        NetworkLayer::Ipv6(ip) => ip.src_ip.to_string(),
        NetworkLayer::Arp(arp) => arp.sender_ip.to_string(),
        NetworkLayer::None => format_mac(pkt.src_mac),
    }
}

/// Resolve the destination IP (or MAC fallback) from a parsed packet.
fn resolve_dst_ip(pkt: &ParsedPacket) -> String {
    match &pkt.network {
        NetworkLayer::Ipv4(ip) => ip.dst_ip.to_string(),
        NetworkLayer::Ipv6(ip) => ip.dst_ip.to_string(),
        NetworkLayer::Arp(arp) => arp.target_ip.to_string(),
        NetworkLayer::None => format_mac(pkt.dst_mac),
    }
}

/// Check whether a packet's IP (src or dst) matches a rule IP field value.
/// Handles "any" (wildcard), "self" (sensor's own IPs), or a literal IP string.
fn ip_field_matches(field: &str, pkt_ip: &str, self_ips: &[IpAddr]) -> bool {
    match field {
        "any" => true,
        "self" => {
            let parsed: Option<IpAddr> = pkt_ip.parse().ok();
            parsed.map(|ip| self_ips.contains(&ip)).unwrap_or(false)
        }
        literal => literal == pkt_ip,
    }
}

// =============================================================================
// Rule Matching
// =============================================================================

fn matches_rule(
    rule: &EvaluatedRule,
    pkt: &ParsedPacket,
    iface: &str,
    self_ips: &[IpAddr],
    tcp_conn_table: &HashMap<ConnKey, (TcpConnState, f64)>,
) -> bool {
    // 1. Check scope/interface
    if !rule
        .scope
        .interfaces
        .iter()
        .any(|i| i == "any" || i == iface)
    {
        return false;
    }

    // 2. Check direction (ingress = packet destined TO self; egress = FROM self)
    let src_ip_str = resolve_src_ip(pkt);
    let dst_ip_str = resolve_dst_ip(pkt);

    match rule.match_config.direction.as_str() {
        "ingress" => {
            // Packet must be arriving at the sensor (dst is one of self_ips)
            let dst_parsed: Option<IpAddr> = dst_ip_str.parse().ok();
            if !dst_parsed.map(|ip| self_ips.contains(&ip)).unwrap_or(false) {
                return false;
            }
        }
        "egress" => {
            // Packet must be leaving from the sensor (src is one of self_ips)
            let src_parsed: Option<IpAddr> = src_ip_str.parse().ok();
            if !src_parsed.map(|ip| self_ips.contains(&ip)).unwrap_or(false) {
                return false;
            }
        }
        _ => {} // "any" or unrecognised — no direction filter
    }

    // 3. Check IP version & IPs (with "any" / "self" / literal support)
    match &pkt.network {
        NetworkLayer::Ipv4(ip) => {
            if !rule.match_config.ip.ip_version.contains(&4) {
                return false;
            }
            if !ip_field_matches(&rule.match_config.ip.src_ip, &ip.src_ip.to_string(), self_ips) {
                return false;
            }
            if !ip_field_matches(&rule.match_config.ip.dst_ip, &ip.dst_ip.to_string(), self_ips) {
                return false;
            }
        }
        NetworkLayer::Ipv6(ip) => {
            if !rule.match_config.ip.ip_version.contains(&6) {
                return false;
            }
            if !ip_field_matches(&rule.match_config.ip.src_ip, &ip.src_ip.to_string(), self_ips) {
                return false;
            }
            if !ip_field_matches(&rule.match_config.ip.dst_ip, &ip.dst_ip.to_string(), self_ips) {
                return false;
            }
        }
        NetworkLayer::Arp(arp) => {
            if !ip_field_matches(
                &rule.match_config.ip.src_ip,
                &arp.sender_ip.to_string(),
                self_ips,
            ) {
                return false;
            }
            if !ip_field_matches(
                &rule.match_config.ip.dst_ip,
                &arp.target_ip.to_string(),
                self_ips,
            ) {
                return false;
            }
        }
        NetworkLayer::None => {
            // No IP layer — only pass if both IP fields are "any"
            if rule.match_config.ip.src_ip != "any" || rule.match_config.ip.dst_ip != "any" {
                return false;
            }
        }
    }

    // 4. Check flow.state for TCP traffic
    match rule.context.flow.state.as_str() {
        "any" => {} // no state filter
        "new" => {
            // Packet must itself be a TCP SYN (no ACK)
            if let TransportLayer::Tcp(tcp) = &pkt.transport {
                if (tcp.flags & TCP_FLAG_SYN) == 0 || (tcp.flags & TCP_FLAG_ACK) != 0 {
                    return false;
                }
            } else {
                return false; // non-TCP cannot be "new"
            }
        }
        "established" => {
            // Connection must already be in Established state in the table
            if let TransportLayer::Tcp(tcp) = &pkt.transport {
                let key: ConnKey = (
                    src_ip_str.clone(),
                    tcp.src_port,
                    dst_ip_str.clone(),
                    tcp.dst_port,
                );
                match tcp_conn_table.get(&key) {
                    Some((TcpConnState::Established, _)) => {}
                    _ => return false,
                }
            } else {
                return false; // non-TCP cannot be "established"
            }
        }
        _ => {} // unknown state value — treat as "any"
    }

    // 5. Check class or transport protocol
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
            if let TransportLayer::Tcp(_) = &pkt.transport {
                matched = true;
            }
        }
        "udp" => {
            if let TransportLayer::Udp(_) = &pkt.transport {
                matched = true;
            }
        }
        _ => {}
    }

    // Check transport protocol list if not matched by class
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
                    if let TransportLayer::Tcp(_) = &pkt.transport {
                        matched = true;
                        break;
                    }
                }
                "udp" => {
                    if let TransportLayer::Udp(_) = &pkt.transport {
                        matched = true;
                        break;
                    }
                }
                "http" | "https" | "ssh" | "rdp" | "smb" | "ftp" => {
                    if let TransportLayer::Tcp(tcp) = &pkt.transport {
                        let is_proto_port = match proto.to_lowercase().as_str() {
                            "http" => {
                                tcp.src_port == 80
                                    || tcp.src_port == 8080
                                    || tcp.src_port == 8081
                                    || tcp.dst_port == 80
                                    || tcp.dst_port == 8080
                                    || tcp.dst_port == 8081
                            }
                            "https" => tcp.src_port == 443 || tcp.dst_port == 443,
                            "ssh" => tcp.src_port == 22 || tcp.dst_port == 22,
                            "rdp" => tcp.src_port == 3389 || tcp.dst_port == 3389,
                            "smb" => tcp.src_port == 445 || tcp.dst_port == 445,
                            "ftp" => {
                                tcp.src_port == 20
                                    || tcp.src_port == 21
                                    || tcp.dst_port == 20
                                    || tcp.dst_port == 21
                            }
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

    // 6. Check specific source and destination ports
    match &pkt.transport {
        TransportLayer::Tcp(tcp) => {
            if !port_matches(&rule.match_config.transport.src_port, tcp.src_port) {
                return false;
            }
            if !port_matches(&rule.match_config.transport.dst_port, tcp.dst_port) {
                return false;
            }
        }
        TransportLayer::Udp(udp) => {
            if !port_matches(&rule.match_config.transport.src_port, udp.src_port) {
                return false;
            }
            if !port_matches(&rule.match_config.transport.dst_port, udp.dst_port) {
                return false;
            }
        }
        _ => {}
    }

    true
}

fn port_matches(val: &serde_json::Value, actual_port: u16) -> bool {
    match val {
        serde_json::Value::String(s) => {
            s == "any" || s.parse::<u16>().map(|p| p == actual_port).unwrap_or(false)
        }
        serde_json::Value::Number(n) => {
            n.as_u64().map(|p| p == actual_port as u64).unwrap_or(false)
        }
        _ => false,
    }
}
