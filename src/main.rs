use chrono::Local;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc as tokio_mpsc;

use network_ids::engine::StatefulDetectionEngine;
use network_ids::flow_parser;
use network_ids::flow_table::{Packet as FlowPacket, SharedState};
use network_ids::pcap_logger;
use network_ids::{capture, locality, parser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut interface_name = None;
    let mut forward_ip = None;
    let mut forward_port = None;
    let mut log_file_path = Some("nids.log");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--interface" | "-i" => {
                if i + 1 < args.len() {
                    interface_name = Some(args[i + 1].as_str());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--ip" | "--host" | "-ip" | "-host" => {
                if i + 1 < args.len() {
                    forward_ip = Some(args[i + 1].as_str());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--port" | "-port" | "-p" => {
                if i + 1 < args.len() {
                    forward_port = Some(args[i + 1].as_str());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--log" | "-l" | "--output" | "-o" => {
                if i + 1 < args.len() {
                    let val = args[i + 1].as_str();
                    if val == "none" || val == "null" {
                        log_file_path = None;
                    } else {
                        log_file_path = Some(val);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    let logger = match Logger::new(log_file_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[Error] Failed to open log file: {}", e);
            return Err(e.into());
        }
    };

    let mut target_addr = None;
    if let Some(ip) = forward_ip {
        if ip.contains(':') {
            target_addr = Some(ip.to_string());
        } else if let Some(port) = forward_port {
            target_addr = Some(format!("{}:{}", ip, port));
        } else {
            logger.log_err("[Warning] No port specified. Defaulting to 9999.");
            target_addr = Some(format!("{}:9999", ip));
        }
    }

    let (tx_alerts, rx_alerts) = std_mpsc::channel();
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();

    let link_type = detect_link_type(interface_name.as_deref());
    let iface = interface_name.map(|s| s.to_string());

    // 1. Initialize Tokio Shared State for Flow Table & Memory Management
    let shared_flow_state = Arc::new(SharedState::new(10_000));
    let (tx_packets, mut rx_packets) = tokio_mpsc::channel::<(Vec<u8>, Instant)>(10_000);

    // 2. Launch Background Tokio Task: Periodic Cleanup Task (Runs every 10 seconds)
    let cleanup_state = shared_flow_state.clone();
    let logger_cleanup = logger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let removed = cleanup_state.cleanup_inactive_flows();
            if removed > 0 {
                logger_cleanup.log(&format!(
                    "[Flow Table Cleanup] Removed {} inactive flow(s) (inactive >60s).",
                    removed
                ));
            }
        }
    });

    // 3. Launch Background Tokio Task: Packet Processor Task
    let processor_state = shared_flow_state.clone();
    let target_log_path = log_file_path.unwrap_or("nids.log").to_string();
    let logger_processor = logger.clone();

    tokio::spawn(async move {
        while let Some((raw_bytes, ts)) = rx_packets.recv().await {
            // Core Requirement 1: Extract 4-tuple flow key with error handling
            match flow_parser::parse_flow_key(&raw_bytes) {
                Ok(flow_key) => {
                    let flow_pkt = FlowPacket {
                        timestamp: ts,
                        data: raw_bytes,
                    };

                    // Core Requirement 2, 3, 4, 6: Flow Segregation, Circular Buffer, LRU Eviction
                    let (burst_detected, burst_packets) =
                        processor_state.process_packet(flow_key, flow_pkt);

                    // Core Requirement 5: Burst Detection Action
                    if burst_detected {
                        if let Some(pkts) = burst_packets {
                            logger_processor.log(&format!(
                                "[BURST DETECTED] Flow ({}.{}.{}.{}:{} -> {}.{}.{}.{}:{}) triggered 100 packets in <60s burst alert!",
                                (flow_key.0 >> 24) & 0xFF,
                                (flow_key.0 >> 16) & 0xFF,
                                (flow_key.0 >> 8) & 0xFF,
                                flow_key.0 & 0xFF,
                                flow_key.1,
                                (flow_key.2 >> 24) & 0xFF,
                                (flow_key.2 >> 16) & 0xFF,
                                (flow_key.2 >> 8) & 0xFF,
                                flow_key.2 & 0xFF,
                                flow_key.3
                            ));
                            let log_file = target_log_path.clone();
                            tokio::spawn(async move {
                                pcap_logger::log_burst(log_file, flow_key, pkts).await;
                            });
                        }
                    }
                }
                Err(_err) => {
                    // Gracefully skip non-IPv4 / non-TCP/UDP / malformed packets
                }
            }
        }
    });

    // 4. Raw packet capture thread with locality buffering
    let tx_alerts_capture = tx_alerts.clone();
    let logger_capture = logger.clone();

    thread::spawn(move || {
        let default_link = link_type;

        let mut capture_engine = match capture::MmapCapture::new(iface.as_deref()) {
            Ok(cap) => cap,
            Err(e) => {
                logger_capture.log_err(&format!(
                    "[Warning] Raw socket capture failed initialization: {}\n[Time] {}.",
                    e,
                    Local::now()
                ));
                logger_capture.log_err(
                    "[Info] Running in simulation fallback mode. Real traffic will not be monitored."
                );
                while is_running_clone.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(200));
                }
                return;
            }
        };

        let mut locality_buffer = Box::new(locality::LocalityBuffer::new());
        let mut detection_engine =
            StatefulDetectionEngine::new(iface.clone().unwrap_or_else(|| "wlan0".to_string()));

        while is_running_clone.load(Ordering::Relaxed) {
            if let Some(block_guard) = capture_engine.next_block(Duration::from_millis(50)) {
                locality_buffer.clear();

                for raw_pkt in block_guard.packets() {
                    let parsed = parser::parse_packet(raw_pkt.data, default_link, None);

                    let mut port_key = 0u16;
                    match &parsed.transport {
                        parser::TransportLayer::Tcp(tcp) => {
                            port_key = std::cmp::min(tcp.src_port, tcp.dst_port);
                        }
                        parser::TransportLayer::Udp(udp) => {
                            port_key = std::cmp::min(udp.src_port, udp.dst_port);
                        }
                        _ => {}
                    }

                    let _ = locality_buffer.add_packet(
                        raw_pkt.data.as_ptr(),
                        raw_pkt.data.len() as u32,
                        raw_pkt.sec,
                        raw_pkt.nsec,
                        raw_pkt.block_idx as u32,
                        port_key,
                    );
                }

                locality_buffer.group_packets();

                for i in 0..locality_buffer.active_count {
                    let port = locality_buffer.active_buckets[i];
                    let slice = locality_buffer.get_bucket_slice(port);
                    for pkt_ref in slice {
                        let raw_slice = unsafe {
                            slice::from_raw_parts(pkt_ref.data_ptr, pkt_ref.len as usize)
                        };

                        // Send packet bytes to Tokio flow processing task with non-blocking backpressure
                        let _ = tx_packets.try_send((raw_slice.to_vec(), Instant::now()));

                        // Also run detection engine rules
                        let parsed = parser::parse_packet(raw_slice, default_link, None);
                        let timestamp =
                            pkt_ref.sec as f64 + (pkt_ref.nsec as f64 / 1_000_000_000.0);
                        let generated_alerts = detection_engine.process_packet(&parsed, timestamp);

                        for msg in generated_alerts {
                            let _ = tx_alerts_capture.send(msg);
                        }
                    }
                }
            }
        }
    });

    let mut forwarder = target_addr.map(|addr| AlertForwarder::new(addr));

    let start_msg = format!(
        "[Info] Network Intrusion Detection System & Flow Table Processor started at {}.\nMonitoring traffic...",
        Local::now()
    );
    logger.log(&start_msg);

    // Spawn alert handling loop on blocking task or async loop
    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = rx_alerts.recv() {
            if let Ok(json) = serde_json::to_string_pretty(&msg) {
                logger.log(&json);
                if let Some(ref mut f) = forwarder {
                    f.send(&json);
                }
            }
        }
    }).await.ok();

    Ok(())
}

fn detect_link_type(interface: Option<&str>) -> parser::LinkType {
    let Some(iface) = interface else {
        return parser::LinkType::Ethernet;
    };
    if let Ok(type_str) = std::fs::read_to_string(format!("/sys/class/net/{}/type", iface)) {
        if let Ok(type_val) = type_str.trim().parse::<u16>() {
            match type_val {
                1 => return parser::LinkType::Ethernet,
                801 => return parser::LinkType::Wifi80211,
                803 => return parser::LinkType::RadiotapWifi,
                _ => {}
            }
        }
    }
    parser::LinkType::Unknown
}

struct AlertForwarder {
    tcp_stream: Option<std::net::TcpStream>,
    udp_socket: Option<std::net::UdpSocket>,
    target_addr: String,
}

impl AlertForwarder {
    fn new(target_addr: String) -> Self {
        let tcp_stream = std::net::TcpStream::connect(&target_addr).ok();
        let udp_socket = if tcp_stream.is_none() {
            std::net::UdpSocket::bind("0.0.0.0:0").ok()
        } else {
            None
        };
        AlertForwarder {
            tcp_stream,
            udp_socket,
            target_addr,
        }
    }

    fn send(&mut self, data: &str) {
        if let Some(ref mut stream) = self.tcp_stream {
            if stream.write_all(data.as_bytes()).is_ok() {
                let _ = stream.write_all(b"\n");
                let _ = stream.flush();
                return;
            }
            self.tcp_stream = None;
            self.udp_socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
        }

        if let Some(ref socket) = self.udp_socket {
            let _ = socket.send_to(data.as_bytes(), &self.target_addr);
        }
    }
}

fn print_help() {
    println!("Network Intrusion Detection System (NIDS) & Tokio Flow Table Engine");
    println!();
    println!("Usage:");
    println!("  Network_IDS [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -i, --interface <name>   Specify network interface to monitor (e.g. wlan0, eth0)");
    println!("  -ip, --ip <ip[:port]>    Specify destination host/IP for alert forwarding");
    println!("  -p, --port <port>        Specify destination port number (default: 9999)");
    println!("  -l, -o, --log <path>     Specify log file path (default: nids.log)");
    println!("  -h, --help               Display help manual");
}

#[derive(Clone)]
struct Logger {
    file: Option<Arc<Mutex<File>>>,
}

impl Logger {
    fn new(path: Option<&str>) -> Result<Self, std::io::Error> {
        let file = if let Some(p) = path {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)?;
            Some(Arc::new(Mutex::new(f)))
        } else {
            None
        };
        Ok(Logger { file })
    }

    fn log(&self, msg: &str) {
        println!("{}", msg);
        if let Some(ref file_mutex) = self.file {
            if let Ok(mut file) = file_mutex.lock() {
                let _ = writeln!(file, "{}", msg);
                let _ = file.flush();
            }
        }
    }

    fn log_err(&self, msg: &str) {
        eprintln!("{}", msg);
        if let Some(ref file_mutex) = self.file {
            if let Ok(mut file) = file_mutex.lock() {
                let _ = writeln!(file, "{}", msg);
                let _ = file.flush();
            }
        }
    }
}
