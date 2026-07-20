use chrono::Local;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use network_ids::engine::StatefulDetectionEngine;
use network_ids::{capture, locality, parser};

fn main() -> Result<(), Box<dyn Error>> {
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
            return Err(Box::new(e));
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

    let (tx_alerts, rx_alerts) = mpsc::channel();
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();

    let link_type = detect_link_type(interface_name.as_deref());

    // 1. Launch raw packet capture thread
    let iface = interface_name.map(|s| s.to_string());
    let tx_alerts_capture = tx_alerts.clone();
    let logger_capture = logger.clone();

    thread::spawn(move || {
        let default_link = link_type;

        // Attempt to create raw socket. If it fails (due to permissions or platform), log and wait
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
                // Fall loop: park the thread
                while is_running_clone.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(200));
                }
                return;
            }
        };

        // Preallocate locality buffer and detection engine
        let mut locality_buffer = Box::new(locality::LocalityBuffer::new());
        let mut detection_engine =
            StatefulDetectionEngine::new(iface.clone().unwrap_or_else(|| "wlan0".to_string()));

        while is_running_clone.load(Ordering::Relaxed) {
            // Poll for next mmap retired block
            if let Some(block_guard) = capture_engine.next_block(Duration::from_millis(50)) {
                locality_buffer.clear();

                // 1. Zero-copy extract packets from the block, pre-parse ports, and add to locality buffer
                for raw_pkt in block_guard.packets() {
                    let parsed = parser::parse_packet(raw_pkt.data, default_link);

                    let mut port_key = 0u16;
                    match &parsed.transport {
                        parser::TransportLayer::Tcp {
                            src_port, dst_port, ..
                        } => {
                            port_key = std::cmp::min(*src_port, *dst_port);
                        }
                        parser::TransportLayer::Udp {
                            src_port, dst_port, ..
                        } => {
                            port_key = std::cmp::min(*src_port, *dst_port);
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

                // 2. Perform locality buffering counting sort grouping (zero copy, contiguous layout)
                locality_buffer.group_packets();

                // 3. Process grouped packets through the stateful engine
                for i in 0..locality_buffer.active_count {
                    let port = locality_buffer.active_buckets[i];
                    let slice = locality_buffer.get_bucket_slice(port);
                    for pkt_ref in slice {
                        // Re-slice safely from mmap reference pointer
                        let raw_slice = unsafe {
                            slice::from_raw_parts(pkt_ref.data_ptr, pkt_ref.len as usize)
                        };
                        let parsed = parser::parse_packet(raw_slice, default_link);

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
        "[Info] Network Intrusion Detection System started at {}.\nMonitoring traffic... ",
        Local::now()
    );
    logger.log(&start_msg);
    // if let Some(ref mut f) = forwarder {
    //     f.send(start_msg);
    // }

    while let Ok(msg) = rx_alerts.recv() {
        if let Ok(json) = serde_json::to_string_pretty(&msg) {
            logger.log(&json);
            if let Some(ref mut f) = forwarder {
                f.send(&json);
            }
        }
    }

    Ok(())
}

fn detect_link_type(interface: Option<&str>) -> parser::LinkType {
    let Some(iface) = interface else {
        return parser::LinkType::Ethernet;
    };
    // Query /sys/class/net/<interface>/type
    if let Ok(type_str) = std::fs::read_to_string(format!("/sys/class/net/{}/type", iface)) {
        if let Ok(type_val) = type_str.trim().parse::<u16>() {
            match type_val {
                1 => return parser::LinkType::Ethernet,       // ARPHRD_ETHER
                801 => return parser::LinkType::Wifi80211,    // ARPHRD_IEEE80211
                803 => return parser::LinkType::RadiotapWifi, // ARPHRD_IEEE80211_RADIOTAP
                _ => {}
            }
        }
    }
    // Fallback to auto-detecting per-packet using Unknown
    parser::LinkType::Unknown
}

struct AlertForwarder {
    tcp_stream: Option<std::net::TcpStream>,
    udp_socket: Option<std::net::UdpSocket>,
    target_addr: String,
}

impl AlertForwarder {
    fn new(target_addr: String) -> Self {
        // Try TCP connection first, fallback to UDP
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
        use std::io::Write;
        if let Some(ref mut stream) = self.tcp_stream {
            if stream.write_all(data.as_bytes()).is_ok() {
                let _ = stream.write_all(b"\n");
                let _ = stream.flush();
                return;
            }
            // TCP failed, try to reconnect or fallback to UDP
            self.tcp_stream = None;
            self.udp_socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
        }

        if let Some(ref socket) = self.udp_socket {
            let _ = socket.send_to(data.as_bytes(), &self.target_addr);
        }
    }
}

fn print_help() {
    println!("Network Intrusion Detection System (NIDS) - Help Manual");
    println!();
    println!("Usage:");
    println!("  Network_IDS [OPTIONS]");
    println!();
    println!("Options:");
    println!(
        "  -i, --interface <name>   Specify the network interface to monitor (e.g. wlan0, eth0)"
    );
    println!("                           Default: wlan0");
    println!(
        "  -ip, --ip,               Specify the destination host/IP to forward monitored and filtered data"
    );
    println!("  -host, --host <ip[:port]> Example: --ip 192.168.1.50 or --ip 127.0.0.1:8080");
    println!(
        "  -p, -port, --port <port> Specify the destination port number (if not provided in host/IP)"
    );
    println!("                           Default: 9999");
    println!("  -l, --log,");
    println!(
        "  -o, --output <path>      Specify the log file path to write output (or 'none' to disable)"
    );
    println!("                           Default: nids.log");
    println!("  -h, --help               Display this help manual and exit");
    println!();
    println!("Examples:");
    println!("  Network_IDS -i eth0");
    println!("  Network_IDS --ip 127.0.0.1 --port 9090");
    println!("  Network_IDS -i wlan0 -ip 192.168.1.10:9999");
    println!("  Network_IDS --log output.log");
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
