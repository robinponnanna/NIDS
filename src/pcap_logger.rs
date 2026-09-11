use crate::flow_table::{FlowKey, Packet};
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;

/// Log burst detection event and packet data directly into the specified single log file (e.g. nids.log).
pub async fn log_burst(log_path: String, key: FlowKey, packets: Vec<Packet>) {
    tokio::task::spawn_blocking(move || {
        let (src_ip, src_port, dst_ip, dst_port) = key;
        let src_str = Ipv4Addr::from(src_ip);
        let dst_str = Ipv4Addr::from(dst_ip);
        let timestamp_str = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

        let header = format!(
            "\n========================================================================\n\
             [BURST DETECTED] Time: {}\n\
             Flow 4-Tuple: {}:{} -> {}:{}\n\
             Packet Count: {} packets (<60 seconds duration)\n\
             ========================================================================\n",
            timestamp_str, src_str, src_port, dst_str, dst_port, packets.len()
        );

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = file.write_all(header.as_bytes());

            for (idx, pkt) in packets.iter().enumerate() {
                let entry = format!(
                    "  [Pkt #{:03}] Len: {} bytes | Data (hex head): {}\n",
                    idx + 1,
                    pkt.data.len(),
                    hex_dump(&pkt.data, 32)
                );
                let _ = file.write_all(entry.as_bytes());
            }

            let _ = file.write_all(b"========================================================================\n\n");
            let _ = file.flush();
        } else {
            eprintln!("[Error] Failed to write to log file at {}", log_path);
        }
    })
    .await
    .ok();
}

fn hex_dump(data: &[u8], limit: usize) -> String {
    let take_len = std::cmp::min(data.len(), limit);
    let hex: Vec<String> = data[..take_len].iter().map(|b| format!("{:02X}", b)).collect();
    if data.len() > limit {
        format!("{}...", hex.join(" "))
    } else {
        hex.join(" ")
    }
}
