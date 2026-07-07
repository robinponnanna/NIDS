use criterion::{black_box, criterion_group, criterion_main, Criterion};
use network_sensor::parser::{parse_packet, LinkType};
use network_sensor::locality::LocalityBuffer;
use network_sensor::engine::StatefulDetectionEngine;
use network_sensor::alert::IDSM;

fn make_tcp_pkt(dst_port: u16) -> Vec<u8> {
    let mut data = Vec::new();
    // Ethernet Header: dst=00:11:22:33:44:55, src=aa:bb:cc:dd:ee:ff, type=0x0800
    data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    data.extend_from_slice(&[0x08, 0x00]);

    // IPv4 Header (20 bytes): TotalLen = 60, Protocol = TCP (6)
    data.extend_from_slice(&[0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]);
    data.extend_from_slice(&[10, 0, 0, 55]); // Src
    data.extend_from_slice(&[192, 168, 1, 10]); // Dst

    // TCP Header (20 bytes): SrcPort = 54321, DstPort, flags = SYN (0x02)
    data.extend_from_slice(&[0xD4, 0x31]); // Src Port
    data.extend_from_slice(&dst_port.to_be_bytes()); // Dst Port
    // Seq, Ack, DataOffset = 5, Flags = 0x02, Window, Checksum, Urgent
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    data
}

fn make_beacon_pkt() -> Vec<u8> {
    let mut data = Vec::new();
    // Radiotap (16 bytes)
    data.extend_from_slice(&[0x00, 0x00, 0x10, 0x00, 0x28, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&[0x85, 0x09, 0xa0, 0x00]);
    data.push(0xD3);
    data.extend_from_slice(&[0x00, 0x00, 0x00]);

    // 802.11 Beacon frame (FC = Beacon (0x80))
    data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Addr1: Broadcast
    let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    data.extend_from_slice(&bssid); // Addr2: BSSID
    data.extend_from_slice(&bssid); // Addr3: BSSID
    data.extend_from_slice(&[0x00, 0x00]);

    // Management Body
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x11, 0x04]);
    // SSID Tag
    data.extend_from_slice(&[0, 17]);
    data.extend_from_slice(b"Enterprise_Secure");
    data
}

fn bench_parser(c: &mut Criterion) {
    let beacon_pkt = make_beacon_pkt();
    let tcp_pkt = make_tcp_pkt(80);

    c.bench_function("parse_80211_beacon", |b| {
        b.iter(|| {
            let parsed = parse_packet(black_box(&beacon_pkt), LinkType::RadiotapWifi);
            black_box(parsed);
        })
    });

    c.bench_function("parse_ethernet_tcp", |b| {
        b.iter(|| {
            let parsed = parse_packet(black_box(&tcp_pkt), LinkType::Ethernet);
            black_box(parsed);
        })
    });
}

fn bench_locality_buffer(c: &mut Criterion) {
    c.bench_function("locality_grouping_1000_pkts", |b| {
        let mut buffer = Box::new(LocalityBuffer::new());
        b.iter(|| {
            buffer.clear();
            let data = [0u8; 64];
            let ptr = data.as_ptr();
            
            for i in 0..1000 {
                let port = if i % 2 == 0 { 80 } else { 443 };
                let _ = buffer.add_packet(ptr, 64, 12345, i as u32, 0, port);
            }
            
            buffer.group_packets();
            black_box(&buffer);
        })
    });
}

fn bench_detection_engine(c: &mut Criterion) {
    let mut engine = StatefulDetectionEngine::new();
    let tcp_pkt = make_tcp_pkt(80);
    let parsed = parse_packet(&tcp_pkt, LinkType::Ethernet);

    c.bench_function("engine_process_tcp_syn", |b| {
        b.iter(|| {
            let alerts = engine.process_packet(black_box(&parsed), black_box(1700000000.0));
            black_box(alerts);
        })
    });
}

fn bench_idsm_compression(c: &mut Criterion) {
    let mut engine = StatefulDetectionEngine::new();
    let tcp_pkt = make_tcp_pkt(80);
    let parsed = parse_packet(&tcp_pkt, LinkType::Ethernet);
    
    // Process packets until an alert is generated (trigger TCP port scan rule)
    let mut alerts = Vec::new();
    for i in 0..25 {
        let pkt = make_tcp_pkt(i as u16 + 1);
        let parsed_pkt = parse_packet(&pkt, LinkType::Ethernet);
        let generated = engine.process_packet(&parsed_pkt, 1700000000.0 + i as f64);
        alerts.extend(generated);
    }
    
    let alert = alerts.first().expect("Should have generated a TCP Scan alert").clone();

    c.bench_function("idsm_compress_zlib", |b| {
        b.iter(|| {
            let compressed = IDSM::compress(black_box(&alert), black_box(&[parsed.clone()]));
            black_box(compressed);
        })
    });
}

criterion_group!(benches, bench_parser, bench_locality_buffer, bench_detection_engine, bench_idsm_compression);
criterion_main!(benches);
