use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use std::slice;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use network_sensor::dashboard::{AppState, ActivePane, draw_ui};
use network_sensor::engine::StatefulDetectionEngine;
use network_sensor::{capture, parser, locality, alert};
use ratatui::layout::Rect;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    let mut interface_name = None;
    for i in 0..args.len() - 1 {
        if args[i] == "--interface" || args[i] == "-i" {
            interface_name = Some(args[i+1].as_str());
        }
    }

    let (tx_alerts, rx_alerts) = mpsc::channel();
    let (tx_metrics, rx_metrics) = mpsc::channel();
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();

    let link_type = detect_link_type(interface_name.as_deref());

    // 1. Launch raw packet capture thread
    let iface = interface_name.map(|s| s.to_string());
    let tx_alerts_capture = tx_alerts.clone();
    let tx_metrics_capture = tx_metrics.clone();

    thread::spawn(move || {
        let default_link = link_type;
        
        // Attempt to create raw socket. If it fails (due to permissions or platform), log and wait
        let mut capture_engine = match capture::MmapCapture::new(iface.as_deref()) {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("[Warning] Raw socket capture failed initialization: {}.", e);
                eprintln!("[Info] Running in simulation fallback mode. Use 'Enter' or 'S' in the dashboard to inject traffic.");
                // Fall loop: park the thread
                while is_running_clone.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(200));
                }
                return;
            }
        };

        // Preallocate locality buffer and detection engine
        let mut locality_buffer = Box::new(locality::LocalityBuffer::new());
        let mut detection_engine = StatefulDetectionEngine::new();

        while is_running_clone.load(Ordering::Relaxed) {
            // Poll for next mmap retired block
            if let Some(block_guard) = capture_engine.next_block(Duration::from_millis(50)) {
                locality_buffer.clear();
                
                // 1. Zero-copy extract packets from the block, pre-parse ports, and add to locality buffer
                for raw_pkt in block_guard.packets() {
                    let parsed = parser::parse_packet(raw_pkt.data, default_link);
                    
                    let mut port_key = 0u16;
                    match &parsed.transport {
                        parser::TransportLayer::Tcp { src_port, dst_port, .. } => {
                            port_key = std::cmp::min(*src_port, *dst_port);
                        }
                        parser::TransportLayer::Udp { src_port, dst_port, .. } => {
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
                        
                        let timestamp = pkt_ref.sec as f64 + (pkt_ref.nsec as f64 / 1_000_000_000.0);
                        let generated_alerts = detection_engine.process_packet(&parsed, timestamp);
                        
                        for alert in generated_alerts {
                            let compressed = alert::IDSM::compress(&alert, &[parsed.clone()]);
                            let _ = tx_alerts_capture.send((alert, compressed));
                        }

                        let _ = tx_metrics_capture.send((pkt_ref.len as usize, pkt_ref.sec, pkt_ref.nsec));
                    }
                }
            }
        }
    });

    // 2. Initialize TUI Terminal Dashboard
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new();
    let link_type_str = match link_type {
        parser::LinkType::Ethernet => "Ethernet",
        parser::LinkType::Wifi80211 => "802.11 Wi-Fi",
        parser::LinkType::RadiotapWifi => "802.11 Wi-Fi (Radiotap)",
        parser::LinkType::Unknown => "Unknown (Auto-Detecting)",
    };
    app.link_layer_info = match interface_name {
        Some(name) => format!("Live: {} ({})", name, link_type_str),
        None => "Simulation Fallback / Bind Any".to_string(),
    };

    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(40);

    loop {
        // Draw ratatui UI
        terminal.draw(|f| draw_ui(f, &mut app))?;

        // Pull alerts and metrics from channels
        while let Ok((alert, compressed)) = rx_alerts.try_recv() {
            app.total_raw_bytes += compressed.raw_payload_size;
            app.total_compressed_bytes += compressed.compressed_size;
            app.alerts.push(alert);
            app.compressed_alerts.push(compressed);
            // Auto-select latest alert
            if !app.alerts.is_empty() {
                app.alerts_table_state.select(Some(app.alerts.len() - 1));
            }
        }

        while let Ok((size, _sec, _nsec)) = rx_metrics.try_recv() {
            app.all_packets_captured += 1;
            app.live_packets_count += 1;
            app.recent_packets.push_back((Instant::now(), size));
        }

        // TUI event polling
        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or(Duration::from_secs(0));
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('p') => app.is_paused = !app.is_paused,
                        KeyCode::Char('c') => {
                            app.clear();
                        }
                        KeyCode::Tab => {
                            app.active_pane = match app.active_pane {
                                ActivePane::AlertsTable => ActivePane::PacketsTable,
                                ActivePane::PacketsTable => ActivePane::IdsmHexView,
                                ActivePane::IdsmHexView => ActivePane::IdsmJsonView,
                                ActivePane::IdsmJsonView => ActivePane::AlertsTable,
                            };
                        }
                        KeyCode::Up => {
                            scroll_pane_up(&mut app);
                        }
                        KeyCode::Down => {
                            scroll_pane_down(&mut app);
                        }
                        KeyCode::Left => {
                            scroll_pane_left(&mut app);
                        }
                        KeyCode::Right => {
                            scroll_pane_right(&mut app);
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse_event) => {
                    let col = mouse_event.column;
                    let row = mouse_event.row;
                    let clicked_pane = if rect_contains(app.alerts_rect, col, row) {
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
                                scroll_pane_up(&mut app);
                            }
                            event::MouseEventKind::ScrollDown => {
                                scroll_pane_down(&mut app);
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

// Helpers for scrolling TUI panes
fn scroll_pane_up(app: &mut AppState) {
    match app.active_pane {
        ActivePane::AlertsTable => {
            if let Some(selected) = app.alerts_table_state.selected() {
                if selected > 0 {
                    app.alerts_table_state.select(Some(selected - 1));
                }
            }
        }
        ActivePane::PacketsTable => {
            if let Some(selected) = app.packets_table_state.selected() {
                if selected > 0 { app.packets_table_state.select(Some(selected - 1)); }
            }
        }
        ActivePane::IdsmHexView => {
            app.hex_scroll_offset = app.hex_scroll_offset.saturating_sub(1);
        }
        ActivePane::IdsmJsonView => {
            app.json_scroll_offset = app.json_scroll_offset.saturating_sub(1);
        }
    }
}

fn scroll_pane_down(app: &mut AppState) {
    match app.active_pane {
        ActivePane::AlertsTable => {
            if let Some(selected) = app.alerts_table_state.selected() {
                if selected < app.alerts.len() - 1 {
                    app.alerts_table_state.select(Some(selected + 1));
                }
            } else if !app.alerts.is_empty() {
                app.alerts_table_state.select(Some(0));
            }
        }
        ActivePane::PacketsTable => {
            if let Some(selected) = app.packets_table_state.selected() {
                app.packets_table_state.select(Some(selected + 1));
            } else {
                app.packets_table_state.select(Some(0));
            }
        }
        ActivePane::IdsmHexView => {
            app.hex_scroll_offset = app.hex_scroll_offset.saturating_add(1);
        }
        ActivePane::IdsmJsonView => {
            app.json_scroll_offset = app.json_scroll_offset.saturating_add(1);
        }
    }
}

fn scroll_pane_left(app: &mut AppState) {
    match app.active_pane {
        ActivePane::IdsmHexView => {
            app.hex_horiz_scroll_offset = app.hex_horiz_scroll_offset.saturating_sub(1);
        }
        ActivePane::IdsmJsonView => {
            app.json_horiz_scroll_offset = app.json_horiz_scroll_offset.saturating_sub(1);
        }
        _ => {}
    }
}

fn scroll_pane_right(app: &mut AppState) {
    match app.active_pane {
        ActivePane::IdsmHexView => {
            app.hex_horiz_scroll_offset = app.hex_horiz_scroll_offset.saturating_add(1);
        }
        ActivePane::IdsmJsonView => {
            app.json_horiz_scroll_offset = app.json_horiz_scroll_offset.saturating_add(1);
        }
        _ => {}
    }
}

fn rect_contains(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

fn detect_link_type(interface: Option<&str>) -> parser::LinkType {
    let Some(iface) = interface else {
        return parser::LinkType::Ethernet;
    };
    // Query /sys/class/net/<interface>/type
    if let Ok(type_str) = std::fs::read_to_string(format!("/sys/class/net/{}/type", iface)) {
        if let Ok(type_val) = type_str.trim().parse::<u16>() {
            match type_val {
                1 => return parser::LinkType::Ethernet,             // ARPHRD_ETHER
                801 => return parser::LinkType::Wifi80211,          // ARPHRD_IEEE80211
                803 => return parser::LinkType::RadiotapWifi,       // ARPHRD_IEEE80211_RADIOTAP
                _ => {}
            }
        }
    }
    // Fallback to auto-detecting per-packet using Unknown
    parser::LinkType::Unknown
}
