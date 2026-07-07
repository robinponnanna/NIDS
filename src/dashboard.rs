use std::collections::VecDeque;
use std::time::Instant;
use ratatui::{
    layout::{Constraint, Direction, Layout, Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Cell, List, ListItem, BorderType},
    Frame,
};
use crate::alert::{SecurityAlert, IdsmCompressedAlert};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ActivePane {
    AlertsTable,
    PacketsTable,
    IdsmHexView,
    IdsmJsonView,
}

pub struct AppState {
    pub all_packets_captured: usize,
    pub live_packets_count: usize,
    pub alerts: Vec<SecurityAlert>,
    pub compressed_alerts: Vec<IdsmCompressedAlert>,
    pub alerts_table_state: TableState,
    pub packets_table_state: TableState,
    pub active_pane: ActivePane,
    pub is_paused: bool,
    pub total_raw_bytes: usize,
    pub total_compressed_bytes: usize,
    pub recent_packets: VecDeque<(Instant, usize)>,
    pub link_layer_info: String,
    
    // Scrolling offsets for paragraph views
    pub hex_scroll_offset: u16,
    pub hex_horiz_scroll_offset: u16,
    pub json_scroll_offset: u16,
    pub json_horiz_scroll_offset: u16,
    
    // Boundary boxes for mouse event tracking
    pub alerts_rect: Rect,
    pub packets_rect: Rect,
    pub hex_rect: Rect,
    pub json_rect: Rect,
}

impl AppState {
    pub fn new() -> Self {
        let mut alerts_table_state = TableState::default();
        alerts_table_state.select(None);
        let mut packets_table_state = TableState::default();
        packets_table_state.select(None);

        AppState {
            all_packets_captured: 0,
            live_packets_count: 0,
            alerts: Vec::new(),
            compressed_alerts: Vec::new(),
            alerts_table_state,
            packets_table_state,
            active_pane: ActivePane::AlertsTable,
            is_paused: false,
            total_raw_bytes: 0,
            total_compressed_bytes: 0,
            recent_packets: VecDeque::new(),
            link_layer_info: "Live Mode / Bind Any".to_string(),
            hex_scroll_offset: 0,
            hex_horiz_scroll_offset: 0,
            json_scroll_offset: 0,
            json_horiz_scroll_offset: 0,
            alerts_rect: Rect::default(),
            packets_rect: Rect::default(),
            hex_rect: Rect::default(),
            json_rect: Rect::default(),
        }
    }

    pub fn get_pps(&self) -> usize {
        self.recent_packets.len()
    }

    pub fn get_bps(&self) -> usize {
        self.recent_packets.iter().map(|(_, size)| size).sum()
    }

    pub fn prune_old_metrics(&mut self) {
        let now = Instant::now();
        while let Some((time, _)) = self.recent_packets.front() {
            if now.duration_since(*time) > std::time::Duration::from_secs(1) {
                self.recent_packets.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn clear(&mut self) {
        self.alerts.clear();
        self.compressed_alerts.clear();
        self.alerts_table_state.select(None);
        self.packets_table_state.select(None);
        self.all_packets_captured = 0;
        self.live_packets_count = 0;
        self.total_raw_bytes = 0;
        self.total_compressed_bytes = 0;
        self.recent_packets.clear();
        self.hex_scroll_offset = 0;
        self.hex_horiz_scroll_offset = 0;
        self.json_scroll_offset = 0;
        self.json_horiz_scroll_offset = 0;
    }
}

pub fn draw_ui(f: &mut Frame, app: &mut AppState) {
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
        Span::styled(" Automotive Wi-Fi Intrusion Detection System ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
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
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
        .alignment(Alignment::Center), chunks[0]);

    // --- Main Layout ---
    // Split horizontally between Sensor & IDSM
    let right_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    // --- Sensor Pane (Left) ---
    let sensor_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(right_columns[0]);

    // Record boundary boxes for mouse event tracking
    app.alerts_rect = sensor_chunks[0];
    app.packets_rect = sensor_chunks[1];

    let alert_border_style = if app.active_pane == ActivePane::AlertsTable { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    
    let alerts_rows: Vec<Row> = app.alerts.iter().map(|a| {
        let sev_color = match a.severity {
            "Critical" => Color::LightRed,
            "High" => Color::Yellow,
            _ => Color::Gray,
        };
        Row::new(vec![
            Cell::from(a.id.to_string()),
            Cell::from(Span::styled(a.rule_name, Style::default().fg(Color::White))),
            Cell::from(Span::styled(a.severity, Style::default().fg(sev_color).add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(format!("{}%", a.confidence), Style::default().fg(Color::LightCyan))),
            Cell::from(a.timestamp.clone()),
        ])
    }).collect();

    let alerts_table = Table::new(alerts_rows, [
        Constraint::Length(5), Constraint::Min(25), Constraint::Length(10), Constraint::Length(8), Constraint::Length(14)
    ])
    .header(Row::new(vec!["ID", "Rule Triggered", "Severity", "Conf", "Time"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
    .block(Block::default().borders(Borders::ALL).title(" 1. Live Security Alerts ").border_style(alert_border_style))
    .row_highlight_style(Style::default().bg(Color::Rgb(30, 30, 60)).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(alerts_table, sensor_chunks[0], &mut app.alerts_table_state);

    // Timeline view of the selected alert in the bottom-left pane
    let packets_border_style = if app.active_pane == ActivePane::PacketsTable { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    
    let selected_idx = app.alerts_table_state.selected();
    let timeline_items: Vec<ListItem> = if let Some(idx) = selected_idx {
        if idx < app.alerts.len() {
            app.alerts[idx].timeline.iter().map(|evt| {
                ListItem::new(Line::from(vec![
                    Span::styled("• ", Style::default().fg(Color::Yellow)),
                    Span::styled(evt.clone(), Style::default().fg(Color::White)),
                ]))
            }).collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let timeline_list = List::new(timeline_items)
        .block(Block::default().borders(Borders::ALL).title(" 2. Alert Timeline / Evidence ").border_style(packets_border_style));
    f.render_widget(timeline_list, sensor_chunks[1]);

    // --- IDSM Pane (Right) ---
    let idsm_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(right_columns[1]);

    let alert_sel_idx = app.alerts_table_state.selected();
    let (stats_block, hex_block, json_block) = if let Some(idx) = alert_sel_idx {
        if idx < app.compressed_alerts.len() {
            let comp = &app.compressed_alerts[idx];
            let raw_alert = &app.alerts[idx];
            let stats = vec![
                Line::from(vec![Span::raw("Affected Device: "), Span::styled(&comp.affected_device, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::raw("Suspected Attacker: "), Span::styled(&comp.suspected_attacker, Style::default().fg(Color::LightRed))]),
                Line::from(vec![Span::raw("Detection Reason:   "), Span::styled(&raw_alert.reason, Style::default().fg(Color::White))]),
                Line::from(vec![
                    Span::raw("IDSM Compression:   "),
                    Span::styled(format!("Raw: {} B -> Compressed: {} B", comp.raw_payload_size, comp.compressed_size), Style::default().fg(Color::LightMagenta)),
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

    f.render_widget(Paragraph::new(stats_block).block(Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::TOP).title(" 3. IDSM Incident Metadata ")), idsm_stats_layout[0]);
    
    f.render_widget(Paragraph::new(hex_block)
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
            .title(" Compressed Binary Payload (Hex sent to Remote SOC) ")
            .border_style(hex_border_style))
        .scroll((app.hex_scroll_offset, app.hex_horiz_scroll_offset)), idsm_stats_layout[1]);

    f.render_widget(Paragraph::new(json_block)
        .block(Block::default().borders(Borders::ALL)
            .title(" 4. IDSM Preserved Semantic Data (Reconstructed at SOC) ")
            .border_style(json_border_style))
        .style(Style::default().fg(Color::LightCyan))
        .scroll((app.json_scroll_offset, app.json_horiz_scroll_offset)), idsm_chunks[1]);

    // --- Footer Pane ---
    let footer_text = Line::from(vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Switch Panel | "),
        Span::styled(" Arrows", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(": Navigate/Scroll | "),
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
