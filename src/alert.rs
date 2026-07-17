use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct IdsmMessage {
    pub seq_no: u64,
    pub ttl_ms: u64,
    pub sensor_id: String,
    pub sensor_cert_id: String,
    pub signature: Vec<u8>,
    pub event: SensorEvent,
}

#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorEvent {
    pub event_id: &'static str,
    pub event_name: &'static str,
    pub severity: Severity,
    pub timestamp: String,
    pub vehicle_id_hash: String,
    pub iface: String,
    pub capture_id: Option<String>,
    pub evidence_uri: Option<String>,
    pub payload: EventPayload,
}

#[derive(Debug, Clone, Serialize)]
pub enum EventPayload {
    RadioPacketFloodStart(RadioPacketFloodStart),
    HighBroadcastStorm(HighBroadcastStorm),
    ProtocolConformantFlood(ProtocolConformantFlood),
    RapidSourceSwitching(RapidSourceSwitching),
    ControlChannelStarvation(ControlChannelStarvation),
    SensorResourceExhaustion(SensorResourceExhaustion),
    PacketReplayFlood(PacketReplayFlood),
    ChannelJammingIndication(ChannelJammingIndication),
    AnomalousBurstPattern(AnomalousBurstPattern),
    FloodMitigationApplied(FloodMitigationApplied),
}

#[derive(Debug, Clone, Serialize)]
pub struct RadioPacketFloodStart {
    pub pkt_rate: u32,
    pub baseline_rate: u32,
    pub window_duration_s: u32,
    pub rssi_avg: f32,
    pub modulation: String,
    pub channel: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighBroadcastStorm {
    pub broadcast_ratio: f32,
    pub pkt_rate: u32,
    pub top_broadcast_srcs: Vec<String>,
    pub top_broadcast_pkt_counts: Vec<u32>,
    pub mitigation_applied: bool,
    pub mitigation_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolConformantFlood {
    pub packet_signature_hash: String,
    pub signature_description: String,
    pub sender_list: Vec<SenderRate>,
    pub fingerprint_ids: Vec<String>,
    pub recommended_mitigation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SenderRate {
    pub sender_id: String,
    pub pkt_rate_per_sender: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RapidSourceSwitching {
    pub unique_src_count: u32,
    pub aggregate_pkt_rate: u32,
    pub top_srcs_summary: Vec<String>,
    pub sample_rate: u32,
    pub cluster_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlChannelStarvation {
    pub channel_id: String,
    pub loss_rate: f32,
    pub median_latency_ms: u32,
    pub missing_message_ids: Vec<String>,
    pub recent_message_samples: Vec<String>,
    pub safety_escalation_flag: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorResourceExhaustion {
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub queue_drops: u32,
    pub sampling_mode_set: bool,
    pub persisted_capture_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketReplayFlood {
    pub payload_hash: String,
    pub repeat_count: u32,
    pub involved_srcs: Vec<String>,
    pub exemplar_packet_reference: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelJammingIndication {
    pub noise_floor_dbm: f32,
    pub crc_error_rate: f32,
    pub affected_channels: Vec<u16>,
    pub spectrogram_id: Option<String>,
    pub rf_scan_snapshot_uri: Option<String>,
    pub mitigation_recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalousBurstPattern {
    pub burst_start_ts: String,
    pub burst_duration_s: u32,
    pub targeted_message_ids: Vec<String>,
    pub missed_count: u32,
    pub timing_trace_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FloodMitigationApplied {
    pub mitigation_type: String,
    pub cause_event_id: String,
    pub policy_id: String,
    pub pre_mitigation_metrics: String,
    pub post_mitigation_metrics: String,
    pub action_status: String,
}
