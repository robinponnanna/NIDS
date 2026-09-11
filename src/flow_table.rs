use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type FlowKey = (u32, u16, u32, u16);

#[derive(Clone, Debug)]
pub struct Packet {
    pub timestamp: Instant,
    pub data: Vec<u8>,
}

pub struct FlowState {
    pub buffer: [Option<Packet>; 100],
    pub timestamps: [Instant; 100],
    pub head: usize,
    pub count: usize,
    pub oldest_ts: Instant,
    pub last_seen_ts: Instant,
}

impl FlowState {
    pub fn new(now: Instant) -> Self {
        const INIT_OPT: Option<Packet> = None;
        FlowState {
            buffer: [INIT_OPT; 100],
            timestamps: [now; 100],
            head: 0,
            count: 0,
            oldest_ts: now,
            last_seen_ts: now,
        }
    }

    /// On each packet arrival:
    /// IF count < 100:
    ///   - Write packet to buffer[head]
    ///   - Write timestamp to timestamps[head]
    ///   - If count == 0: set oldest_ts = timestamp
    ///   - count += 1
    ///   - head = (head + 1) % 100
    ///   - Return: no burst
    ///
    /// ELSE (buffer full, count == 100):
    ///   - time_span = now - oldest_ts
    ///   - IF time_span < 60 seconds:
    ///       → BURST DETECTED!
    ///   - Overwrite buffer[head] with new packet
    ///   - Update timestamps[head] = now
    ///   - oldest_ts = timestamps[(head + 1) % 100]  // Next slot becomes oldest
    ///   - head = (head + 1) % 100
    ///   - Return: burst_detected (true/false) and snapshot of 100 burst packets
    pub fn add_packet(&mut self, pkt: Packet) -> (bool, Option<Vec<Packet>>) {
        let now = pkt.timestamp;
        self.last_seen_ts = now;

        if self.count < 100 {
            self.buffer[self.head] = Some(pkt);
            self.timestamps[self.head] = now;
            if self.count == 0 {
                self.oldest_ts = now;
            }
            self.count += 1;
            self.head = (self.head + 1) % 100;
            (false, None)
        } else {
            // Buffer is full (count == 100)
            let time_span = if now >= self.oldest_ts {
                now.duration_since(self.oldest_ts)
            } else {
                Duration::from_secs(0)
            };

            let burst_detected = time_span < Duration::from_secs(60);

            let packets_snapshot = if burst_detected {
                Some(self.get_ordered_packets())
            } else {
                None
            };

            // Overwrite buffer[head] with new packet
            self.buffer[self.head] = Some(pkt);
            self.timestamps[self.head] = now;
            self.oldest_ts = self.timestamps[(self.head + 1) % 100];
            self.head = (self.head + 1) % 100;

            (burst_detected, packets_snapshot)
        }
    }

    /// Retrieve stored packets in chronological order.
    pub fn get_ordered_packets(&self) -> Vec<Packet> {
        let mut result = Vec::with_capacity(self.count);
        if self.count == 0 {
            return result;
        }

        if self.count < 100 {
            for i in 0..self.count {
                if let Some(ref pkt) = self.buffer[i] {
                    result.push(pkt.clone());
                }
            }
        } else {
            for i in 0..100 {
                let idx = (self.head + i) % 100;
                if let Some(ref pkt) = self.buffer[idx] {
                    result.push(pkt.clone());
                }
            }
        }
        result
    }
}

/// Global shared state managing flow table with mutex synchronization
pub struct SharedState {
    pub flow_table: Arc<Mutex<HashMap<FlowKey, FlowState>>>,
    pub max_flows: usize,
}

impl SharedState {
    pub fn new(max_flows: usize) -> Self {
        SharedState {
            flow_table: Arc::new(Mutex::new(HashMap::new())),
            max_flows,
        }
    }

    /// Process incoming packet, using LRU eviction if max_flows limit reached.
    pub fn process_packet(&self, key: FlowKey, pkt: Packet) -> (bool, Option<Vec<Packet>>) {
        let mut table = self.flow_table.lock().unwrap();

        if !table.contains_key(&key) {
            // LRU Eviction: trigger when flow_table.len() >= max_flows
            if table.len() >= self.max_flows {
                let mut oldest_key: Option<FlowKey> = None;
                let mut oldest_seen: Option<Instant> = None;

                for (k, state) in table.iter() {
                    match oldest_seen {
                        None => {
                            oldest_seen = Some(state.last_seen_ts);
                            oldest_key = Some(*k);
                        }
                        Some(ts) => {
                            if state.last_seen_ts < ts {
                                oldest_seen = Some(state.last_seen_ts);
                                oldest_key = Some(*k);
                            }
                        }
                    }
                }

                if let Some(k_evict) = oldest_key {
                    table.remove(&k_evict);
                }
            }

            table.insert(key, FlowState::new(pkt.timestamp));
        }

        let flow = table.get_mut(&key).unwrap();
        flow.add_packet(pkt)
    }

    /// Timeout-based cleanup: remove all flows where now - last_seen_ts > 60 seconds
    pub fn cleanup_inactive_flows(&self) -> usize {
        let mut table = self.flow_table.lock().unwrap();
        let now = Instant::now();
        let initial_len = table.len();

        table.retain(|_key, flow| {
            if now >= flow.last_seen_ts {
                now.duration_since(flow.last_seen_ts) <= Duration::from_secs(60)
            } else {
                true
            }
        });

        initial_len - table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_circular_buffer_and_burst_detection() {
        let now = Instant::now();
        let mut flow = FlowState::new(now);

        // Send 99 packets
        for i in 0..99 {
            let pkt = Packet {
                timestamp: now + Duration::from_millis(i * 10),
                data: vec![1, 2, 3],
            };
            let (burst, snapshot) = flow.add_packet(pkt);
            assert!(!burst);
            assert!(snapshot.is_none());
        }

        // Send 100th packet within 1 second total span
        let pkt100 = Packet {
            timestamp: now + Duration::from_millis(1000),
            data: vec![4, 5, 6],
        };
        let (burst, _snapshot) = flow.add_packet(pkt100);
        assert!(!burst); // Count reached 100, but burst condition evaluates on next packet when buffer is full (count == 100)

        // 101st packet within 2 seconds span (100 packets in < 60s)
        let pkt101 = Packet {
            timestamp: now + Duration::from_millis(2000),
            data: vec![7, 8, 9],
        };
        let (burst101, snapshot101) = flow.add_packet(pkt101);
        assert!(burst101);
        assert!(snapshot101.is_some());
        assert_eq!(snapshot101.unwrap().len(), 100);
    }

    #[test]
    fn test_lru_eviction() {
        let state = SharedState::new(2);
        let now = Instant::now();

        let key1 = (1, 100, 2, 200);
        let key2 = (3, 300, 4, 400);
        let key3 = (5, 500, 6, 600);

        let pkt1 = Packet { timestamp: now, data: vec![] };
        let pkt2 = Packet { timestamp: now + Duration::from_secs(1), data: vec![] };
        let pkt3 = Packet { timestamp: now + Duration::from_secs(2), data: vec![] };

        state.process_packet(key1, pkt1);
        state.process_packet(key2, pkt2);
        assert_eq!(state.flow_table.lock().unwrap().len(), 2);

        // Process key3 -> key1 has oldest last_seen_ts (now vs now+1s), so key1 should be evicted
        state.process_packet(key3, pkt3);
        let table = state.flow_table.lock().unwrap();
        assert_eq!(table.len(), 2);
        assert!(!table.contains_key(&key1));
        assert!(table.contains_key(&key2));
        assert!(table.contains_key(&key3));
    }

    #[test]
    fn test_timeout_cleanup() {
        let state = SharedState::new(10);
        let now = Instant::now();
        let old_ts = now.checked_sub(Duration::from_secs(70)).unwrap_or(now);

        let key1 = (10, 80, 20, 8080);
        let key2 = (30, 80, 40, 8080);

        // Key 1 packet with old timestamp (70s ago)
        state.process_packet(key1, Packet { timestamp: old_ts, data: vec![] });
        // Key 2 packet with fresh timestamp
        state.process_packet(key2, Packet { timestamp: now, data: vec![] });

        assert_eq!(state.flow_table.lock().unwrap().len(), 2);

        let removed = state.cleanup_inactive_flows();
        assert_eq!(removed, 1);

        let table = state.flow_table.lock().unwrap();
        assert_eq!(table.len(), 1);
        assert!(!table.contains_key(&key1));
        assert!(table.contains_key(&key2));
    }
}

