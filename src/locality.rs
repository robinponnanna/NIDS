/// Maximum packet references per batch (chosen to fit comfortably in L2/L3 cache)
pub const MAX_BATCH_SIZE: usize = 4096;
pub const MAX_ACTIVE_BUCKETS: usize = 4096;

/// Zero-copy packet reference structure pointing to memory inside the mmap ring.
/// Highly compact (24 bytes) to maximize cache density.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct PacketRef {
    pub data_ptr: *const u8,
    pub len: u32,
    pub sec: u32,
    pub nsec: u32,
    pub block_idx: u32,
    pub port_key: u16, // min(src_port, dst_port)
}

impl Default for PacketRef {
    #[inline(always)]
    fn default() -> Self {
        PacketRef {
            data_ptr: std::ptr::null(),
            len: 0,
            sec: 0,
            nsec: 0,
            block_idx: 0,
            port_key: 0,
        }
    }
}

/// Locality Buffer cache-aligned structure.
/// Preallocates all tables to achieve zero heap allocations in the hot path.
#[repr(align(64))]
pub struct LocalityBuffer {
    pub input_refs: [PacketRef; MAX_BATCH_SIZE],
    pub sorted_refs: [PacketRef; MAX_BATCH_SIZE],
    
    // Counting sort structures: one entry per port
    pub counts: [u16; 65536],
    pub offsets: [u16; 65536],
    pub start_offsets: [u16; 65536],
    
    // Active buckets tracking list to prevent O(65536) iterations
    pub active_buckets: [u16; MAX_ACTIVE_BUCKETS],
    pub active_count: usize,
    pub current_size: usize,
}

impl LocalityBuffer {
    /// Create a new preallocated locality buffer.
    /// Since the structure is large (~600KB), it should be boxed on creation.
    pub fn new() -> Self {
        LocalityBuffer {
            input_refs: [PacketRef::default(); MAX_BATCH_SIZE],
            sorted_refs: [PacketRef::default(); MAX_BATCH_SIZE],
            counts: [0; 65536],
            offsets: [0; 65536],
            start_offsets: [0; 65536],
            active_buckets: [0; MAX_ACTIVE_BUCKETS],
            active_count: 0,
            current_size: 0,
        }
    }

    /// Clear counts, offsets, and active buckets tracker in O(ActiveBuckets) time instead of O(65536).
    #[inline(always)]
    pub fn clear(&mut self) {
        // Clear only the buckets that were modified in the previous batch
        for i in 0..self.active_count {
            let port = self.active_buckets[i] as usize;
            self.counts[port] = 0;
            self.offsets[port] = 0;
            self.start_offsets[port] = 0;
        }
        self.active_count = 0;
        self.current_size = 0;
    }

    /// Add a packet reference to the input batch.
    #[inline(always)]
    pub fn add_packet(
        &mut self,
        data_ptr: *const u8,
        len: u32,
        sec: u32,
        nsec: u32,
        block_idx: u32,
        port_key: u16,
    ) -> Result<(), &'static str> {
        if self.current_size >= MAX_BATCH_SIZE {
            return Err("Locality buffer batch size exceeded");
        }

        let ref_idx = self.current_size;
        self.input_refs[ref_idx] = PacketRef {
            data_ptr,
            len,
            sec,
            nsec,
            block_idx,
            port_key,
        };

        let port = port_key as usize;
        // If this is the first packet for this port in this batch, track it in active buckets
        if self.counts[port] == 0 {
            if self.active_count < MAX_ACTIVE_BUCKETS {
                self.active_buckets[self.active_count] = port_key;
                self.active_count += 1;
            }
        }
        self.counts[port] += 1;
        self.current_size += 1;

        Ok(())
    }

    /// Contiguously group packet references in O(N) using Counting Sort.
    /// Eliminates pointer chasing or linked lists.
    pub fn group_packets(&mut self) {
        if self.current_size == 0 {
            return;
        }

        // 1. Calculate start offsets for each active bucket in sorted array
        let mut sum = 0u16;
        for i in 0..self.active_count {
            let port = self.active_buckets[i] as usize;
            self.offsets[port] = sum;
            self.start_offsets[port] = sum;
            sum += self.counts[port];
        }

        // 2. Place packet references into sorted array contiguously by port key
        for i in 0..self.current_size {
            let pkt_ref = self.input_refs[i];
            let port = pkt_ref.port_key as usize;
            let dest_idx = self.offsets[port] as usize;
            
            // Bounds check to guarantee memory safety before unsafely indexing
            if dest_idx < MAX_BATCH_SIZE {
                self.sorted_refs[dest_idx] = pkt_ref;
                self.offsets[port] += 1;
            }
        }
    }

    /// Get contiguous slice of PacketRef for a specific active port.
    /// This linear scan of the slice has optimal spatial cache locality.
    #[inline(always)]
    pub fn get_bucket_slice(&self, port: u16) -> &[PacketRef] {
        let port_idx = port as usize;
        let start = self.start_offsets[port_idx] as usize;
        let count = self.counts[port_idx] as usize;
        
        if start + count <= self.current_size {
            &self.sorted_refs[start..start + count]
        } else {
            &[]
        }
    }
}

unsafe impl Send for PacketRef {}
unsafe impl Sync for PacketRef {}
