use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::ptr;
use std::slice;
use std::time::Duration;

// Raw Linux constants for packet socket and PACKET_MMAP
pub const SOL_PACKET: libc::c_int = 263;
pub const PACKET_VERSION: libc::c_int = 10;
pub const PACKET_RX_RING: libc::c_int = 5;
pub const TPACKET_V3: libc::c_int = 2;

// Block status flags
pub const TP_STATUS_KERNEL: u32 = 0;
pub const TP_STATUS_USER: u32 = 1;

/// Radiotap packet timestamp structure inside kernel headers
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tpacket_bd_ts {
    pub ts_sec: u32,
    pub ts_usec: u32,
}

/// Block header descriptor version 1
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tpacket_hdr_v1 {
    pub block_status: u32,
    pub num_pkts: u32,
    pub offset_to_first_pkt: u32,
    pub blk_len: u32,
    pub seq_num: u64,
    pub ts_first_pkt: tpacket_bd_ts,
    pub ts_last_pkt: tpacket_bd_ts,
}

/// Union for block descriptor headers
#[repr(C)]
#[derive(Copy, Clone)]
pub union tpacket_bd_header_u {
    pub bh1: tpacket_hdr_v1,
}

/// Entire block descriptor header
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tpacket_block_desc {
    pub version: u32,
    pub offset_to_priv: u32,
    pub hdr: tpacket_bd_header_u,
}

/// Variant header inside packet headers
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tpacket_hdr_variant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    pub tp_padding: u16,
}

/// Header for individual packet frame inside the block
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tpacket3_hdr {
    pub tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: tpacket_hdr_variant1,
    pub tp_padding: [u8; 8],
}

/// Config request structure for setting up PACKET_RX_RING
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tpacket_req3 {
    pub tp_block_size: libc::c_uint,
    pub tp_block_nr: libc::c_uint,
    pub tp_frame_size: libc::c_uint,
    pub tp_frame_nr: libc::c_uint,
    pub tp_retire_blk_tov: libc::c_uint,
    pub tp_sizeof_priv: libc::c_uint,
    pub tp_feature_req_word: libc::c_uint,
}

/// Zero-copy packet pointer borrowing directly from the MMAP ring
#[derive(Debug, Copy, Clone)]
pub struct RawPacket<'a> {
    pub data: &'a [u8],
    pub sec: u32,
    pub nsec: u32,
    pub len: u32,
    pub snaplen: u32,
    pub block_idx: usize,
}

/// RAII Guard that manages ownership of a retired block
pub struct BlockGuard<'a> {
    capture: &'a mut MmapCapture,
    pub block_idx: usize,
}

impl<'a> BlockGuard<'a> {
    /// Iterates over all packets in the retired block
    pub fn packets(&self) -> PacketIterator<'a> {
        let block_ptr = self.capture.get_block_ptr(self.block_idx);
        unsafe {
            // SAFETY: The block_ptr is guaranteed to point to a valid memory block mapped in our mmap space.
            // Under TPACKET_V3, a block contains a tpacket_block_desc header.
            let desc = &*(block_ptr as *const tpacket_block_desc);
            let bh1 = &desc.hdr.bh1;
            PacketIterator {
                block_ptr,
                num_pkts: bh1.num_pkts,
                current_pkt_idx: 0,
                current_offset: bh1.offset_to_first_pkt as usize,
                block_idx: self.block_idx,
                _phantom: std::marker::PhantomData,
            }
        }
    }
}

impl<'a> Drop for BlockGuard<'a> {
    fn drop(&mut self) {
        // Recycle block back to kernel ownership
        unsafe {
            // SAFETY: The block_idx is in valid range, and the pointer points to a valid mapped block.
            // Returning the block to the kernel is necessary for continuous capture.
            self.capture.recycle_block(self.block_idx);
        }
    }
}

/// Iterator yielding RawPacket references
pub struct PacketIterator<'a> {
    block_ptr: *const u8,
    num_pkts: u32,
    current_pkt_idx: u32,
    current_offset: usize,
    block_idx: usize,
    _phantom: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Iterator for PacketIterator<'a> {
    type Item = RawPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_pkt_idx >= self.num_pkts {
            return None;
        }

        unsafe {
            // SAFETY: We ensure that self.current_offset is within the block boundaries (block size is 1MB).
            // The kernel guarantees that packet offsets in the ring buffer are aligned and correct.
            let pkt_hdr_ptr = self.block_ptr.add(self.current_offset) as *const tpacket3_hdr;
            let pkt_hdr = &*pkt_hdr_ptr;

            let data_ptr = (pkt_hdr_ptr as *const u8).add(pkt_hdr.tp_mac as usize);
            let data_len = pkt_hdr.tp_snaplen as usize;

            // SAFTEY: Creating a slice from raw parts of the mapped ring buffer.
            // The lifetime is bounded by the block guard.
            let data = slice::from_raw_parts(data_ptr, data_len);

            let packet = RawPacket {
                data,
                sec: pkt_hdr.tp_sec,
                nsec: pkt_hdr.tp_nsec,
                len: pkt_hdr.tp_len,
                snaplen: pkt_hdr.tp_snaplen,
                block_idx: self.block_idx,
            };

            // Advance offset
            if pkt_hdr.tp_next_offset > 0 {
                self.current_offset += pkt_hdr.tp_next_offset as usize;
            } else {
                // If next_offset is 0, we can't parse further, stop
                self.current_pkt_idx = self.num_pkts;
            }
            self.current_pkt_idx += 1;

            Some(packet)
        }
    }
}

/// Zero-Copy MMAP Capture Engine using standard Linux APIs
pub struct MmapCapture {
    fd: RawFd,
    mmap_ptr: *mut libc::c_void,
    mmap_len: usize,
    block_size: usize,
    block_nr: usize,
    current_block_idx: usize,
    poll_fd: libc::pollfd,
}

impl MmapCapture {
    /// Initialize Raw Socket and Mmap Ring Buffer on the given interface (e.g. "wlan0").
    /// If interface is None, captures on any interface.
    pub fn new(interface: Option<&str>) -> Result<Self, String> {
        unsafe {
            // SAFETY: System call to open raw packet socket. Using ETH_P_ALL to listen to all packet protocols.
            // Returns raw file descriptor.
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            );
            if fd < 0 {
                return Err(format!("Failed to create raw socket: errno {}", std::io::Error::last_os_error()));
            }

            // Set packet version to TPACKET_V3
            let version = TPACKET_V3;
            // SAFETY: Configuring packet socket version to V3 using setsockopt.
            let res = libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                std::mem::size_of_val(&version) as libc::socklen_t,
            );
            if res < 0 {
                libc::close(fd);
                return Err(format!("Failed to set socket packet version to V3: errno {}", std::io::Error::last_os_error()));
            }

            // Configure RX Ring structure
            let block_size = 1048576; // 1MB block size (must be page size aligned)
            let block_nr = 64;        // 64 blocks = 64MB ring buffer size
            let frame_size = 2048;    // 2KB frame size (must be 16-byte aligned)
            let frame_nr = (block_size / frame_size) * block_nr;
            
            let req = tpacket_req3 {
                tp_block_size: block_size as libc::c_uint,
                tp_block_nr: block_nr as libc::c_uint,
                tp_frame_size: frame_size as libc::c_uint,
                tp_frame_nr: frame_nr as libc::c_uint,
                tp_retire_blk_tov: 10, // 10ms block timeout (lowers latency)
                tp_sizeof_priv: 0,
                tp_feature_req_word: 0,
            };

            // SAFETY: Configuring raw socket ring buffer layout using setsockopt.
            let res = libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                std::mem::size_of_val(&req) as libc::socklen_t,
            );
            if res < 0 {
                libc::close(fd);
                return Err(format!("Failed to set PACKET_RX_RING: errno {}", std::io::Error::last_os_error()));
            }

            // Memory map the ring buffer
            let mmap_len = block_size * block_nr;
            // SAFETY: mmap maps the ring buffer allocated by the kernel in setsockopt into the process address space.
            // This is shared memory-mapped memory directly mapping kernel packet capture buffers.
            let mmap_ptr = libc::mmap(
                ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if mmap_ptr == libc::MAP_FAILED {
                libc::close(fd);
                return Err(format!("Failed to mmap socket ring buffer: errno {}", std::io::Error::last_os_error()));
            }

            // Bind the socket to the interface index
            let mut if_index = 0;
            if let Some(if_name) = interface {
                let name_cstr = CString::new(if_name).unwrap();
                // SAFETY: FFI call to lookup system network interface index from name.
                let index = libc::if_nametoindex(name_cstr.as_ptr());
                if index == 0 {
                    libc::munmap(mmap_ptr, mmap_len);
                    libc::close(fd);
                    return Err(format!("Interface '{}' not found", if_name));
                }
                if_index = index as libc::c_int;
            }

            let mut addr: libc::sockaddr_ll = std::mem::zeroed();
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            addr.sll_ifindex = if_index;

            // SAFETY: Bind packet socket to the interface. Binds capture to specific NIC or all if index is 0.
            let res = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if res < 0 {
                libc::munmap(mmap_ptr, mmap_len);
                libc::close(fd);
                return Err(format!("Failed to bind socket: errno {}", std::io::Error::last_os_error()));
            }

            let poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };

            Ok(MmapCapture {
                fd,
                mmap_ptr,
                mmap_len,
                block_size,
                block_nr,
                current_block_idx: 0,
                poll_fd,
            })
        }
    }

    /// Read next block from the ring buffer. Blocks up to `timeout` if no block is ready.
    /// Returns `Some(BlockGuard)` when a block becomes owned by userspace.
    pub fn next_block(&mut self, timeout: Duration) -> Option<BlockGuard<'_>> {
        let block_idx = self.current_block_idx;
        let block_ptr = self.get_block_ptr(block_idx);

        unsafe {
            // SAFETY: We verify block ownership by casting the block pointer to tpacket_block_desc.
            // If block_status is not owned by userspace (i.e. does not have TP_STATUS_USER bit set),
            // we use poll to wait for packets to arrive.
            let desc = &*(block_ptr as *const tpacket_block_desc);
            let status = desc.hdr.bh1.block_status;

            if (status & TP_STATUS_USER) == 0 {
                // Not owned by user. Let's poll for packets.
                self.poll_fd.revents = 0;
                let timeout_ms = timeout.as_millis() as libc::c_int;
                
                // SAFETY: Poll yields execution to kernel until socket descriptor has incoming packets.
                let ret = libc::poll(&mut self.poll_fd as *mut _, 1, timeout_ms);
                if ret <= 0 {
                    return None;
                }

                // Check block status again
                let status = desc.hdr.bh1.block_status;
                if (status & TP_STATUS_USER) == 0 {
                    return None;
                }
            }

            // We have a retired block ready for userspace processing!
            // Advance block index
            self.current_block_idx = (self.current_block_idx + 1) % self.block_nr;

            Some(BlockGuard {
                capture: self,
                block_idx,
            })
        }
    }

    /// Releases block back to the kernel.
    pub unsafe fn recycle_block(&mut self, block_idx: usize) {
        let block_ptr = self.get_block_ptr(block_idx);
        // SAFETY: Pointer is valid. We are resetting the block status field to TP_STATUS_KERNEL (0)
        // to signify that userspace has completed reading all packets and the kernel is free to overwrite.
        unsafe {
            let desc = &mut *(block_ptr as *mut tpacket_block_desc);
            desc.hdr.bh1.block_status = TP_STATUS_KERNEL;
        }
    }

    /// Get raw pointer to start of block at `block_idx`
    #[inline(always)]
    fn get_block_ptr(&self, block_idx: usize) -> *mut u8 {
        unsafe {
            // SAFETY: Arithmetic offset calculations within memory boundaries of the mapped pointer.
            // mmap_ptr + block_idx * block_size is guaranteed to be within mapped range since block_idx < block_nr.
            (self.mmap_ptr as *mut u8).add(block_idx * self.block_size)
        }
    }
}

impl Drop for MmapCapture {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: Clean up shared memory map and close the file descriptor on drop to prevent leaks.
            libc::munmap(self.mmap_ptr, self.mmap_len);
            libc::close(self.fd);
        }
    }
}

unsafe impl Send for tpacket_bd_ts {}
unsafe impl Send for tpacket_hdr_v1 {}
unsafe impl Send for tpacket_bd_header_u {}
unsafe impl Send for tpacket_block_desc {}
unsafe impl Send for tpacket_hdr_variant1 {}
unsafe impl Send for tpacket3_hdr {}

unsafe impl Sync for tpacket_bd_ts {}
unsafe impl Sync for tpacket_hdr_v1 {}
unsafe impl Sync for tpacket_bd_header_u {}
unsafe impl Sync for tpacket_block_desc {}
unsafe impl Sync for tpacket_hdr_variant1 {}
unsafe impl Sync for tpacket3_hdr {}

unsafe impl<'a> Send for RawPacket<'a> {}
unsafe impl<'a> Sync for RawPacket<'a> {}
