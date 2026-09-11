use std::fmt;

pub type FlowKey = (u32, u16, u32, u16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowParseError {
    PacketTooShort,
    NotIpv4,
    UnsupportedProtocol(u8),
    TruncatedHeader,
}

impl fmt::Display for FlowParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowParseError::PacketTooShort => write!(f, "Packet buffer too short"),
            FlowParseError::NotIpv4 => write!(f, "Not an IPv4 packet"),
            FlowParseError::UnsupportedProtocol(p) => write!(f, "Unsupported protocol: {}", p),
            FlowParseError::TruncatedHeader => write!(f, "Truncated IP or Transport header"),
        }
    }
}

impl std::error::Error for FlowParseError {}

/// Parse 4-tuple (src_ip, src_port, dst_ip, dst_port) from raw packet bytes.
/// Handles Ethernet II encapsulated frames as well as raw IPv4 headers.
pub fn parse_flow_key(data: &[u8]) -> Result<FlowKey, FlowParseError> {
    if data.is_empty() {
        return Err(FlowParseError::PacketTooShort);
    }

    // Determine offset of IPv4 header
    let ip_offset = if data.len() >= 14 && data[12] == 0x08 && data[13] == 0x00 {
        // Ethernet II frame header (14 bytes)
        14
    } else if (data[0] >> 4) == 4 {
        // Direct raw IPv4 packet header
        0
    } else {
        return Err(FlowParseError::NotIpv4);
    };

    let ip_bytes = &data[ip_offset..];
    if ip_bytes.len() < 20 {
        return Err(FlowParseError::PacketTooShort);
    }

    // Check version
    let version = ip_bytes[0] >> 4;
    if version != 4 {
        return Err(FlowParseError::NotIpv4);
    }

    // Internet Header Length (IHL) in 32-bit words
    let ihl = ((ip_bytes[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ip_bytes.len() < ihl {
        return Err(FlowParseError::TruncatedHeader);
    }

    let protocol = ip_bytes[9];
    if protocol != 6 && protocol != 17 {
        // Only TCP (6) and UDP (17) are processed per core requirements
        return Err(FlowParseError::UnsupportedProtocol(protocol));
    }

    // Extract IPv4 source and destination (big endian)
    let src_ip = u32::from_be_bytes([ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]]);
    let dst_ip = u32::from_be_bytes([ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]]);

    // Transport header starts after IHL
    let transport_bytes = &ip_bytes[ihl..];
    if transport_bytes.len() < 4 {
        return Err(FlowParseError::TruncatedHeader);
    }

    let src_port = u16::from_be_bytes([transport_bytes[0], transport_bytes[1]]);
    let dst_port = u16::from_be_bytes([transport_bytes[2], transport_bytes[3]]);

    Ok((src_ip, src_port, dst_ip, dst_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_ipv4_tcp() {
        let mut pkt = vec![0u8; 14 + 20 + 20];
        // Ethernet header
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        // IPv4 header (IHL = 5 -> 20 bytes, protocol = 6 TCP)
        let ip = &mut pkt[14..];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&192u32.to_be_bytes());
        ip[16..20].copy_from_slice(&10u32.to_be_bytes());
        // TCP header
        let tcp = &mut pkt[34..];
        tcp[0..2].copy_from_slice(&80u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&12345u16.to_be_bytes());

        let res = parse_flow_key(&pkt);
        assert!(res.is_ok());
        let (src_ip, src_port, dst_ip, dst_port) = res.unwrap();
        assert_eq!(src_ip, 192);
        assert_eq!(src_port, 80);
        assert_eq!(dst_ip, 10);
        assert_eq!(dst_port, 12345);
    }
}
