#![no_std]

pub const ACTION_PASS: u32 = 0;
pub const ACTION_DROP: u32 = 1;
pub const FLAG_EMIT_EVENTS: u32 = 1;

// CompoundRule match_fields bitmask
pub const MATCH_PROTO: u32 = 1;
pub const MATCH_PORT: u32 = 2;
pub const MATCH_COUNTRY: u32 = 4;
pub const MATCH_ASN: u32 = 8;
pub const MATCH_IP: u32 = 16;

/// High bit flag to distinguish ASN IDs from country IDs in GEO_POLICY map.
pub const ASN_FLAG: u32 = 0x80000000;

/// Encode protocol number and port into a single u32 key for ALLOWED_PORTS map.
#[inline(always)]
pub const fn port_key(proto: u8, port: u16) -> u32 {
    (proto as u32) << 16 | port as u32
}

pub const MAX_COMPOUND_RULES: u32 = 128;
pub const RULES_PER_STAGE: u32 = 16;
pub const RULE_STAGE_COUNT: u32 = (MAX_COMPOUND_RULES + RULES_PER_STAGE - 1) / RULES_PER_STAGE;
pub const RULE_PIPELINE_V4_BASE: u32 = 0;
pub const RULE_PIPELINE_V4_POST: u32 = RULE_PIPELINE_V4_BASE + RULE_STAGE_COUNT;
pub const RULE_PIPELINE_V6_BASE: u32 = RULE_PIPELINE_V4_POST + 1;
pub const RULE_PIPELINE_V6_POST: u32 = RULE_PIPELINE_V6_BASE + RULE_STAGE_COUNT;
pub const RULE_PIPELINE_SIZE: u32 = RULE_PIPELINE_V6_POST + 1;

/// Connection tracking key for IPv4 (5-tuple, network byte order for IPs/ports).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnTrackKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Connection tracking key for IPv6 (5-tuple, network byte order for ports).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnTrackKey6 {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketCtxV4 {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ct_src_port: u16,
    pub ct_dst_port: u16,
    pub proto: u8,
    pub _pad0: u8,
    pub country_id: u32,
    pub asn_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketCtxV6 {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub ct_src_port: u16,
    pub ct_dst_port: u16,
    pub proto: u8,
    pub _pad0: u8,
    pub country_id: u32,
    pub asn_id: u32,
}

/// Packet event log entry, shared between kernel and userspace via PerfEventArray.
/// Supports both IPv4 and IPv6. For IPv4, only the first 4 bytes of addr are used.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: u8,
    pub family: u8, // 4 = IPv4, 6 = IPv6
    pub _padding: [u8; 1],
}

/// Compound rule with multiple match conditions.
/// match_fields bitmask determines which fields are checked.
/// A match_fields of 0 means the slot is empty/unused.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompoundRule {
    pub match_fields: u32,
    pub action: u32,
    pub proto: u8,
    pub prefix_len: u8,
    pub port: u16,
    pub country_id: u32,
    pub asn_id: u32,
    pub src_ip: [u8; 16],
    pub family: u8, // 0 = any, 4 = IPv4 only, 6 = IPv6 only
    pub _pad: [u8; 3],
}

impl Default for CompoundRule {
    fn default() -> Self {
        Self {
            match_fields: 0,
            action: 0,
            proto: 0,
            prefix_len: 0,
            port: 0,
            country_id: 0,
            asn_id: 0,
            src_ip: [0u8; 16],
            family: 0,
            _pad: [0u8; 3],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackKey6 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CompoundRule {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketCtxV4 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketCtxV6 {}

#[cfg(feature = "user")]
impl CompoundRule {
    /// Fill src_ip from an IPv4 address (network byte order u32).
    pub fn set_ipv4(&mut self, addr_be: u32, prefix: u8) {
        let bytes = addr_be.to_ne_bytes();
        self.src_ip[0] = bytes[0];
        self.src_ip[1] = bytes[1];
        self.src_ip[2] = bytes[2];
        self.src_ip[3] = bytes[3];
        self.prefix_len = prefix;
        self.family = 4;
    }

    /// Fill src_ip from an IPv6 address octets.
    pub fn set_ipv6(&mut self, addr: [u8; 16], prefix: u8) {
        self.src_ip = addr;
        self.prefix_len = prefix;
        self.family = 6;
    }
}

#[cfg(feature = "user")]
pub fn parse_proto(proto: &str) -> Option<u8> {
    match proto.to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" | "ipv6-icmp" => Some(58),
        _ => None,
    }
}

#[cfg(feature = "user")]
pub fn proto_name(num: u8) -> &'static str {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "unknown",
    }
}
