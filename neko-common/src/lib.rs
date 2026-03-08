#![no_std]

pub const ACTION_PASS: u32 = 0;
pub const ACTION_DROP: u32 = 1;

// CompoundRule match_fields bitmask
pub const MATCH_PROTO: u32 = 1;
pub const MATCH_PORT: u32 = 2;
pub const MATCH_COUNTRY: u32 = 4;
pub const MATCH_ASN: u32 = 8;
pub const MATCH_IP: u32 = 16;

pub const MAX_COMPOUND_RULES: u32 = 128;

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
