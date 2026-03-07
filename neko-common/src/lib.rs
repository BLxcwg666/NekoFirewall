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

/// Connection tracking key (5-tuple, network byte order for IPs/ports).
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

/// Packet event log entry, shared between kernel and userspace via PerfEventArray.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: u8,
    pub _padding: [u8; 2],
}

/// Compound rule with multiple match conditions.
/// match_fields bitmask determines which fields are checked.
/// A match_fields of 0 means the slot is empty/unused.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CompoundRule {
    pub match_fields: u32,
    pub action: u32,
    pub proto: u8,
    pub prefix_len: u8,
    pub port: u16,
    pub country_id: u32,
    pub asn_id: u32,
    pub src_ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CompoundRule {}
