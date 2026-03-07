#![no_std]

pub const ACTION_PASS: u32 = 0;
pub const ACTION_DROP: u32 = 1;

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackKey {}
