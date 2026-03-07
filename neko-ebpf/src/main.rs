#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map, xdp},
    maps::{HashMap, LpmTrie, PerfEventArray},
    programs::{TcContext, XdpContext},
};
use aya_ebpf::maps::lpm_trie::Key;
use core::mem;
use neko_common::{ConnTrackKey, PacketLog, ACTION_DROP, ACTION_PASS};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const CONNTRACK_TIMEOUT_NS: u64 = 300_000_000_000;

#[map]
static ALLOWED_IPS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static ALLOWED_PORTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static CONNTRACK: HashMap<ConnTrackKey, u64> = HashMap::with_max_entries(65536, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[map]
static GEO_MAP: LpmTrie<u32, u32> = LpmTrie::with_max_entries(524288, 0);

#[map]
static GEO_POLICY: HashMap<u32, u32> = HashMap::with_max_entries(512, 0);

#[xdp]
pub fn neko_firewall(ctx: XdpContext) -> u32 {
    match try_neko_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_neko_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let ethhdr: *const EthHdr = ptr_at(start, end, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(start, end, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };
    let proto_num = proto_to_num(proto);

    let src_host = u32::from_be(src_addr);
    if unsafe { ALLOWED_IPS.get(&src_host) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    let geo_key = Key::new(32, src_addr);
    if let Some(&geo_id) = unsafe { GEO_MAP.get(&geo_key) } {
        if let Some(&action) = unsafe { GEO_POLICY.get(&geo_id) } {
            if action == ACTION_DROP {
                log_event(ctx, src_addr, dst_addr, 0, 0, proto_num, ACTION_DROP as u8);
                return Ok(xdp_action::XDP_DROP);
            }
            if action == ACTION_PASS {
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    let proto_wildcard = (proto_num as u32) << 16;
    if unsafe { ALLOWED_PORTS.get(&proto_wildcard) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    let (src_port, dst_port, ct_src_port, ct_dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(start, end, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let raw_src = unsafe { (*tcphdr).source };
            let raw_dst = unsafe { (*tcphdr).dest };
            (u16::from_be(raw_src), u16::from_be(raw_dst), raw_src, raw_dst)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(start, end, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let raw_src = unsafe { (*udphdr).source };
            let raw_dst = unsafe { (*udphdr).dest };
            (u16::from_be(raw_src), u16::from_be(raw_dst), raw_src, raw_dst)
        }
        IpProto::Icmp => {
            let icmp_type_ptr: *const u8 = ptr_at(start, end, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let icmp_type = unsafe { *icmp_type_ptr };
            (0u16, icmp_type as u16, 0u16, 0u16)
        }
        _ => return Ok(xdp_action::XDP_DROP),
    };

    if dst_port > 0 {
        let port_key = (proto_num as u32) << 16 | dst_port as u32;
        if unsafe { ALLOWED_PORTS.get(&port_key) }.is_some() {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let ct_key = ConnTrackKey {
        src_ip: src_addr,
        dst_ip: dst_addr,
        src_port: ct_src_port,
        dst_port: ct_dst_port,
        proto: proto_num,
        _pad: [0; 3],
    };

    if let Some(&last_seen) = unsafe { CONNTRACK.get(&ct_key) } {
        let now = unsafe { bpf_ktime_get_ns() };
        if now.wrapping_sub(last_seen) < CONNTRACK_TIMEOUT_NS {
            let _ = CONNTRACK.insert(&ct_key, &now, 0);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    log_event(ctx, src_addr, dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
    Ok(xdp_action::XDP_DROP)
}

#[classifier]
pub fn neko_egress(ctx: TcContext) -> i32 {
    match try_neko_egress(&ctx) {
        Ok(action) => action,
        Err(_) => 0,
    }
}

fn try_neko_egress(ctx: &TcContext) -> Result<i32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let ethhdr: *const EthHdr = ptr_at(start, end, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(0),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(start, end, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };

    let (raw_src_port, raw_dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(start, end, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (unsafe { (*tcphdr).source }, unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(start, end, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (unsafe { (*udphdr).source }, unsafe { (*udphdr).dest })
        }
        IpProto::Icmp => (0u16, 0u16),
        _ => return Ok(0),
    };

    let ct_key = ConnTrackKey {
        src_ip: dst_addr,
        dst_ip: src_addr,
        src_port: raw_dst_port,
        dst_port: raw_src_port,
        proto: proto_to_num(proto),
        _pad: [0; 3],
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let _ = CONNTRACK.insert(&ct_key, &now, 0);

    Ok(0)
}

#[inline(always)]
fn proto_to_num(proto: IpProto) -> u8 {
    match proto {
        IpProto::Tcp => 6,
        IpProto::Udp => 17,
        IpProto::Icmp => 1,
        _ => 0,
    }
}

#[inline(always)]
fn log_event(
    ctx: &XdpContext,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
) {
    let log = PacketLog {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        action,
        _padding: [0; 2],
    };
    EVENTS.output(ctx, &log, 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
