#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use core::mem;
use neko_common::{PacketLog, ACTION_DROP};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static PORT_RULES: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[xdp]
pub fn neko_firewall(ctx: XdpContext) -> u32 {
    match try_neko_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_neko_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };

    // Check IP blocklist
    if let Some(&action) = unsafe { BLOCKLIST.get(&u32::from_be(src_addr)) } {
        if action == ACTION_DROP {
            log_event(ctx, src_addr, dst_addr, 0, 0, proto as u8, ACTION_DROP as u8);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Extract ports for TCP/UDP
    let (src_port, dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src = u16::from_be(unsafe { (*tcphdr).source });
            let dst = u16::from_be(unsafe { (*tcphdr).dest });
            (src, dst)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src = u16::from_be(unsafe { (*udphdr).source });
            let dst = u16::from_be(unsafe { (*udphdr).dest });
            (src, dst)
        }
        _ => (0u16, 0u16),
    };

    // Check port rules: key = (proto << 16) | port
    if dst_port != 0 {
        let proto_num: u8 = match proto {
            IpProto::Tcp => 6,
            IpProto::Udp => 17,
            _ => 0,
        };
        let port_key = (proto_num as u32) << 16 | dst_port as u32;
        if let Some(&action) = unsafe { PORT_RULES.get(&port_key) } {
            if action == ACTION_DROP {
                log_event(ctx, src_addr, dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
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
