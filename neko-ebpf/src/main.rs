#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerfEventArray},
    programs::{TcContext, XdpContext},
};
use aya_ebpf::maps::lpm_trie::Key;
use core::mem;
use neko_common::{
    CompoundRule, ConnTrackKey, ConnTrackKey6, PacketLog,
    ACTION_DROP, ACTION_PASS, MAX_COMPOUND_RULES,
    MATCH_ASN, MATCH_COUNTRY, MATCH_IP, MATCH_PORT, MATCH_PROTO,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const CONNTRACK_TIMEOUT_NS: u64 = 300_000_000_000;

#[map]
static ALLOWED_IPS: LpmTrie<u32, u32> = LpmTrie::pinned(65536, 0);

#[map]
static CONNTRACK: LruHashMap<ConnTrackKey, u64> = LruHashMap::pinned(65536, 0);

#[map]
static GEO_COUNTRY_MAP: LpmTrie<u32, u32> = LpmTrie::pinned(524288, 0);

#[map]
static GEO_ASN_MAP: LpmTrie<u32, u32> = LpmTrie::pinned(524288, 0);

#[map]
static ALLOWED_IPS6: LpmTrie<[u8; 16], u32> = LpmTrie::pinned(65536, 0);

#[map]
static CONNTRACK6: LruHashMap<ConnTrackKey6, u64> = LruHashMap::pinned(65536, 0);

#[map]
static GEO_COUNTRY_MAP6: LpmTrie<[u8; 16], u32> = LpmTrie::pinned(524288, 0);

#[map]
static GEO_ASN_MAP6: LpmTrie<[u8; 16], u32> = LpmTrie::pinned(524288, 0);

#[map]
static ALLOWED_PORTS: HashMap<u32, u32> = HashMap::pinned(1024, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::pinned(0);

#[map]
static GEO_POLICY: HashMap<u32, u32> = HashMap::pinned(512, 0);

#[map]
static RULES: Array<CompoundRule> = Array::pinned(MAX_COMPOUND_RULES, 0);

#[xdp]
pub fn neko_firewall(ctx: XdpContext) -> u32 {
    match try_neko_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_DROP,
    }
}

#[inline(always)]
fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = mem::size_of::<T>();
    let ptr = start.checked_add(offset).ok_or(())?;
    let next = ptr.checked_add(len).ok_or(())?;
    if next > end {
        return Err(());
    }
    Ok(ptr as *const T)
}

#[inline(always)]
fn ipv4_header_len(ipv4hdr: *const Ipv4Hdr) -> Result<usize, ()> {
    let ihl = unsafe { (*ipv4hdr).ihl() };
    if ihl != 5 {
        return Err(());
    }
    Ok(Ipv4Hdr::LEN)
}

fn try_neko_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let ethhdr: *const EthHdr = ptr_at(start, end, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => try_firewall_v4(ctx, start, end),
        EtherType::Ipv6 => try_firewall_v6(ctx, start, end),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn try_firewall_v4(ctx: &XdpContext, start: usize, end: usize) -> Result<u32, ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(start, end, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };
    let transport_offset = EthHdr::LEN + ipv4_header_len(ipv4hdr)?;
    let proto_num = proto_to_num(proto);

    // --- IP whitelist (LPM/CIDR) ---
    let ip_key = Key::new(32, src_addr);
    if ALLOWED_IPS.get(&ip_key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Extract ports ---
    let (src_port, dst_port, ct_src_port, ct_dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(start, end, transport_offset)?;
            let raw_src = unsafe { (*tcphdr).source };
            let raw_dst = unsafe { (*tcphdr).dest };
            (u16::from_be(raw_src), u16::from_be(raw_dst), raw_src, raw_dst)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(start, end, transport_offset)?;
            let raw_src = unsafe { (*udphdr).source };
            let raw_dst = unsafe { (*udphdr).dest };
            (u16::from_be(raw_src), u16::from_be(raw_dst), raw_src, raw_dst)
        }
        IpProto::Icmp => {
            let icmp_type_ptr: *const u8 = ptr_at(start, end, transport_offset)?;
            let icmp_type = unsafe { *icmp_type_ptr };
            (0u16, icmp_type as u16, 0u16, 0u16)
        }
        _ => return Ok(xdp_action::XDP_DROP),
    };

    let geo_key = Key::new(32, src_addr);
    let country_id = GEO_COUNTRY_MAP.get(&geo_key).copied().unwrap_or(0);
    let asn_id = GEO_ASN_MAP.get(&geo_key).copied().unwrap_or(0);

    for i in 0..MAX_COMPOUND_RULES {
        if let Some(rule) = RULES.get(i) {
            let mf = rule.match_fields;
            if mf == 0 {
                continue;
            }
            if rule.family == 6 {
                continue;
            }
            let mut matched = true;
            if mf & MATCH_PROTO != 0 && rule.proto != proto_num {
                matched = false;
            }
            if mf & MATCH_PORT != 0 && rule.port != dst_port {
                matched = false;
            }
            if mf & MATCH_COUNTRY != 0 && rule.country_id != country_id {
                matched = false;
            }
            if mf & MATCH_ASN != 0 && rule.asn_id != asn_id {
                matched = false;
            }
            if mf & MATCH_IP != 0 {
                let pl = rule.prefix_len;
                if pl > 0 && pl <= 32 {
                    let mask = if pl >= 32 {
                        !0u32
                    } else {
                        !0u32 << (32 - pl as u32)
                    };
                    let mask_be = mask.to_be();
                    if (src_addr & mask_be) != (u32::from_ne_bytes([rule.src_ip[0], rule.src_ip[1], rule.src_ip[2], rule.src_ip[3]]) & mask_be) {
                        matched = false;
                    }
                }
            }
            if matched {
                if rule.action == ACTION_DROP {
                    log_event_v4(ctx, src_addr, dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                    return Ok(xdp_action::XDP_DROP);
                }
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    let mut geo_allowed = false;
    if country_id != 0 {
        if let Some(&action) = unsafe { GEO_POLICY.get(&country_id) } {
            if action == ACTION_DROP {
                log_event_v4(ctx, src_addr, dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                return Ok(xdp_action::XDP_DROP);
            }
            if action == ACTION_PASS {
                geo_allowed = true;
            }
        }
    }
    if asn_id != 0 {
        if let Some(&action) = unsafe { GEO_POLICY.get(&asn_id) } {
            if action == ACTION_DROP {
                log_event_v4(ctx, src_addr, dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                return Ok(xdp_action::XDP_DROP);
            }
            if action == ACTION_PASS {
                geo_allowed = true;
            }
        }
    }
    if geo_allowed {
        return Ok(xdp_action::XDP_PASS);
    }

    let proto_wildcard = (proto_num as u32) << 16;
    if unsafe { ALLOWED_PORTS.get(&proto_wildcard) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }
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
        let _ = CONNTRACK.remove(&ct_key);
    }

    log_event_v4(ctx, src_addr, dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
    Ok(xdp_action::XDP_DROP)
}

fn try_firewall_v6(ctx: &XdpContext, start: usize, end: usize) -> Result<u32, ()> {
    let ipv6hdr: *const Ipv6Hdr = ptr_at(start, end, EthHdr::LEN)?;
    let src_addr: [u8; 16] = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };
    let dst_addr: [u8; 16] = unsafe { (*ipv6hdr).dst_addr.in6_u.u6_addr8 };
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };
    let transport_offset = EthHdr::LEN + Ipv6Hdr::LEN;

    let proto_num = match next_hdr {
        IpProto::Tcp => 6u8,
        IpProto::Udp => 17u8,
        IpProto::Ipv6Icmp => 58u8,
        _ => return Ok(xdp_action::XDP_DROP),
    };

    let ip_key = Key::new(128, src_addr);
    if ALLOWED_IPS6.get(&ip_key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    let (src_port, dst_port, ct_src_port, ct_dst_port) = match next_hdr {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(start, end, transport_offset)?;
            let raw_src = unsafe { (*tcphdr).source };
            let raw_dst = unsafe { (*tcphdr).dest };
            (u16::from_be(raw_src), u16::from_be(raw_dst), raw_src, raw_dst)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(start, end, transport_offset)?;
            let raw_src = unsafe { (*udphdr).source };
            let raw_dst = unsafe { (*udphdr).dest };
            (u16::from_be(raw_src), u16::from_be(raw_dst), raw_src, raw_dst)
        }
        IpProto::Ipv6Icmp => {
            let icmp_type_ptr: *const u8 = ptr_at(start, end, transport_offset)?;
            let icmp_type = unsafe { *icmp_type_ptr };
            (0u16, icmp_type as u16, 0u16, 0u16)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let geo_key = Key::new(128, src_addr);
    let country_id = GEO_COUNTRY_MAP6.get(&geo_key).copied().unwrap_or(0);
    let asn_id = GEO_ASN_MAP6.get(&geo_key).copied().unwrap_or(0);

    for i in 0..MAX_COMPOUND_RULES {
        if let Some(rule) = RULES.get(i) {
            let mf = rule.match_fields;
            if mf == 0 {
                continue;
            }
            if rule.family == 4 {
                continue;
            }
            let mut matched = true;
            if mf & MATCH_PROTO != 0 && rule.proto != proto_num {
                matched = false;
            }
            if mf & MATCH_PORT != 0 && rule.port != dst_port {
                matched = false;
            }
            if mf & MATCH_COUNTRY != 0 && rule.country_id != country_id {
                matched = false;
            }
            if mf & MATCH_ASN != 0 && rule.asn_id != asn_id {
                matched = false;
            }
            if mf & MATCH_IP != 0 {
                if !ipv6_prefix_match(&src_addr, &rule.src_ip, rule.prefix_len) {
                    matched = false;
                }
            }
            if matched {
                if rule.action == ACTION_DROP {
                    log_event_v6(ctx, &src_addr, &dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                    return Ok(xdp_action::XDP_DROP);
                }
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    let mut geo_allowed = false;
    if country_id != 0 {
        if let Some(&action) = unsafe { GEO_POLICY.get(&country_id) } {
            if action == ACTION_DROP {
                log_event_v6(ctx, &src_addr, &dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                return Ok(xdp_action::XDP_DROP);
            }
            if action == ACTION_PASS {
                geo_allowed = true;
            }
        }
    }
    if asn_id != 0 {
        if let Some(&action) = unsafe { GEO_POLICY.get(&asn_id) } {
            if action == ACTION_DROP {
                log_event_v6(ctx, &src_addr, &dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
                return Ok(xdp_action::XDP_DROP);
            }
            if action == ACTION_PASS {
                geo_allowed = true;
            }
        }
    }
    if geo_allowed {
        return Ok(xdp_action::XDP_PASS);
    }

    let proto_wildcard = (proto_num as u32) << 16;
    if unsafe { ALLOWED_PORTS.get(&proto_wildcard) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }
    if dst_port > 0 {
        let port_key = (proto_num as u32) << 16 | dst_port as u32;
        if unsafe { ALLOWED_PORTS.get(&port_key) }.is_some() {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let ct_key = ConnTrackKey6 {
        src_ip: src_addr,
        dst_ip: dst_addr,
        src_port: ct_src_port,
        dst_port: ct_dst_port,
        proto: proto_num,
        _pad: [0; 3],
    };
    if let Some(&last_seen) = unsafe { CONNTRACK6.get(&ct_key) } {
        let now = unsafe { bpf_ktime_get_ns() };
        if now.wrapping_sub(last_seen) < CONNTRACK_TIMEOUT_NS {
            let _ = CONNTRACK6.insert(&ct_key, &now, 0);
            return Ok(xdp_action::XDP_PASS);
        }
        let _ = CONNTRACK6.remove(&ct_key);
    }

    log_event_v6(ctx, &src_addr, &dst_addr, src_port, dst_port, proto_num, ACTION_DROP as u8);
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
        EtherType::Ipv4 => try_egress_v4(start, end),
        EtherType::Ipv6 => try_egress_v6(start, end),
        _ => Ok(0),
    }
}

fn try_egress_v4(start: usize, end: usize) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(start, end, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };
    let transport_offset = EthHdr::LEN + ipv4_header_len(ipv4hdr)?;

    let (raw_src_port, raw_dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(start, end, transport_offset)?;
            (unsafe { (*tcphdr).source }, unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(start, end, transport_offset)?;
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

fn try_egress_v6(start: usize, end: usize) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = ptr_at(start, end, EthHdr::LEN)?;
    let src_addr: [u8; 16] = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };
    let dst_addr: [u8; 16] = unsafe { (*ipv6hdr).dst_addr.in6_u.u6_addr8 };
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };
    let transport_offset = EthHdr::LEN + Ipv6Hdr::LEN;

    let (raw_src_port, raw_dst_port) = match next_hdr {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(start, end, transport_offset)?;
            (unsafe { (*tcphdr).source }, unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(start, end, transport_offset)?;
            (unsafe { (*udphdr).source }, unsafe { (*udphdr).dest })
        }
        IpProto::Ipv6Icmp => (0u16, 0u16),
        _ => return Ok(0),
    };

    let proto_num = match next_hdr {
        IpProto::Tcp => 6u8,
        IpProto::Udp => 17u8,
        IpProto::Ipv6Icmp => 58u8,
        _ => return Ok(0),
    };

    let ct_key = ConnTrackKey6 {
        src_ip: dst_addr,
        dst_ip: src_addr,
        src_port: raw_dst_port,
        dst_port: raw_src_port,
        proto: proto_num,
        _pad: [0; 3],
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let _ = CONNTRACK6.insert(&ct_key, &now, 0);

    Ok(0)
}

#[inline(always)]
fn proto_to_num(proto: IpProto) -> u8 {
    match proto {
        IpProto::Tcp => 6,
        IpProto::Udp => 17,
        IpProto::Icmp => 1,
        IpProto::Ipv6Icmp => 58,
        _ => 0,
    }
}

#[inline(always)]
fn ipv6_prefix_match(addr: &[u8; 16], rule_addr: &[u8; 16], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let pl = prefix_len as u32;

    let a0 = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
    let r0 = u32::from_be_bytes([rule_addr[0], rule_addr[1], rule_addr[2], rule_addr[3]]);
    if pl >= 32 {
        if a0 != r0 { return false; }
    } else {
        let mask = !0u32 << (32 - pl);
        return (a0 & mask) == (r0 & mask);
    }

    let a1 = u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]);
    let r1 = u32::from_be_bytes([rule_addr[4], rule_addr[5], rule_addr[6], rule_addr[7]]);
    if pl >= 64 {
        if a1 != r1 { return false; }
    } else {
        let mask = !0u32 << (64 - pl);
        return (a1 & mask) == (r1 & mask);
    }

    let a2 = u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]);
    let r2 = u32::from_be_bytes([rule_addr[8], rule_addr[9], rule_addr[10], rule_addr[11]]);
    if pl >= 96 {
        if a2 != r2 { return false; }
    } else {
        let mask = !0u32 << (96 - pl);
        return (a2 & mask) == (r2 & mask);
    }

    let a3 = u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]);
    let r3 = u32::from_be_bytes([rule_addr[12], rule_addr[13], rule_addr[14], rule_addr[15]]);
    if pl >= 128 {
        return a3 == r3;
    }
    let mask = !0u32 << (128 - pl);
    (a3 & mask) == (r3 & mask)
}

#[inline(always)]
fn log_event_v4(
    ctx: &XdpContext,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
) {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    let src_bytes = src_addr.to_ne_bytes();
    let dst_bytes = dst_addr.to_ne_bytes();
    src[0] = src_bytes[0]; src[1] = src_bytes[1]; src[2] = src_bytes[2]; src[3] = src_bytes[3];
    dst[0] = dst_bytes[0]; dst[1] = dst_bytes[1]; dst[2] = dst_bytes[2]; dst[3] = dst_bytes[3];

    let log = PacketLog {
        src_addr: src,
        dst_addr: dst,
        src_port,
        dst_port,
        protocol,
        action,
        family: 4,
        _padding: [0; 1],
    };
    EVENTS.output(ctx, &log, 0);
}

#[inline(always)]
fn log_event_v6(
    ctx: &XdpContext,
    src_addr: &[u8; 16],
    dst_addr: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
) {
    let log = PacketLog {
        src_addr: *src_addr,
        dst_addr: *dst_addr,
        src_port,
        dst_port,
        protocol,
        action,
        family: 6,
        _padding: [0; 1],
    };
    EVENTS.output(ctx, &log, 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
