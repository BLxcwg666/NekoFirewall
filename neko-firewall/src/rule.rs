use anyhow::{bail, Context, Result};
use aya::maps::lpm_trie::Key;
use aya::maps::HashMap;
use log::info;
use neko_common::{ConnTrackKey, ConnTrackKey6, ACTION_PASS};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::Config;
use crate::loader;

pub enum CidrAddr {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

pub fn parse_cidr(s: &str) -> Result<CidrAddr> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("Invalid IP: {}", ip_str))?;
        let prefix: u8 = prefix_str
            .parse()
            .with_context(|| format!("Invalid prefix: {}", prefix_str))?;
        match ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    bail!("IPv4 prefix length must be 0-32, got {}", prefix);
                }
                Ok(CidrAddr::V4(v4, prefix))
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    bail!("IPv6 prefix length must be 0-128, got {}", prefix);
                }
                Ok(CidrAddr::V6(v6, prefix))
            }
        }
    } else {
        let ip: IpAddr = s
            .parse()
            .with_context(|| format!("Invalid IP or CIDR: {}", s))?;
        match ip {
            IpAddr::V4(v4) => Ok(CidrAddr::V4(v4, 32)),
            IpAddr::V6(v6) => Ok(CidrAddr::V6(v6, 128)),
        }
    }
}

pub fn allow_ip(cidr: &str) -> Result<()> {
    match parse_cidr(cidr)? {
        CidrAddr::V4(ip, prefix) => {
            let mut map = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
            let key = Key::new(prefix as u32, u32::from(ip).to_be());
            map.insert(&key, ACTION_PASS, 0)?;
            info!("Whitelisted: {}", cidr);
        }
        CidrAddr::V6(ip, prefix) => {
            let mut map = loader::open_pinned_lpm_trie::<[u8; 16], u32>("ALLOWED_IPS6")?;
            let key = Key::new(prefix as u32, ip.octets());
            map.insert(&key, ACTION_PASS, 0)?;
            info!("Whitelisted: {}", cidr);
        }
    }

    let mut cfg = Config::load()?;
    cfg.add_ip(cidr);
    cfg.save()?;
    Ok(())
}

pub fn block_ip(cidr: &str) -> Result<()> {
    match parse_cidr(cidr)? {
        CidrAddr::V4(ip, prefix) => {
            let mut map = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
            let key = Key::new(prefix as u32, u32::from(ip).to_be());
            map.remove(&key)?;
            info!("Removed from whitelist: {}", cidr);
        }
        CidrAddr::V6(ip, prefix) => {
            let mut map = loader::open_pinned_lpm_trie::<[u8; 16], u32>("ALLOWED_IPS6")?;
            let key = Key::new(prefix as u32, ip.octets());
            map.remove(&key)?;
            info!("Removed from whitelist: {}", cidr);
        }
    }

    let mut cfg = Config::load()?;
    cfg.remove_ip(cidr);
    cfg.save()?;
    Ok(())
}

pub fn allow_port(proto: &str, port: u16) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16 | port as u32;
    let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
    map.insert(key, ACTION_PASS, 0)?;
    let label = if proto_num == 1 || proto_num == 58 {
        "type"
    } else {
        "port"
    };
    info!("Whitelisted {} {} {}", proto, label, port);

    let mut cfg = Config::load()?;
    cfg.add_port(proto, port);
    cfg.save()?;
    Ok(())
}

pub fn block_port(proto: &str, port: u16) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16 | port as u32;
    let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
    map.remove(&key)?;
    info!("Removed from whitelist: {} {}", proto, port);

    let mut cfg = Config::load()?;
    cfg.remove_port(proto, port);
    cfg.save()?;
    Ok(())
}

pub fn allow_proto(proto: &str) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16; // port=0 as wildcard
    let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
    map.insert(key, ACTION_PASS, 0)?;
    info!("Whitelisted protocol: {}", proto);

    let mut cfg = Config::load()?;
    cfg.add_proto(proto);
    cfg.save()?;
    Ok(())
}

pub fn block_proto(proto: &str) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16;
    let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
    map.remove(&key)?;
    info!("Removed protocol from whitelist: {}", proto);

    let mut cfg = Config::load()?;
    cfg.remove_proto(proto);
    cfg.save()?;
    Ok(())
}

pub fn proto_name(num: u8) -> &'static str {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "unknown",
    }
}

pub fn list_rules() -> Result<()> {
    println!("=== Whitelisted IPs (IPv4) ===");
    {
        let map = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (key, _) = res.context("Failed to read entry")?;
            let ip = Ipv4Addr::from(u32::from_be(key.data()));
            let prefix = key.prefix_len();
            if prefix == 32 {
                println!("  ALLOW {}", ip);
            } else {
                println!("  ALLOW {}/{}", ip, prefix);
            }
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        }
    }

    println!("\n=== Whitelisted IPs (IPv6) ===");
    {
        let map = loader::open_pinned_lpm_trie::<[u8; 16], u32>("ALLOWED_IPS6")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (key, _) = res.context("Failed to read entry")?;
            let ip = Ipv6Addr::from(key.data());
            let prefix = key.prefix_len();
            if prefix == 128 {
                println!("  ALLOW {}", ip);
            } else {
                println!("  ALLOW {}/{}", ip, prefix);
            }
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        }
    }

    println!("\n=== Whitelisted Ports / Protocols ===");
    {
        let map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (key, _) = res.context("Failed to read entry")?;
            let pnum = (key >> 16) as u8;
            let port = (key & 0xFFFF) as u16;
            let name = proto_name(pnum);
            if port == 0 {
                println!("  ALLOW proto {}", name);
            } else if pnum == 1 || pnum == 58 {
                println!("  ALLOW {} type {}", name, port);
            } else {
                println!("  ALLOW {}/{}", port, name);
            }
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        }
    }

    Ok(())
}

pub fn show_conntrack() -> Result<()> {
    println!("=== Active Connections (IPv4) ===");
    {
        let ct: HashMap<_, ConnTrackKey, u64> = loader::open_pinned_hashmap("CONNTRACK")?;
        let mut count = 0u32;
        for res in ct.iter() {
            let (key, _ts) = res.context("Failed to read conntrack entry")?;
            let src = Ipv4Addr::from(u32::from_be(key.src_ip));
            let dst = Ipv4Addr::from(u32::from_be(key.dst_ip));
            let src_port = u16::from_be(key.src_port);
            let dst_port = u16::from_be(key.dst_port);
            let proto = match key.proto {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "???",
            };
            if key.proto == 1 {
                println!("  {} {} <-> {}", proto, src, dst);
            } else {
                println!("  {} {}:{} -> {}:{}", proto, src, src_port, dst, dst_port);
            }
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        } else {
            println!("  ({} entries)", count);
        }
    }

    println!("\n=== Active Connections (IPv6) ===");
    {
        let ct: HashMap<_, ConnTrackKey6, u64> = loader::open_pinned_hashmap("CONNTRACK6")?;
        let mut count = 0u32;
        for res in ct.iter() {
            let (key, _ts) = res.context("Failed to read conntrack6 entry")?;
            let src = Ipv6Addr::from(key.src_ip);
            let dst = Ipv6Addr::from(key.dst_ip);
            let src_port = u16::from_be(key.src_port);
            let dst_port = u16::from_be(key.dst_port);
            let proto = match key.proto {
                6 => "TCP",
                17 => "UDP",
                58 => "ICMPv6",
                _ => "???",
            };
            if key.proto == 58 {
                println!("  {} {} <-> {}", proto, src, dst);
            } else {
                println!("  {} [{}]:{} -> [{}]:{}", proto, src, src_port, dst, dst_port);
            }
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        } else {
            println!("  ({} entries)", count);
        }
    }

    Ok(())
}

pub fn parse_proto(proto: &str) -> Result<u8> {
    match proto.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" | "ipv6-icmp" => Ok(58),
        _ => bail!(
            "Unsupported protocol: {} (use tcp, udp, icmp, or icmpv6)",
            proto
        ),
    }
}
