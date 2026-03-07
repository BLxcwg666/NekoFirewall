use anyhow::{bail, Context, Result};
use aya::maps::lpm_trie::Key;
use aya::maps::HashMap;
use log::info;
use neko_common::{ConnTrackKey, ACTION_PASS};
use std::net::Ipv4Addr;

use crate::config::Config;
use crate::loader;

pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let ip: Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("Invalid IP: {}", ip_str))?;
        let prefix: u8 = prefix_str
            .parse()
            .with_context(|| format!("Invalid prefix: {}", prefix_str))?;
        if prefix > 32 {
            bail!("Prefix length must be 0-32, got {}", prefix);
        }
        Ok((ip, prefix))
    } else {
        let ip: Ipv4Addr = s
            .parse()
            .with_context(|| format!("Invalid IP or CIDR: {}", s))?;
        Ok((ip, 32))
    }
}

pub fn allow_ip(cidr: &str) -> Result<()> {
    let (ip, prefix) = parse_cidr(cidr)?;
    let mut map = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
    let key = Key::new(prefix as u32, u32::from(ip).to_be());
    map.insert(&key, ACTION_PASS, 0)?;
    info!("Whitelisted: {}", cidr);

    let mut cfg = Config::load()?;
    cfg.add_ip(cidr);
    cfg.save()?;
    Ok(())
}

pub fn block_ip(cidr: &str) -> Result<()> {
    let (ip, prefix) = parse_cidr(cidr)?;
    let mut map = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
    let key = Key::new(prefix as u32, u32::from(ip).to_be());
    map.remove(&key)?;
    info!("Removed from whitelist: {}", cidr);

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
    let label = if proto_num == 1 { "type" } else { "port" };
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

fn proto_name(num: u8) -> &'static str {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    }
}

pub fn list_rules() -> Result<()> {
    println!("=== Whitelisted IPs ===");
    {
        let map = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (key, _) = res.context("Failed to read entry")?;
            let ip = Ipv4Addr::from(u32::from_be(key.data));
            let prefix = key.prefix_len;
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

    println!("\n=== Whitelisted Ports / Protocols ===");
    {
        let map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (key, _) = res.context("Failed to read entry")?;
            let proto_num = (key >> 16) as u8;
            let port = (key & 0xFFFF) as u16;
            let name = proto_name(proto_num);
            if port == 0 {
                println!("  ALLOW proto {}", name);
            } else if proto_num == 1 {
                println!("  ALLOW icmp type {}", port);
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
    let ct: HashMap<_, ConnTrackKey, u64> = loader::open_pinned_hashmap("CONNTRACK")?;

    println!("=== Active Connections ===");
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

    Ok(())
}

fn parse_proto(proto: &str) -> Result<u8> {
    match proto.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        _ => bail!("Unsupported protocol: {} (use tcp, udp, or icmp)", proto),
    }
}
