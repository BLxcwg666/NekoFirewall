use anyhow::{bail, Context, Result};
use aya::maps::{HashMap, Map, MapData};
use log::info;
use neko_common::{ConnTrackKey, ACTION_PASS};
use std::net::Ipv4Addr;

use crate::loader;

pub fn allow_ip(addr: Ipv4Addr) -> Result<()> {
    let mut map = loader::open_pinned_hashmap("ALLOWED_IPS")?;
    let ip: u32 = addr.into();
    map.insert(ip, ACTION_PASS, 0)?;
    info!("Whitelisted IP: {}", addr);
    Ok(())
}

pub fn block_ip(addr: Ipv4Addr) -> Result<()> {
    let mut map = loader::open_pinned_hashmap("ALLOWED_IPS")?;
    let ip: u32 = addr.into();
    map.remove(&ip)?;
    info!("Removed IP from whitelist: {}", addr);
    Ok(())
}

pub fn allow_port(proto: &str, port: u16) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16 | port as u32;
    let mut map = loader::open_pinned_hashmap("ALLOWED_PORTS")?;
    map.insert(key, ACTION_PASS, 0)?;
    info!("Whitelisted port: {}/{}", port, proto);
    Ok(())
}

pub fn block_port(proto: &str, port: u16) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16 | port as u32;
    let mut map = loader::open_pinned_hashmap("ALLOWED_PORTS")?;
    map.remove(&key)?;
    info!("Removed port from whitelist: {}/{}", port, proto);
    Ok(())
}

pub fn list_rules() -> Result<()> {
    println!("=== Whitelisted IPs ===");
    {
        let map = loader::open_pinned_hashmap("ALLOWED_IPS")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (ip, _) = res.context("Failed to read entry")?;
            println!("  ALLOW {}", Ipv4Addr::from(ip));
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        }
    }

    println!("\n=== Whitelisted Ports ===");
    {
        let map = loader::open_pinned_hashmap("ALLOWED_PORTS")?;
        let mut count = 0u32;
        for res in map.iter() {
            let (key, _) = res.context("Failed to read entry")?;
            let proto_num = (key >> 16) as u8;
            let port = (key & 0xFFFF) as u16;
            let proto_str = match proto_num {
                6 => "tcp",
                17 => "udp",
                _ => "unknown",
            };
            println!("  ALLOW {}/{}", port, proto_str);
            count += 1;
        }
        if count == 0 {
            println!("  (none)");
        }
    }

    Ok(())
}

pub fn show_conntrack() -> Result<()> {
    let pin = "/sys/fs/bpf/neko/CONNTRACK";
    let data = MapData::from_pin(pin)
        .map_err(|e| anyhow::anyhow!("Failed to open CONNTRACK: {} (is the firewall running?)", e))?;
    let map = Map::HashMap(data);
    let ct: HashMap<_, ConnTrackKey, u64> = HashMap::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open CONNTRACK as HashMap: {:?}", e))?;

    println!("=== Active Connections ===");
    let mut count = 0u32;
    for res in ct.iter() {
        let (key, _ts) = res.context("Failed to read conntrack entry")?;
        let src = Ipv4Addr::from(u32::from_be(key.src_ip));
        let dst = Ipv4Addr::from(u32::from_be(key.dst_ip));
        let src_port = u16::from_be(key.src_port);
        let dst_port = u16::from_be(key.dst_port);
        let proto = match key.proto {
            6 => "TCP",
            17 => "UDP",
            _ => "???",
        };
        println!("  {} {}:{} -> {}:{}", proto, src, src_port, dst, dst_port);
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
        _ => bail!("Unsupported protocol: {} (use tcp or udp)", proto),
    }
}
