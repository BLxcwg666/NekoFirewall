use anyhow::{bail, Context, Result};
use log::info;
use neko_common::ACTION_DROP;
use std::net::Ipv4Addr;

use crate::loader;

pub fn block_ip(addr: Ipv4Addr) -> Result<()> {
    let mut blocklist = loader::open_pinned_map("BLOCKLIST")?;
    let ip: u32 = addr.into();
    blocklist.insert(ip, ACTION_DROP, 0)?;
    info!("Blocked IP: {}", addr);
    Ok(())
}

pub fn allow_ip(addr: Ipv4Addr) -> Result<()> {
    let mut blocklist = loader::open_pinned_map("BLOCKLIST")?;
    let ip: u32 = addr.into();
    blocklist.remove(&ip)?;
    info!("Allowed IP: {}", addr);
    Ok(())
}

pub fn block_port(proto: &str, port: u16) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16 | port as u32;
    let mut port_rules = loader::open_pinned_map("PORT_RULES")?;
    port_rules.insert(key, ACTION_DROP, 0)?;
    info!("Blocked port: {}/{}", port, proto);
    Ok(())
}

pub fn allow_port(proto: &str, port: u16) -> Result<()> {
    let proto_num = parse_proto(proto)?;
    let key = (proto_num as u32) << 16 | port as u32;
    let mut port_rules = loader::open_pinned_map("PORT_RULES")?;
    port_rules.remove(&key)?;
    info!("Allowed port: {}/{}", port, proto);
    Ok(())
}

pub fn list_rules() -> Result<()> {
    println!("=== IP Blocklist ===");
    {
        let blocklist = loader::open_pinned_map("BLOCKLIST")?;
        let mut count = 0u32;
        for res in blocklist.iter() {
            let (ip, action) = res.context("Failed to read blocklist entry")?;
            let addr = Ipv4Addr::from(ip);
            let action_str = if action == ACTION_DROP { "DROP" } else { "PASS" };
            println!("  {} -> {}", addr, action_str);
            count += 1;
        }
        if count == 0 {
            println!("  (empty)");
        }
    }

    println!("\n=== Port Rules ===");
    {
        let port_rules = loader::open_pinned_map("PORT_RULES")?;
        let mut count = 0u32;
        for res in port_rules.iter() {
            let (key, action) = res.context("Failed to read port rule entry")?;
            let proto_num = (key >> 16) as u8;
            let port = (key & 0xFFFF) as u16;
            let proto_str = match proto_num {
                6 => "tcp",
                17 => "udp",
                _ => "unknown",
            };
            let action_str = if action == ACTION_DROP { "DROP" } else { "PASS" };
            println!("  {}/{} -> {}", port, proto_str, action_str);
            count += 1;
        }
        if count == 0 {
            println!("  (empty)");
        }
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
