use anyhow::{bail, Context, Result};
use aya::maps::Array;
use log::info;
use neko_common::{
    CompoundRule, ACTION_PASS, MAX_COMPOUND_RULES,
    MATCH_ASN, MATCH_COUNTRY, MATCH_IP, MATCH_PORT, MATCH_PROTO,
};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{config::{CompoundRuleEntry, Config}, geo, loader, rule::{self, CidrAddr}};

pub fn add_rule(
    action: u32,
    proto: Option<&str>,
    port: Option<u16>,
    country: Option<&str>,
    asn: Option<u32>,
    ip: Option<&str>,
) -> Result<u32> {
    let mut bpf_rule = CompoundRule::default();
    bpf_rule.action = action;

    if let Some(p) = proto {
        bpf_rule.proto = parse_proto(p)?;
        bpf_rule.match_fields |= MATCH_PROTO;
    }
    if let Some(p) = port {
        bpf_rule.port = p;
        bpf_rule.match_fields |= MATCH_PORT;
    }
    if let Some(c) = country {
        bpf_rule.country_id = geo::country_to_id(c)?;
        bpf_rule.match_fields |= MATCH_COUNTRY;
    }
    if let Some(a) = asn {
        bpf_rule.asn_id = 0x80000000 | a;
        bpf_rule.match_fields |= MATCH_ASN;
    }
    if let Some(cidr) = ip {
        match rule::parse_cidr(cidr)? {
            CidrAddr::V4(addr, prefix) => {
                let bytes = u32::from(addr).to_be().to_ne_bytes();
                bpf_rule.src_ip[0] = bytes[0];
                bpf_rule.src_ip[1] = bytes[1];
                bpf_rule.src_ip[2] = bytes[2];
                bpf_rule.src_ip[3] = bytes[3];
                bpf_rule.prefix_len = prefix;
                bpf_rule.family = 4;
            }
            CidrAddr::V6(addr, prefix) => {
                bpf_rule.src_ip = addr.octets();
                bpf_rule.prefix_len = prefix;
                bpf_rule.family = 6;
            }
        }
        bpf_rule.match_fields |= MATCH_IP;
    }

    if bpf_rule.match_fields == 0 {
        bail!("At least one condition is required (--proto, --port, --country, --asn, --ip)");
    }

    let mut map = open_rules_array()?;
    for i in 0..MAX_COMPOUND_RULES {
        let existing = map.get(&i, 0).context("Failed to read RULES slot")?;
        if existing.match_fields == 0 {
            map.set(i, bpf_rule, 0)
                .map_err(|e| anyhow::anyhow!("Failed to insert rule: {:?}", e))?;
            info!("Added compound rule at slot {}", i);

            let mut cfg = Config::load()?;
            cfg.add_compound_rule(CompoundRuleEntry::new(action, proto, port, country, asn, ip));
            cfg.save()?;

            return Ok(i);
        }
    }
    bail!("No free rule slots (max {})", MAX_COMPOUND_RULES);
}

pub fn remove_rule(index: u32) -> Result<()> {
    if index >= MAX_COMPOUND_RULES {
        bail!("Index out of range (max {})", MAX_COMPOUND_RULES - 1);
    }
    let mut map = open_rules_array()?;
    map.set(index, CompoundRule::default(), 0)
        .map_err(|e| anyhow::anyhow!("Failed to clear rule slot {}: {:?}", index, e))?;

    let mut cfg = Config::load()?;
    cfg.remove_compound_rule(index as usize);
    cfg.save()?;

    Ok(())
}

pub fn list_rules() -> Result<()> {
    let map = open_rules_array()?;
    let mut count = 0u32;
    for i in 0..MAX_COMPOUND_RULES {
        let rule = map.get(&i, 0).context("Failed to read RULES slot")?;
        if rule.match_fields == 0 {
            continue;
        }
        let action_str = if rule.action == ACTION_PASS {
            "ALLOW"
        } else {
            "DROP"
        };
        let mut parts = Vec::new();
        if rule.match_fields & MATCH_PROTO != 0 {
            parts.push(format!("proto={}", proto_name(rule.proto)));
        }
        if rule.match_fields & MATCH_PORT != 0 {
            parts.push(format!("port={}", rule.port));
        }
        if rule.match_fields & MATCH_COUNTRY != 0 {
            parts.push(format!("country={}", geo::id_to_country(rule.country_id)));
        }
        if rule.match_fields & MATCH_ASN != 0 {
            parts.push(format!("asn={}", rule.asn_id & 0x7FFFFFFF));
        }
        if rule.match_fields & MATCH_IP != 0 {
            let ip_str = if rule.family == 6 {
                let ip = Ipv6Addr::from(rule.src_ip);
                if rule.prefix_len < 128 {
                    format!("ip={}/{}", ip, rule.prefix_len)
                } else {
                    format!("ip={}", ip)
                }
            } else {
                let ip = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes([
                    rule.src_ip[0],
                    rule.src_ip[1],
                    rule.src_ip[2],
                    rule.src_ip[3],
                ])));
                if rule.prefix_len < 32 {
                    format!("ip={}/{}", ip, rule.prefix_len)
                } else {
                    format!("ip={}", ip)
                }
            };
            parts.push(ip_str);
        }
        println!("  [{}] {} {}", i, action_str, parts.join(" "));
        count += 1;
    }
    if count == 0 {
        println!("  (none)");
    }
    Ok(())
}

fn open_rules_array() -> Result<Array<aya::maps::MapData, CompoundRule>> {
    let map = loader::open_pinned_map("RULES")?;
    Array::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open RULES as Array: {:?}", e))
}

fn parse_proto(proto: &str) -> Result<u8> {
    match proto.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" | "ipv6-icmp" => Ok(58),
        _ => bail!("Unsupported protocol: {} (use tcp, udp, icmp, or icmpv6)", proto),
    }
}

fn proto_name(num: u8) -> &'static str {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "unknown",
    }
}
