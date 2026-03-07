use anyhow::{bail, Context, Result};
use aya::maps::Array;
use log::info;
use neko_common::{
    CompoundRule, ACTION_DROP, ACTION_PASS, MAX_COMPOUND_RULES,
    MATCH_ASN, MATCH_COUNTRY, MATCH_IP, MATCH_PORT, MATCH_PROTO,
};
use std::net::Ipv4Addr;

use crate::{config::{CompoundRuleEntry, Config}, geo, loader};

pub fn add_rule(
    action: u32,
    proto: Option<&str>,
    port: Option<u16>,
    country: Option<&str>,
    asn: Option<u32>,
    ip: Option<Ipv4Addr>,
) -> Result<u32> {
    let mut rule = CompoundRule {
        match_fields: 0,
        action,
        proto: 0,
        _pad: [0],
        port: 0,
        country_id: 0,
        asn_id: 0,
        src_ip: 0,
    };

    if let Some(p) = proto {
        rule.proto = parse_proto(p)?;
        rule.match_fields |= MATCH_PROTO;
    }
    if let Some(p) = port {
        rule.port = p;
        rule.match_fields |= MATCH_PORT;
    }
    if let Some(c) = country {
        rule.country_id = geo::country_to_id(c)?;
        rule.match_fields |= MATCH_COUNTRY;
    }
    if let Some(a) = asn {
        rule.asn_id = 0x80000000 | a;
        rule.match_fields |= MATCH_ASN;
    }
    if let Some(addr) = ip {
        rule.src_ip = u32::from(addr).to_be();
        rule.match_fields |= MATCH_IP;
    }

    if rule.match_fields == 0 {
        bail!("At least one condition is required (--proto, --port, --country, --asn, --ip)");
    }

    let mut map = open_rules_array()?;
    for i in 0..MAX_COMPOUND_RULES {
        let existing = map.get(&i, 0).context("Failed to read RULES slot")?;
        if existing.match_fields == 0 {
            map.set(i, rule, 0)
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
    let empty = CompoundRule {
        match_fields: 0,
        action: 0,
        proto: 0,
        _pad: [0],
        port: 0,
        country_id: 0,
        asn_id: 0,
        src_ip: 0,
    };
    let mut map = open_rules_array()?;
    map.set(index, empty, 0)
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
            parts.push(format!(
                "ip={}",
                Ipv4Addr::from(u32::from_be(rule.src_ip))
            ));
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
        _ => bail!("Unsupported protocol: {} (use tcp, udp, or icmp)", proto),
    }
}

fn proto_name(num: u8) -> &'static str {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    }
}
