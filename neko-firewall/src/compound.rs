use anyhow::{bail, Result};
use log::info;
use neko_common::{
    CompoundRule, MATCH_ASN, MATCH_COUNTRY, MATCH_IP, MATCH_PORT, MATCH_PROTO, MAX_COMPOUND_RULES,
};

use crate::{
    config::{CompoundRuleEntry, Config},
    geo,
    rule::{self, CidrAddr},
};

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
        if !is_any_proto(p) {
            bpf_rule.proto = parse_proto(p)?;
            bpf_rule.match_fields |= MATCH_PROTO;
        }
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
        if matches!(proto, Some(p) if is_any_proto(p)) {
            bail!("--proto any must be combined with --port, --country, --asn, or --ip");
        }
        bail!("At least one condition is required (--proto, --port, --country, --asn, --ip)");
    }

    let mut cfg = Config::load()?;
    if cfg.rules.len() as u32 >= MAX_COMPOUND_RULES {
        bail!("No free rule slots (max {})", MAX_COMPOUND_RULES);
    }
    let index = cfg.rules.len() as u32;
    let _ = bpf_rule;
    cfg.add_compound_rule(CompoundRuleEntry::new(
        action, proto, port, country, asn, ip,
    ));
    cfg.save()?;
    cfg.apply_compound_rules()?;
    info!("Added compound rule at slot {}", index);
    Ok(index)
}

pub fn remove_rule(index: u32) -> Result<()> {
    if index >= MAX_COMPOUND_RULES {
        bail!("Index out of range (max {})", MAX_COMPOUND_RULES - 1);
    }
    let mut cfg = Config::load()?;
    if index as usize >= cfg.rules.len() {
        bail!("Rule slot {} is empty", index);
    }
    cfg.remove_compound_rule(index as usize);
    cfg.save()?;
    cfg.apply_compound_rules()?;

    Ok(())
}

pub fn list_rules() -> Result<()> {
    let cfg = Config::load()?;
    let mut count = 0u32;
    for (i, entry) in cfg.rules.iter().enumerate() {
        let action_str = if entry.action.eq_ignore_ascii_case("allow") {
            "ALLOW"
        } else {
            "DROP"
        };
        let mut parts = Vec::new();
        if let Some(proto) = &entry.proto {
            parts.push(format!("proto={}", proto));
        }
        if let Some(port) = entry.port {
            parts.push(format!("port={}", port));
        }
        if let Some(country) = &entry.country {
            parts.push(format!("country={}", country));
        }
        if let Some(asn) = entry.asn {
            parts.push(format!("asn={}", asn));
        }
        if let Some(ip) = &entry.ip {
            parts.push(format!("ip={}", ip));
        }
        println!("  [{}] {} {}", i, action_str, parts.join(" "));
        count += 1;
    }
    if count == 0 {
        println!("  (none)");
    }
    Ok(())
}

fn parse_proto(proto: &str) -> Result<u8> {
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

fn is_any_proto(proto: &str) -> bool {
    proto.eq_ignore_ascii_case("any")
}
