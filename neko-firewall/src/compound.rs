use anyhow::{bail, Result};
use log::info;
use neko_common::MAX_COMPOUND_RULES;

use crate::{
    config::{CompoundRuleEntry, Config},
    geo,
    rule,
};

pub fn add_rule(
    action: u32,
    proto: Option<&str>,
    port: Option<u16>,
    country: Option<&str>,
    asn: Option<u32>,
    ip: Option<&str>,
) -> Result<u32> {
    // Validate proto if specified and not "any"
    if let Some(p) = proto {
        if !p.eq_ignore_ascii_case("any") {
            rule::parse_proto(p)?;
        }
    }
    // Validate country code
    if let Some(c) = country {
        geo::country_to_id(c)?;
    }
    // Validate IP/CIDR
    if let Some(cidr) = ip {
        rule::parse_cidr(cidr)?;
    }

    let entry = CompoundRuleEntry::new(action, proto, port, country, asn, ip);

    // Validate the entry can produce a valid BPF rule
    if entry.to_bpf_rule().is_none() {
        if matches!(proto, Some(p) if p.eq_ignore_ascii_case("any")) {
            bail!("--proto any must be combined with --port, --country, --asn, or --ip");
        }
        bail!("At least one condition is required (--proto, --port, --country, --asn, --ip)");
    }

    let mut cfg = Config::load()?;
    if cfg.rules.len() as u32 >= MAX_COMPOUND_RULES {
        bail!("No free rule slots (max {})", MAX_COMPOUND_RULES);
    }
    let index = cfg.rules.len() as u32;
    cfg.add_compound_rule(entry);
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
