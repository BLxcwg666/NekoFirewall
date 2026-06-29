use anyhow::{Context, Result};
use aya::maps::{lpm_trie::Key, Array, HashMap};
use neko_common::{
    port_key, CompoundRule, ACTION_DROP, ACTION_PASS, ASN_FLAG, MATCH_ASN, MATCH_COUNTRY, MATCH_IP,
    MATCH_PORT, MATCH_PROTO, MAX_COMPOUND_RULES,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{
    geo, loader,
    rule::{self, CidrAddr},
};

const CONFIG_DIR: &str = "/etc/neko-firewall";
const CONFIG_PATH: &str = "/etc/neko-firewall/rules.toml";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub allow: AllowRules,
    #[serde(default)]
    pub block: BlockRules,
    #[serde(default)]
    pub rules: Vec<CompoundRuleEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AllowRules {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default)]
    pub asns: Vec<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BlockRules {
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default)]
    pub asns: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundRuleEntry {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Path::new(CONFIG_PATH);
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", CONFIG_PATH))?;
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", CONFIG_PATH))
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(CONFIG_DIR)
            .with_context(|| format!("Failed to create {}", CONFIG_DIR))?;
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        // Write to a temp file in the same dir, then atomically rename over the
        // target, so a crash mid-write can't leave a truncated/corrupt config
        // that fails to parse on the next start.
        let tmp_path = format!("{}.tmp", CONFIG_PATH);
        std::fs::write(&tmp_path, content)
            .with_context(|| format!("Failed to write {}", tmp_path))?;
        std::fs::rename(&tmp_path, CONFIG_PATH)
            .with_context(|| format!("Failed to replace {}", CONFIG_PATH))
    }

    pub fn apply(&self) -> Result<()> {
        // Apply IP rules (LpmTrie/CIDR)
        if !self.allow.ips.is_empty() {
            let mut map4 = loader::open_pinned_lpm_trie::<u32, u32>("ALLOWED_IPS")?;
            let mut map6 = loader::open_pinned_lpm_trie::<[u8; 16], u32>("ALLOWED_IPS6")?;
            for cidr in &self.allow.ips {
                match rule::parse_cidr(cidr) {
                    Ok(CidrAddr::V4(ip, prefix)) => {
                        let key = Key::new(prefix as u32, u32::from(ip).to_be());
                        map4.insert(&key, ACTION_PASS, 0)?;
                    }
                    Ok(CidrAddr::V6(ip, prefix)) => {
                        let key = Key::new(prefix as u32, ip.octets());
                        map6.insert(&key, ACTION_PASS, 0)?;
                    }
                    Err(_) => {
                        eprintln!("  Warning: skipping invalid IP/CIDR '{}'", cidr);
                    }
                }
            }
        }

        // Apply port rules
        if !self.allow.ports.is_empty() {
            let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
            for port_str in &self.allow.ports {
                if let Some((proto, port)) = parse_port_entry(port_str) {
                    if let Ok(num) = rule::parse_port_proto(proto) {
                        let key = port_key(num, port);
                        map.insert(key, ACTION_PASS, 0)?;
                    } else {
                        eprintln!("  Warning: skipping unknown protocol '{}'", proto);
                    }
                } else {
                    eprintln!("  Warning: skipping invalid port '{}'", port_str);
                }
            }
        }

        // Apply protocol rules
        if !self.allow.protocols.is_empty() {
            let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
            for proto in &self.allow.protocols {
                if let Some(num) = neko_common::parse_proto(proto) {
                    let key = port_key(num, 0);
                    map.insert(key, ACTION_PASS, 0)?;
                } else {
                    eprintln!("  Warning: skipping unknown protocol '{}'", proto);
                }
            }
        }

        // Apply geo policies
        if !self.allow.countries.is_empty()
            || !self.block.countries.is_empty()
            || !self.allow.asns.is_empty()
            || !self.block.asns.is_empty()
        {
            let mut map: HashMap<_, u32, u32> = loader::open_pinned_hashmap("GEO_POLICY")?;
            for code in &self.allow.countries {
                if let Ok(id) = geo::country_to_id(code) {
                    map.insert(id, ACTION_PASS, 0)?;
                }
            }
            for code in &self.block.countries {
                if let Ok(id) = geo::country_to_id(code) {
                    map.insert(id, ACTION_DROP, 0)?;
                }
            }
            for &asn in &self.allow.asns {
                map.insert(ASN_FLAG | asn, ACTION_PASS, 0)?;
            }
            for &asn in &self.block.asns {
                map.insert(ASN_FLAG | asn, ACTION_DROP, 0)?;
            }
        }

        self.apply_compound_rules()?;

        Ok(())
    }

    pub fn apply_compound_rules(&self) -> Result<()> {
        let map_v4 = loader::open_pinned_map("RULES_V4")?;
        let mut arr_v4: Array<_, CompoundRule> = Array::try_from(map_v4)
            .map_err(|e| anyhow::anyhow!("Failed to open RULES_V4: {:?}", e))?;
        let map_v6 = loader::open_pinned_map("RULES_V6")?;
        let mut arr_v6: Array<_, CompoundRule> = Array::try_from(map_v6)
            .map_err(|e| anyhow::anyhow!("Failed to open RULES_V6: {:?}", e))?;

        let mut next_v4 = 0u32;
        let mut next_v6 = 0u32;

        for (i, entry) in self.rules.iter().enumerate() {
            let Some(rule) = entry.to_bpf_rule() else {
                eprintln!("  Warning: skipping invalid compound rule #{}", i);
                continue;
            };

            match rule.family {
                4 => {
                    if next_v4 >= MAX_COMPOUND_RULES {
                        eprintln!(
                            "  Warning: too many IPv4 compound rules, max {}",
                            MAX_COMPOUND_RULES
                        );
                        continue;
                    }
                    arr_v4.set(next_v4, rule, 0).map_err(|e| {
                        anyhow::anyhow!("Failed to set RULES_V4[{}]: {:?}", next_v4, e)
                    })?;
                    next_v4 += 1;
                }
                6 => {
                    if next_v6 >= MAX_COMPOUND_RULES {
                        eprintln!(
                            "  Warning: too many IPv6 compound rules, max {}",
                            MAX_COMPOUND_RULES
                        );
                        continue;
                    }
                    arr_v6.set(next_v6, rule, 0).map_err(|e| {
                        anyhow::anyhow!("Failed to set RULES_V6[{}]: {:?}", next_v6, e)
                    })?;
                    next_v6 += 1;
                }
                _ => {
                    if next_v4 >= MAX_COMPOUND_RULES || next_v6 >= MAX_COMPOUND_RULES {
                        eprintln!(
                            "  Warning: too many compound rules, max {}",
                            MAX_COMPOUND_RULES
                        );
                        continue;
                    }
                    arr_v4.set(next_v4, rule, 0).map_err(|e| {
                        anyhow::anyhow!("Failed to set RULES_V4[{}]: {:?}", next_v4, e)
                    })?;
                    arr_v6.set(next_v6, rule, 0).map_err(|e| {
                        anyhow::anyhow!("Failed to set RULES_V6[{}]: {:?}", next_v6, e)
                    })?;
                    next_v4 += 1;
                    next_v6 += 1;
                }
            }
        }

        for i in next_v4..MAX_COMPOUND_RULES {
            arr_v4
                .set(i, CompoundRule::default(), 0)
                .map_err(|e| anyhow::anyhow!("Failed to clear RULES_V4[{}]: {:?}", i, e))?;
        }
        for i in next_v6..MAX_COMPOUND_RULES {
            arr_v6
                .set(i, CompoundRule::default(), 0)
                .map_err(|e| anyhow::anyhow!("Failed to clear RULES_V6[{}]: {:?}", i, e))?;
        }

        Ok(())
    }

    pub fn rule_count(&self) -> usize {
        self.allow.ips.len()
            + self.allow.ports.len()
            + self.allow.protocols.len()
            + self.allow.countries.len()
            + self.allow.asns.len()
            + self.block.countries.len()
            + self.block.asns.len()
            + self.rules.len()
    }

    pub fn add_ip(&mut self, cidr: &str) {
        let s = cidr.to_string();
        if !self.allow.ips.contains(&s) {
            self.allow.ips.push(s);
        }
    }

    pub fn remove_ip(&mut self, cidr: &str) {
        let s = cidr.to_string();
        self.allow.ips.retain(|x| x != &s);
    }

    pub fn add_port(&mut self, proto: &str, port: u16) {
        let entry = format_port_entry(proto, port);
        if !self.allow.ports.contains(&entry) {
            self.allow.ports.push(entry);
        }
    }

    pub fn remove_port(&mut self, proto: &str, port: u16) {
        let entry = format_port_entry(proto, port);
        self.allow.ports.retain(|x| x != &entry);
    }

    pub fn add_proto(&mut self, proto: &str) {
        let p = proto.to_lowercase();
        if !self.allow.protocols.contains(&p) {
            self.allow.protocols.push(p);
        }
    }

    pub fn remove_proto(&mut self, proto: &str) {
        let p = proto.to_lowercase();
        self.allow.protocols.retain(|x| x != &p);
    }

    pub fn set_country(&mut self, action: u32, code: &str) {
        let code = code.to_uppercase();
        // Remove from both lists first
        self.allow.countries.retain(|x| x != &code);
        self.block.countries.retain(|x| x != &code);
        if action == ACTION_PASS {
            self.allow.countries.push(code);
        } else {
            self.block.countries.push(code);
        }
    }

    pub fn set_asn(&mut self, action: u32, asn: u32) {
        self.allow.asns.retain(|&x| x != asn);
        self.block.asns.retain(|&x| x != asn);
        if action == ACTION_PASS {
            self.allow.asns.push(asn);
        } else {
            self.block.asns.push(asn);
        }
    }

    pub fn add_compound_rule(&mut self, entry: CompoundRuleEntry) {
        self.rules.push(entry);
    }

    pub fn remove_compound_rule(&mut self, index: usize) {
        if index < self.rules.len() {
            self.rules.remove(index);
        }
    }
}

impl CompoundRuleEntry {
    pub fn new(
        action: u32,
        proto: Option<&str>,
        port: Option<u16>,
        country: Option<&str>,
        asn: Option<u32>,
        ip: Option<&str>,
    ) -> Self {
        Self {
            action: if action == ACTION_PASS {
                "allow".into()
            } else {
                "drop".into()
            },
            proto: proto.map(|p| p.to_lowercase()),
            port,
            country: country.map(|c| c.to_uppercase()),
            asn,
            ip: ip.map(|s| s.to_string()),
        }
    }

    pub(crate) fn to_bpf_rule(&self) -> Option<CompoundRule> {
        let action = match self.action.as_str() {
            "allow" => ACTION_PASS,
            // Fail-closed: anything that isn't an explicit allow becomes a drop.
            // An unknown/typo'd action must never silently disable a rule that
            // was meant to block traffic ("drop", "block", "deny", ...).
            _ => ACTION_DROP,
        };
        let mut bpf_rule = CompoundRule::default();
        bpf_rule.action = action;

        if let Some(ref p) = self.proto {
            if !p.eq_ignore_ascii_case("any") {
                bpf_rule.proto = neko_common::parse_proto(p)?;
                bpf_rule.match_fields |= MATCH_PROTO;
            }
        }
        if let Some(port) = self.port {
            bpf_rule.port = port;
            bpf_rule.match_fields |= MATCH_PORT;
        }
        if let Some(ref c) = self.country {
            bpf_rule.country_id = geo::country_to_id(c).ok()?;
            bpf_rule.match_fields |= MATCH_COUNTRY;
        }
        if let Some(asn) = self.asn {
            bpf_rule.asn_id = ASN_FLAG | asn;
            bpf_rule.match_fields |= MATCH_ASN;
        }
        if let Some(ref ip_str) = self.ip {
            match rule::parse_cidr(ip_str).ok()? {
                CidrAddr::V4(addr, prefix) => {
                    bpf_rule.set_ipv4(u32::from(addr).to_be(), prefix);
                }
                CidrAddr::V6(addr, prefix) => {
                    bpf_rule.set_ipv6(addr.octets(), prefix);
                }
            }
            bpf_rule.match_fields |= MATCH_IP;
        }
        if bpf_rule.match_fields == 0 {
            return None;
        }

        Some(bpf_rule)
    }
}

fn format_port_entry(proto: &str, port: u16) -> String {
    format!("{}/{}", proto.to_lowercase(), port)
}

fn parse_port_entry(s: &str) -> Option<(&str, u16)> {
    let (proto, port_str) = s.split_once('/')?;
    let port = port_str.parse().ok()?;
    Some((proto, port))
}

#[cfg(test)]
mod tests {
    use super::{CompoundRuleEntry, MATCH_PORT};

    #[test]
    fn any_proto_keeps_other_matchers() {
        let entry = CompoundRuleEntry {
            action: "allow".into(),
            proto: Some("any".into()),
            port: Some(53),
            country: None,
            asn: None,
            ip: None,
        };

        let rule = entry.to_bpf_rule().expect("rule should be valid");
        assert_eq!(rule.match_fields, MATCH_PORT);
        assert_eq!(rule.proto, 0);
        assert_eq!(rule.port, 53);
    }

    #[test]
    fn any_proto_needs_another_matcher() {
        let entry = CompoundRuleEntry {
            action: "allow".into(),
            proto: Some("any".into()),
            port: None,
            country: None,
            asn: None,
            ip: None,
        };

        assert!(entry.to_bpf_rule().is_none());
    }
}
