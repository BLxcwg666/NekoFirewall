use anyhow::{Context, Result};
use aya::maps::{Array, HashMap};
use neko_common::{
    CompoundRule, ACTION_DROP, ACTION_PASS, MAX_COMPOUND_RULES,
    MATCH_ASN, MATCH_COUNTRY, MATCH_IP, MATCH_PORT, MATCH_PROTO,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

use crate::{geo, loader};

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
        std::fs::write(CONFIG_PATH, content)
            .with_context(|| format!("Failed to write {}", CONFIG_PATH))
    }

    pub fn apply(&self) -> Result<()> {
        // Apply IP rules
        if !self.allow.ips.is_empty() {
            let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_IPS")?;
            for ip_str in &self.allow.ips {
                if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
                    let ip: u32 = addr.into();
                    map.insert(ip, ACTION_PASS, 0)?;
                } else {
                    eprintln!("  Warning: skipping invalid IP '{}'", ip_str);
                }
            }
        }

        // Apply port rules
        if !self.allow.ports.is_empty() {
            let mut map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
            for port_str in &self.allow.ports {
                if let Some((proto, port)) = parse_port_entry(port_str) {
                    let proto_num = parse_proto_num(proto);
                    if let Some(num) = proto_num {
                        let key = (num as u32) << 16 | port as u32;
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
                if let Some(num) = parse_proto_num(proto) {
                    let key = (num as u32) << 16;
                    map.insert(key, ACTION_PASS, 0)?;
                } else {
                    eprintln!("  Warning: skipping unknown protocol '{}'", proto);
                }
            }
        }

        // Apply geo policies
        if !self.allow.countries.is_empty() || !self.block.countries.is_empty()
            || !self.allow.asns.is_empty() || !self.block.asns.is_empty()
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
                map.insert(0x80000000 | asn, ACTION_PASS, 0)?;
            }
            for &asn in &self.block.asns {
                map.insert(0x80000000 | asn, ACTION_DROP, 0)?;
            }
        }

        // Apply compound rules
        if !self.rules.is_empty() {
            let map = loader::open_pinned_map("RULES")?;
            let mut arr: Array<_, CompoundRule> = Array::try_from(map)
                .map_err(|e| anyhow::anyhow!("Failed to open RULES: {:?}", e))?;
            for (i, entry) in self.rules.iter().enumerate() {
                if i as u32 >= MAX_COMPOUND_RULES {
                    eprintln!("  Warning: too many compound rules, max {}", MAX_COMPOUND_RULES);
                    break;
                }
                if let Some(rule) = entry.to_bpf_rule() {
                    arr.set(i as u32, rule, 0)
                        .map_err(|e| anyhow::anyhow!("Failed to set RULES[{}]: {:?}", i, e))?;
                } else {
                    eprintln!("  Warning: skipping invalid compound rule #{}", i);
                }
            }
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

    pub fn add_ip(&mut self, addr: Ipv4Addr) {
        let s = addr.to_string();
        if !self.allow.ips.contains(&s) {
            self.allow.ips.push(s);
        }
    }

    pub fn remove_ip(&mut self, addr: Ipv4Addr) {
        let s = addr.to_string();
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
        ip: Option<Ipv4Addr>,
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
            ip: ip.map(|a| a.to_string()),
        }
    }

    fn to_bpf_rule(&self) -> Option<CompoundRule> {
        let action = match self.action.as_str() {
            "allow" => ACTION_PASS,
            "drop" | "block" => ACTION_DROP,
            _ => return None,
        };
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
        if let Some(ref p) = self.proto {
            rule.proto = parse_proto_num(p)?;
            rule.match_fields |= MATCH_PROTO;
        }
        if let Some(port) = self.port {
            rule.port = port;
            rule.match_fields |= MATCH_PORT;
        }
        if let Some(ref c) = self.country {
            rule.country_id = geo::country_to_id(c).ok()?;
            rule.match_fields |= MATCH_COUNTRY;
        }
        if let Some(asn) = self.asn {
            rule.asn_id = 0x80000000 | asn;
            rule.match_fields |= MATCH_ASN;
        }
        if let Some(ref ip_str) = self.ip {
            let addr: Ipv4Addr = ip_str.parse().ok()?;
            rule.src_ip = u32::from(addr).to_be();
            rule.match_fields |= MATCH_IP;
        }
        Some(rule)
    }
}

fn format_port_entry(proto: &str, port: u16) -> String {
    let p = proto.to_lowercase();
    if p == "icmp" {
        format!("icmp/{}", port)
    } else {
        format!("{}/{}", p, port)
    }
}

fn parse_port_entry(s: &str) -> Option<(&str, u16)> {
    let (proto, port_str) = s.split_once('/')?;
    let port = port_str.parse().ok()?;
    Some((proto, port))
}

fn parse_proto_num(proto: &str) -> Option<u8> {
    match proto.to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        _ => None,
    }
}
