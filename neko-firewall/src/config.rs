use anyhow::{Context, Result};
use aya::maps::HashMap;
use neko_common::{ACTION_DROP, ACTION_PASS};
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
