use neko_common::port_key;
use std::net::IpAddr;
use std::process::Command;

use crate::config::{self, CompoundRuleEntry};
use crate::rule;

pub fn check_ssh_safety(ebpf: &mut aya::Ebpf) {
    let ssh_ports = detect_ssh_ports();

    let map = ebpf
        .map("ALLOWED_PORTS")
        .expect("ALLOWED_PORTS map not found");
    let map: aya::maps::HashMap<_, u32, u32> =
        aya::maps::HashMap::try_from(map).expect("ALLOWED_PORTS type mismatch");

    let tcp_wildcard = port_key(6, 0);
    if map.get(&tcp_wildcard, 0).is_ok() {
        return;
    }

    let mut missing_ports = Vec::new();
    for ssh_port in ssh_ports.iter().copied() {
        let ssh_key = port_key(6, ssh_port);
        if map.get(&ssh_key, 0).is_ok() || allowed_by_compound_rules(ssh_port) {
            continue;
        }
        if !missing_ports.contains(&ssh_port) {
            missing_ports.push(ssh_port);
        }
    }

    if missing_ports.is_empty() {
        return;
    }

    missing_ports.sort_unstable();
    let missing_list = missing_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!(
        "!  WARNING: SSH port(s) {}/tcp are NOT in allowed rules",
        missing_list
    );
    eprintln!("!  You may lose SSH access after firewall attaches");
    if missing_ports.len() == 1 {
        eprintln!("!  Run: nf allow port tcp {}", missing_ports[0]);
    }
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

fn detect_ssh_ports() -> Vec<u16> {
    if let Some(port) = port_from_connection_env() {
        return vec![port];
    }

    if let Some(ports) = ports_from_sshd() {
        return ports;
    }

    if let Some(ports) = ports_from_config() {
        return ports;
    }

    vec![22]
}

fn port_from_connection_env() -> Option<u16> {
    std::env::var("SSH_CONNECTION").ok().and_then(|conn| {
        conn.split_whitespace()
            .nth(3)
            .and_then(|p| p.parse::<u16>().ok())
    })
}

fn ports_from_sshd() -> Option<Vec<u16>> {
    for program in ["/usr/sbin/sshd", "/usr/bin/sshd", "sshd"] {
        let Ok(output) = Command::new(program).arg("-T").output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }

        let ports = parse_sshd_ports(&String::from_utf8_lossy(&output.stdout));
        if !ports.is_empty() {
            return Some(ports);
        }
    }
    None
}

fn ports_from_config() -> Option<Vec<u16>> {
    let content = std::fs::read_to_string("/etc/ssh/sshd_config").ok()?;
    let ports = parse_sshd_ports(&content);
    if ports.is_empty() {
        None
    } else {
        Some(ports)
    }
}

fn parse_sshd_ports(content: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if !matches!(parts.next(), Some(keyword) if keyword.eq_ignore_ascii_case("port")) {
            continue;
        }
        if let Some(value) = parts.next() {
            if let Ok(port) = value.parse::<u16>() {
                ports.push(port);
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn allowed_by_compound_rules(ssh_port: u16) -> bool {
    let Ok(cfg) = config::Config::load() else {
        return false;
    };
    let ssh_family = detect_family();
    cfg.rules
        .iter()
        .any(|rule| compound_rule_allows_ssh(rule, ssh_port, ssh_family))
}

fn detect_family() -> Option<u8> {
    let server_ip = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|conn| conn.split_whitespace().nth(2).map(str::to_owned))?;
    let ip: IpAddr = server_ip.parse().ok()?;
    Some(match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    })
}

fn compound_rule_allows_ssh(
    rule_entry: &CompoundRuleEntry,
    ssh_port: u16,
    ssh_family: Option<u8>,
) -> bool {
    if !rule_entry.action.eq_ignore_ascii_case("allow") {
        return false;
    }

    let has_specific_proto = rule_entry
        .proto
        .as_deref()
        .is_some_and(|proto| !proto.eq_ignore_ascii_case("any"));

    if !has_specific_proto && rule_entry.port.is_none() {
        return false;
    }

    if let Some(proto) = &rule_entry.proto {
        if !proto.eq_ignore_ascii_case("tcp") && !proto.eq_ignore_ascii_case("any") {
            return false;
        }
    }

    if let Some(port) = rule_entry.port {
        if port != ssh_port {
            return false;
        }
    }

    let Some(ssh_family) = ssh_family else {
        return true;
    };

    let Some(ip) = rule_entry.ip.as_deref() else {
        return true;
    };

    match rule::parse_cidr(ip) {
        Ok(rule::CidrAddr::V4(_, _)) => ssh_family == 4,
        Ok(rule::CidrAddr::V6(_, _)) => ssh_family == 6,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::compound_rule_allows_ssh;
    use crate::config::CompoundRuleEntry;

    fn allow_rule(proto: Option<&str>, port: Option<u16>) -> CompoundRuleEntry {
        CompoundRuleEntry {
            action: "allow".into(),
            proto: proto.map(str::to_string),
            port,
            country: None,
            asn: None,
            ip: None,
        }
    }

    #[test]
    fn ssh_check_accepts_any_proto_with_matching_port() {
        let rule = allow_rule(Some("any"), Some(22));
        assert!(compound_rule_allows_ssh(&rule, 22, Some(4)));
    }

    #[test]
    fn ssh_check_rejects_any_proto_without_other_matchers() {
        let rule = allow_rule(Some("any"), None);
        assert!(!compound_rule_allows_ssh(&rule, 22, Some(4)));
    }
}
