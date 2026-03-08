mod compound;
mod config;
mod geo;
mod loader;
mod rule;

use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::info;
use neko_common::{PacketLog, ACTION_DROP, ACTION_PASS};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::signal;

fn set_title(title: &str) {
    // OSC escape: \x1b]2;TITLE\x07
    eprint!("\x1b]2;{}\x07", title);
}

#[derive(Parser)]
#[command(name = "neko-firewall", about = "XDP/eBPF whitelist firewall")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(short, long)]
        iface: String,
    },
    Allow {
        #[command(subcommand)]
        target: AllowTarget,
    },
    Block {
        #[command(subcommand)]
        target: BlockTarget,
    },
    List,
    Conntrack,
    Monitor,
    Stop {
        #[arg(short, long)]
        iface: String,
    },
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },
}

#[derive(Subcommand)]
enum AllowTarget {
    Ip { addr: String },
    Port { proto: String, port: u16 },
    Proto { proto: String },
    Country { code: String },
    Asn { asn: u32 },
}

#[derive(Subcommand)]
enum BlockTarget {
    Ip { addr: String },
    Port { proto: String, port: u16 },
    Proto { proto: String },
    Country { code: String },
    Asn { asn: u32 },
}

#[derive(Subcommand)]
enum RuleAction {
    Add {
        action: String,
        #[arg(long)]
        proto: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        asn: Option<u32>,
        #[arg(long)]
        ip: Option<String>,
    },
    Remove {
        index: u32,
    },
    List,
}

fn spawn_event_readers(ebpf: &mut aya::Ebpf) -> Result<()> {
    let events_map = ebpf.take_map("EVENTS").expect("EVENTS map not found");
    let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;

    let cpus = aya::util::online_cpus().unwrap();
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketLog>()))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let ptr = buffers[i].as_ptr() as *const PacketLog;
                    let log = unsafe { ptr.read_unaligned() };
                    print_packet_log(&log);
                }
            }
        });
    }
    Ok(())
}

fn print_packet_log(log: &PacketLog) {
    let action = if log.action == ACTION_DROP as u8 {
        "DROP"
    } else {
        "PASS"
    };

    if log.family == 6 {
        // IPv6
        let src = Ipv6Addr::from(log.src_addr);
        let dst = Ipv6Addr::from(log.dst_addr);
        match log.protocol {
            58 => println!(
                "[{}] ICMPv6 {} -> {} (type {})",
                action, src, dst, log.dst_port
            ),
            6 => println!(
                "[{}] TCP [{}]:{} -> [{}]:{}",
                action, src, log.src_port, dst, log.dst_port
            ),
            17 => println!(
                "[{}] UDP [{}]:{} -> [{}]:{}",
                action, src, log.src_port, dst, log.dst_port
            ),
            p => println!("[{}] proto={} {} -> {}", action, p, src, dst),
        }
    } else {
        // IPv4 — address stored in first 4 bytes
        let src_bytes = [log.src_addr[0], log.src_addr[1], log.src_addr[2], log.src_addr[3]];
        let src = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes(src_bytes)));
        let dst_bytes = [log.dst_addr[0], log.dst_addr[1], log.dst_addr[2], log.dst_addr[3]];
        let dst = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes(dst_bytes)));
        match log.protocol {
            1 => println!(
                "[{}] ICMP {} -> {} (type {})",
                action, src, dst, log.dst_port
            ),
            6 => println!(
                "[{}] TCP {}:{} -> {}:{}",
                action, src, log.src_port, dst, log.dst_port
            ),
            17 => println!(
                "[{}] UDP {}:{} -> {}:{}",
                action, src, log.src_port, dst, log.dst_port
            ),
            p => println!("[{}] proto={} {} -> {}", action, p, src, dst),
        }
    }
}

fn detect_ssh_port() -> u16 {
    // 1. Try SSH_CONNECTION env (available in SSH sessions)
    if let Some(port) = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|conn| conn.split_whitespace().nth(3).and_then(|p| p.parse::<u16>().ok()))
    {
        return port;
    }

    // 2. Parse sshd_config (works under systemd)
    if let Ok(content) = std::fs::read_to_string("/etc/ssh/sshd_config") {
        for line in content.lines().rev() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("Port") {
                if let Some(port) = rest.trim().parse::<u16>().ok() {
                    return port;
                }
            }
        }
    }

    22
}

fn check_ssh_safety(ebpf: &mut aya::Ebpf) {
    let ssh_port = detect_ssh_port();

    let map = ebpf.map("ALLOWED_PORTS").expect("ALLOWED_PORTS map not found");
    let map: aya::maps::HashMap<_, u32, u32> =
        aya::maps::HashMap::try_from(map).expect("ALLOWED_PORTS type mismatch");

    let tcp_wildcard = 6u32 << 16;
    let ssh_key = (6u32 << 16) | ssh_port as u32;

    if map.get(&tcp_wildcard, 0).is_ok() || map.get(&ssh_key, 0).is_ok() {
        return;
    }

    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!("!  WARNING: SSH port {}/tcp is NOT in allowed rules", ssh_port);
    eprintln!("!  You may lose SSH access after firewall attaches");
    eprintln!("!  Run: nf allow port tcp {}", ssh_port);
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    set_title(&format!(
        "NekoFirewall v{}",
        env!("CARGO_PKG_VERSION")
    ));
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { iface } => {
            let mut ebpf = loader::load(&iface)?;
            loader::reset_runtime_maps(&mut ebpf)?;

            println!("Loading GeoIP databases...");
            let (geo4, geo6) = geo::load_geo_map(&mut ebpf)?;
            let (asn4, asn6) = geo::load_asn_map(&mut ebpf)?;
            println!(
                "  Loaded {} IPv4 + {} IPv6 country, {} IPv4 + {} IPv6 ASN prefixes",
                geo4, geo6, asn4, asn6
            );

            let cfg = config::Config::load()?;
            let rule_count = cfg.rule_count();
            cfg.apply()?;
            if rule_count > 0 {
                println!("  Restored {} rules from config", rule_count);
            }

            check_ssh_safety(&mut ebpf);
            loader::attach(&mut ebpf, &iface)?;

            set_title(&format!("NekoFirewall | {} · whitelist", iface));
            println!("Firewall running on {} (whitelist mode, IPv4+IPv6)", iface);
            println!("  Use 'nf stop -i {}' for emergency detach", iface);
            println!("Press Ctrl+C to stop.");
            spawn_event_readers(&mut ebpf)?;
            signal::ctrl_c().await?;
            info!("Shutting down...");
            loader::cleanup_pins();
        }
        Commands::Allow { target } => match target {
            AllowTarget::Ip { addr } => {
                rule::allow_ip(&addr)?;
                println!("Whitelisted IP: {}", addr);
            }
            AllowTarget::Port { proto, port } => {
                rule::allow_port(&proto, port)?;
                let pnum = rule::parse_proto(&proto)?;
                if pnum == 1 || pnum == 58 {
                    println!("Whitelisted: {} type {}", proto, port);
                } else {
                    println!("Whitelisted: {}/{}", port, proto);
                }
            }
            AllowTarget::Proto { proto } => {
                rule::allow_proto(&proto)?;
                println!("Whitelisted protocol: {}", proto);
            }
            AllowTarget::Country { code } => {
                geo::set_country_policy(ACTION_PASS, &code)?;
                println!("Allowed country: {}", code.to_uppercase());
            }
            AllowTarget::Asn { asn } => {
                geo::set_asn_policy(ACTION_PASS, asn)?;
                println!("Allowed ASN: {}", asn);
            }
        },
        Commands::Block { target } => match target {
            BlockTarget::Ip { addr } => {
                rule::block_ip(&addr)?;
                println!("Removed from whitelist: {}", addr);
            }
            BlockTarget::Port { proto, port } => {
                rule::block_port(&proto, port)?;
                println!("Removed from whitelist: {}/{}", port, proto);
            }
            BlockTarget::Proto { proto } => {
                rule::block_proto(&proto)?;
                println!("Removed protocol from whitelist: {}", proto);
            }
            BlockTarget::Country { code } => {
                geo::set_country_policy(ACTION_DROP, &code)?;
                println!("Blocked country: {}", code.to_uppercase());
            }
            BlockTarget::Asn { asn } => {
                geo::set_asn_policy(ACTION_DROP, asn)?;
                println!("Blocked ASN: {}", asn);
            }
        },
        Commands::List => {
            rule::list_rules()?;
            println!("\n=== Geo/ASN Policies ===");
            geo::list_policies()?;
            println!("\n=== Compound Rules ===");
            compound::list_rules()?;
        }
        Commands::Conntrack => {
            rule::show_conntrack()?;
        }
        Commands::Monitor => {
            let map = loader::open_pinned_perf_event_array("EVENTS")?;
            let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map)?;

            set_title("NekoFirewall | monitoring");
            println!("Monitoring dropped packets... (Ctrl+C to stop)");

            let cpus = aya::util::online_cpus().unwrap();
            for cpu_id in cpus {
                let mut buf = perf_array.open(cpu_id, None)?;
                tokio::spawn(async move {
                    let mut buffers = (0..10)
                        .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketLog>()))
                        .collect::<Vec<_>>();
                    loop {
                        let events = buf.read_events(&mut buffers).await.unwrap();
                        for i in 0..events.read {
                            let ptr = buffers[i].as_ptr() as *const PacketLog;
                            let log = unsafe { ptr.read_unaligned() };
                            print_packet_log(&log);
                        }
                    }
                });
            }

            signal::ctrl_c().await?;
        }
        Commands::Stop { iface } => {
            loader::force_stop(&iface)?;
            println!("Firewall stopped on {}", iface);
        }
        Commands::Rule { action } => match action {
            RuleAction::Add {
                action,
                proto,
                port,
                country,
                asn,
                ip,
            } => {
                let action_val = match action.to_lowercase().as_str() {
                    "allow" => ACTION_PASS,
                    "drop" | "block" => ACTION_DROP,
                    _ => anyhow::bail!("Action must be 'allow' or 'drop'"),
                };
                let idx = compound::add_rule(
                    action_val,
                    proto.as_deref(),
                    port,
                    country.as_deref(),
                    asn,
                    ip.as_deref(),
                )?;
                println!("Added compound rule [{}]", idx);
            }
            RuleAction::Remove { index } => {
                compound::remove_rule(index)?;
                println!("Removed compound rule [{}]", index);
            }
            RuleAction::List => {
                println!("=== Compound Rules ===");
                compound::list_rules()?;
            }
        },
    }

    Ok(())
}
