mod compound;
mod config;
mod geo;
mod honeypot;
mod loader;
mod rule;
mod ssh;

use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::info;
use neko_common::{port_key, PacketLog, ACTION_DROP, ACTION_PASS, FLAG_EMIT_EVENTS};
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
        target: RuleTarget,
    },
    Block {
        #[command(subcommand)]
        target: RuleTarget,
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
    Honeypot {
        #[command(subcommand)]
        action: HoneypotAction,
    },
}

#[derive(Subcommand)]
enum HoneypotAction {
    /// Enable the honeypot on one or more TCP ports (open to all sources).
    Enable {
        #[arg(short, long, required = true)]
        port: Vec<u16>,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long)]
        notify_command: Option<String>,
        /// Identifier for this host in notifications (defaults to the hostname).
        #[arg(long)]
        node_name: Option<String>,
        /// Embed an encrypted watermark token in responses (for counter-mapping).
        #[arg(long)]
        watermark: bool,
    },
    /// Disable the honeypot (config is kept).
    Disable,
    /// Decode a watermark token back to the visitor record.
    Decode { token: String },
    /// Show the current honeypot configuration.
    Status,
}

#[derive(Subcommand)]
enum RuleTarget {
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

fn spawn_perf_readers(perf_array: &mut AsyncPerfEventArray<aya::maps::MapData>) -> Result<()> {
    let cpus = aya::util::online_cpus().unwrap();
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketLog>()))
                .collect::<Vec<_>>();
            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let ptr = buffers[i].as_ptr() as *const PacketLog;
                            let log = unsafe { ptr.read_unaligned() };
                            print_packet_log(&log);
                        }
                    }
                    Err(e) => {
                        log::error!("perf event read error: {}", e);
                        continue;
                    }
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
        let src = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes([
            log.src_addr[0],
            log.src_addr[1],
            log.src_addr[2],
            log.src_addr[3],
        ])));
        let dst = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes([
            log.dst_addr[0],
            log.dst_addr[1],
            log.dst_addr[2],
            log.dst_addr[3],
        ])));
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    set_title(&format!("NekoFirewall v{}", env!("CARGO_PKG_VERSION")));
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

            ssh::check_ssh_safety(&mut ebpf);
            loader::attach(&mut ebpf, &iface)?;

            set_title(&format!("NekoFirewall | {} · whitelist", iface));
            println!("Firewall running on {} (whitelist mode, IPv4+IPv6)", iface);
            println!("  Use 'nf stop -i {}' for emergency detach", iface);
            println!("Press Ctrl+C to stop.");

            if cfg.honeypot.enabled && !cfg.honeypot.ports.is_empty() {
                // Open the honeypot ports to all sources so scanners reach the
                // userspace responder (default policy is drop). Note: a global
                // geo/ASN block still precedes the port allow, so a blocked
                // source won't hit the honeypot — keep those un-blocked for a
                // true catch-all.
                let mut ports_map = loader::open_pinned_hashmap::<u32, u32>("ALLOWED_PORTS")?;
                for &p in &cfg.honeypot.ports {
                    ports_map.insert(port_key(6, p), ACTION_PASS, 0)?;
                }
                println!(
                    "Honeypot active on tcp {:?} (open to all · watermark + log {})",
                    cfg.honeypot.ports, cfg.honeypot.log_path
                );
                honeypot::serve(cfg.honeypot.clone());
            }

            let events_map = ebpf.take_map("EVENTS").expect("EVENTS map not found");
            let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;
            spawn_perf_readers(&mut perf_array)?;
            loader::set_runtime_flag(FLAG_EMIT_EVENTS, true)?;

            signal::ctrl_c().await?;
            info!("Shutting down...");
            let _ = loader::set_runtime_flag(FLAG_EMIT_EVENTS, false);
            loader::cleanup_pins();
        }
        Commands::Allow { target } => match target {
            RuleTarget::Ip { addr } => {
                rule::allow_ip(&addr)?;
                println!("Whitelisted IP: {}", addr);
            }
            RuleTarget::Port { proto, port } => {
                rule::allow_port(&proto, port)?;
                let display_proto = proto.to_lowercase();
                if rule::proto_uses_type(&display_proto) {
                    println!("Whitelisted: {} type {}", display_proto, port);
                } else {
                    println!("Whitelisted: {}/{}", port, display_proto);
                }
            }
            RuleTarget::Proto { proto } => {
                rule::allow_proto(&proto)?;
                println!("Whitelisted protocol: {}", proto);
            }
            RuleTarget::Country { code } => {
                geo::set_country_policy(ACTION_PASS, &code)?;
                println!("Allowed country: {}", code.to_uppercase());
            }
            RuleTarget::Asn { asn } => {
                geo::set_asn_policy(ACTION_PASS, asn)?;
                println!("Allowed ASN: {}", asn);
            }
        },
        Commands::Block { target } => match target {
            RuleTarget::Ip { addr } => {
                rule::block_ip(&addr)?;
                println!("Removed from whitelist: {}", addr);
            }
            RuleTarget::Port { proto, port } => {
                rule::block_port(&proto, port)?;
                println!("Removed from whitelist: {}/{}", port, proto);
            }
            RuleTarget::Proto { proto } => {
                rule::block_proto(&proto)?;
                println!("Removed protocol from whitelist: {}", proto);
            }
            RuleTarget::Country { code } => {
                geo::set_country_policy(ACTION_DROP, &code)?;
                println!("Blocked country: {}", code.to_uppercase());
            }
            RuleTarget::Asn { asn } => {
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
            loader::set_runtime_flag(FLAG_EMIT_EVENTS, true)?;
            let map = loader::open_pinned_perf_event_array("EVENTS")?;
            let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map)?;

            set_title("NekoFirewall | monitoring");
            println!("Monitoring dropped packets... (Ctrl+C to stop)");
            spawn_perf_readers(&mut perf_array)?;

            signal::ctrl_c().await?;
            let _ = loader::set_runtime_flag(FLAG_EMIT_EVENTS, false);
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
        Commands::Honeypot { action } => match action {
            HoneypotAction::Enable {
                port,
                secret,
                notify_command,
                node_name,
                watermark,
            } => {
                let mut cfg = config::Config::load()?;
                cfg.honeypot.enabled = true;
                cfg.honeypot.ports = port;
                cfg.honeypot.watermark = watermark;
                if node_name.is_some() {
                    cfg.honeypot.node_name = node_name;
                }
                if let Some(s) = secret {
                    cfg.honeypot.secret = s;
                }
                // A secret is only needed in watermark mode (to derive the key).
                if cfg.honeypot.watermark && cfg.honeypot.secret.is_empty() {
                    cfg.honeypot.secret = honeypot::generate_secret();
                    println!(
                        "Generated honeypot secret (store it — needed to decode tokens):\n  {}",
                        cfg.honeypot.secret
                    );
                }
                if notify_command.is_some() {
                    cfg.honeypot.notify_command = notify_command;
                }
                cfg.save()?;
                println!(
                    "Honeypot enabled on tcp {:?} (watermark: {}). Restart 'nf run' to activate.",
                    cfg.honeypot.ports, cfg.honeypot.watermark
                );
            }
            HoneypotAction::Disable => {
                let mut cfg = config::Config::load()?;
                cfg.honeypot.enabled = false;
                cfg.save()?;
                println!("Honeypot disabled. Restart 'nf run' to apply.");
            }
            HoneypotAction::Decode { token } => {
                let cfg = config::Config::load()?;
                if cfg.honeypot.secret.is_empty() {
                    anyhow::bail!("No honeypot secret configured");
                }
                let json = honeypot::decode_token(&cfg.honeypot.secret, &token)?;
                println!("{}", json);
            }
            HoneypotAction::Status => {
                let cfg = config::Config::load()?;
                let hp = &cfg.honeypot;
                println!("enabled:   {}", hp.enabled);
                println!("node:      {}", hp.node_name.as_deref().unwrap_or("(hostname)"));
                println!("ports:     {:?}", hp.ports);
                println!("watermark: {}", hp.watermark);
                println!("log:       {}", hp.log_path);
                println!(
                    "notify:    {}",
                    hp.notify_command.as_deref().unwrap_or("(none)")
                );
                println!(
                    "debounce:  {}s per IP, max {}/min (then folded into a summary)",
                    hp.notify_dedup_secs, hp.notify_max_per_min
                );
                println!("max conns: {}", hp.max_connections);
                println!(
                    "secret:    {}",
                    if hp.secret.is_empty() {
                        "(unset)"
                    } else {
                        "(set)"
                    }
                );
            }
        },
    }

    Ok(())
}
