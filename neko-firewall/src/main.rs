mod geo;
mod loader;
mod rule;

use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::{Map, MapData};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::info;
use neko_common::{PacketLog, ACTION_DROP, ACTION_PASS};
use std::net::Ipv4Addr;
use tokio::signal;

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
}

#[derive(Subcommand)]
enum AllowTarget {
    Ip { addr: Ipv4Addr },
    Port { proto: String, port: u16 },
    Proto { proto: String },
    Country { code: String },
    Asn { asn: u32 },
}

#[derive(Subcommand)]
enum BlockTarget {
    Ip { addr: Ipv4Addr },
    Port { proto: String, port: u16 },
    Proto { proto: String },
    Country { code: String },
    Asn { asn: u32 },
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
    let src = Ipv4Addr::from(log.src_addr.to_be());
    let dst = Ipv4Addr::from(log.dst_addr.to_be());
    let action = if log.action == 1 { "DROP" } else { "PASS" };
    match log.protocol {
        1 => println!("[{}] ICMP {} -> {} (type {})", action, src, dst, log.dst_port),
        6 => println!("[{}] TCP {}:{} -> {}:{}", action, src, log.src_port, dst, log.dst_port),
        17 => println!("[{}] UDP {}:{} -> {}:{}", action, src, log.src_port, dst, log.dst_port),
        p => println!("[{}] proto={} {} -> {}", action, p, src, dst),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { iface } => {
            let mut ebpf = loader::load_and_attach(&iface)?;

            println!("Loading GeoIP databases...");
            let geo_count = geo::load_geo_map(&mut ebpf)?;
            let asn_count = geo::load_asn_map(&mut ebpf)?;
            println!("  Loaded {} country + {} ASN prefixes", geo_count, asn_count);

            println!("Firewall running on {} (whitelist mode)", iface);
            println!("  Use 'allow/block country/asn' for geo filtering");
            println!("Press Ctrl+C to stop.");
            spawn_event_readers(&mut ebpf)?;
            signal::ctrl_c().await?;
            info!("Shutting down...");
            loader::cleanup_pins();
        }
        Commands::Allow { target } => match target {
            AllowTarget::Ip { addr } => {
                rule::allow_ip(addr)?;
                println!("Whitelisted IP: {}", addr);
            }
            AllowTarget::Port { proto, port } => {
                rule::allow_port(&proto, port)?;
                if proto.eq_ignore_ascii_case("icmp") {
                    println!("Whitelisted: icmp type {}", port);
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
                rule::block_ip(addr)?;
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
        }
        Commands::Conntrack => {
            rule::show_conntrack()?;
        }
        Commands::Monitor => {
            let data = MapData::from_pin("/sys/fs/bpf/neko/EVENTS")
                .map_err(|e| anyhow::anyhow!("EVENTS: {} (is the firewall running?)", e))?;
            let map = Map::PerfEventArray(data);
            let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map)?;

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
    }

    Ok(())
}
