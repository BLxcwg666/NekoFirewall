mod loader;
mod rule;

use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::info;
use neko_common::PacketLog;
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Parser)]
#[command(name = "neko-firewall", about = "XDP/eBPF firewall powered by Aya")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Load and attach the XDP firewall to an interface
    Run {
        #[arg(short, long)]
        iface: String,
    },
    /// Block an IP address or port
    Block {
        #[command(subcommand)]
        target: BlockTarget,
    },
    /// Allow (unblock) an IP address or port
    Allow {
        #[command(subcommand)]
        target: AllowTarget,
    },
    /// List all active rules
    List,
    /// Monitor blocked packets in real-time
    Monitor,
}

#[derive(Subcommand)]
enum BlockTarget {
    /// Block an IP address
    Ip { addr: Ipv4Addr },
    /// Block a port
    Port { proto: String, port: u16 },
}

#[derive(Subcommand)]
enum AllowTarget {
    /// Allow (unblock) an IP address
    Ip { addr: Ipv4Addr },
    /// Allow (unblock) a port
    Port { proto: String, port: u16 },
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
                    let src = Ipv4Addr::from(log.src_addr.to_be());
                    let dst = Ipv4Addr::from(log.dst_addr.to_be());
                    let action = if log.action == 1 { "DROP" } else { "PASS" };
                    let proto = match log.protocol {
                        6 => "TCP",
                        17 => "UDP",
                        _ => "OTHER",
                    };
                    println!(
                        "[{}] {} {}:{} -> {}:{}",
                        action, proto, src, log.src_port, dst, log.dst_port,
                    );
                }
            }
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { iface } => {
            let mut ebpf = loader::load_and_attach(&iface)?;
            info!("Firewall running on {}. Press Ctrl+C to stop.", iface);
            spawn_event_readers(&mut ebpf)?;
            signal::ctrl_c().await?;
            info!("Shutting down...");
            loader::cleanup_pins();
        }
        Commands::Block { target } => match target {
            BlockTarget::Ip { addr } => {
                rule::block_ip(addr)?;
                println!("Blocked IP: {}", addr);
            }
            BlockTarget::Port { proto, port } => {
                rule::block_port(&proto, port)?;
                println!("Blocked port: {}/{}", port, proto);
            }
        },
        Commands::Allow { target } => match target {
            AllowTarget::Ip { addr } => {
                rule::allow_ip(addr)?;
                println!("Allowed IP: {}", addr);
            }
            AllowTarget::Port { proto, port } => {
                rule::allow_port(&proto, port)?;
                println!("Allowed port: {}/{}", port, proto);
            }
        },
        Commands::List => {
            rule::list_rules()?;
        }
        Commands::Monitor => {
            use aya::maps::{Map, MapData};
            let data = MapData::from_pin("/sys/fs/bpf/neko/EVENTS")
                .map_err(|e| anyhow::anyhow!("Failed to open pinned EVENTS map (is the firewall running?): {}", e))?;
            let map = Map::PerfEventArray(data);
            let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map)?;

            println!("Monitoring packets... (Ctrl+C to stop)");

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
                            let src = Ipv4Addr::from(log.src_addr.to_be());
                            let dst = Ipv4Addr::from(log.dst_addr.to_be());
                            let action = if log.action == 1 { "DROP" } else { "PASS" };
                            let proto = match log.protocol {
                                6 => "TCP",
                                17 => "UDP",
                                _ => "OTHER",
                            };
                            println!(
                                "[{}] {} {}:{} -> {}:{}",
                                action, proto, src, log.src_port, dst, log.dst_port,
                            );
                        }
                    }
                });
            }

            signal::ctrl_c().await?;
        }
    }

    Ok(())
}
