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
    List {
        #[arg(short, long)]
        iface: String,
    },
    /// Monitor blocked packets in real-time
    Monitor {
        #[arg(short, long)]
        iface: String,
    },
}

#[derive(Subcommand)]
enum BlockTarget {
    /// Block an IP address
    Ip {
        addr: Ipv4Addr,
        #[arg(short, long)]
        iface: String,
    },
    /// Block a port
    Port {
        proto: String,
        port: u16,
        #[arg(short, long)]
        iface: String,
    },
}

#[derive(Subcommand)]
enum AllowTarget {
    /// Allow (unblock) an IP address
    Ip {
        addr: Ipv4Addr,
        #[arg(short, long)]
        iface: String,
    },
    /// Allow (unblock) a port
    Port {
        proto: String,
        port: u16,
        #[arg(short, long)]
        iface: String,
    },
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
        }
        Commands::Block { target } => match target {
            BlockTarget::Ip { addr, iface } => {
                let mut ebpf = loader::load_and_attach(&iface)?;
                rule::block_ip(&mut ebpf, addr)?;
                println!("Blocked IP: {}", addr);
            }
            BlockTarget::Port { proto, port, iface } => {
                let mut ebpf = loader::load_and_attach(&iface)?;
                rule::block_port(&mut ebpf, &proto, port)?;
                println!("Blocked port: {}/{}", port, proto);
            }
        },
        Commands::Allow { target } => match target {
            AllowTarget::Ip { addr, iface } => {
                let mut ebpf = loader::load_and_attach(&iface)?;
                rule::allow_ip(&mut ebpf, addr)?;
                println!("Allowed IP: {}", addr);
            }
            AllowTarget::Port { proto, port, iface } => {
                let mut ebpf = loader::load_and_attach(&iface)?;
                rule::allow_port(&mut ebpf, &proto, port)?;
                println!("Allowed port: {}/{}", port, proto);
            }
        },
        Commands::List { iface } => {
            let mut ebpf = loader::load_and_attach(&iface)?;
            rule::list_rules(&mut ebpf)?;
        }
        Commands::Monitor { iface } => {
            let mut ebpf = loader::load_and_attach(&iface)?;
            println!("Monitoring packets on {}... (Ctrl+C to stop)", iface);
            spawn_event_readers(&mut ebpf)?;
            signal::ctrl_c().await?;
        }
    }

    Ok(())
}
