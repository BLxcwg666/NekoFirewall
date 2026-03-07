use anyhow::{Context, Result};
use aya::{
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use log::info;
use std::path::Path;

const EBPF_OBJ_PATH: &str = "target/bpfel-unknown-none/release/neko-ebpf";

pub fn load_and_attach(iface: &str) -> Result<Ebpf> {
    let path = Path::new(EBPF_OBJ_PATH);
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read eBPF object at {}", path.display()))?;

    let mut ebpf = Ebpf::load(&data).context("Failed to load eBPF program")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        log::warn!("Failed to init eBPF logger: {}", e);
    }

    let program: &mut Xdp = ebpf
        .program_mut("neko_firewall")
        .unwrap()
        .try_into()
        .context("Failed to get XDP program")?;

    program.load().context("Failed to load XDP program")?;
    program
        .attach(iface, XdpFlags::default())
        .with_context(|| format!("Failed to attach XDP to interface {}", iface))?;

    info!("XDP program attached to {}", iface);
    Ok(ebpf)
}
