use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, Map, MapData},
    pin::PinError,
    programs::{
        tc::{self, SchedClassifier, TcAttachType},
        Xdp, XdpFlags,
    },
    Ebpf,
};
use log::info;
use std::path::Path;

const EBPF_OBJ_PATH: &str = "target/bpfel-unknown-none/release/neko-ebpf";
const PIN_PATH: &str = "/sys/fs/bpf/neko";

pub fn load_and_attach(iface: &str) -> Result<Ebpf> {
    let path = Path::new(EBPF_OBJ_PATH);
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read eBPF object at {}", path.display()))?;

    let mut ebpf = Ebpf::load(&data).context("Failed to load eBPF program")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        log::warn!("Failed to init eBPF logger: {}", e);
    }

    let xdp: &mut Xdp = ebpf
        .program_mut("neko_firewall")
        .unwrap()
        .try_into()
        .context("Failed to get XDP program")?;
    xdp.load().context("Failed to load XDP program")?;
    xdp.attach(iface, XdpFlags::SKB_MODE)
        .with_context(|| format!("Failed to attach XDP to {}", iface))?;
    info!("XDP program attached to {} (ingress)", iface);

    if let Err(e) = tc::qdisc_add_clsact(iface) {
        log::warn!("qdisc_add_clsact: {} (may already exist)", e);
    }
    let tc_prog: &mut SchedClassifier = ebpf
        .program_mut("neko_egress")
        .unwrap()
        .try_into()
        .context("Failed to get TC program")?;
    tc_prog.load().context("Failed to load TC program")?;
    tc_prog
        .attach(iface, TcAttachType::Egress)
        .with_context(|| format!("Failed to attach TC egress to {}", iface))?;
    info!("TC egress program attached to {} (conntrack)", iface);

    std::fs::create_dir_all(PIN_PATH).ok();
    for name in ["ALLOWED_IPS", "ALLOWED_PORTS", "CONNTRACK", "EVENTS", "GEO_MAP", "GEO_POLICY"] {
        if let Some(map) = ebpf.map_mut(name) {
            let pin = format!("{}/{}", PIN_PATH, name);
            match map.pin(&pin) {
                Ok(()) => info!("Pinned map {}", name),
                Err(PinError::SyscallError(_)) => {
                    info!("Map {} pin skipped (may already exist)", name);
                }
                Err(e) => log::warn!("Failed to pin map {}: {}", name, e),
            }
        }
    }

    Ok(ebpf)
}

pub fn cleanup_pins() {
    for name in ["ALLOWED_IPS", "ALLOWED_PORTS", "CONNTRACK", "EVENTS", "GEO_MAP", "GEO_POLICY"] {
        let pin = format!("{}/{}", PIN_PATH, name);
        std::fs::remove_file(&pin).ok();
    }
    std::fs::remove_dir(PIN_PATH).ok();
}

pub fn open_pinned_hashmap(name: &str) -> Result<HashMap<MapData, u32, u32>> {
    let pin = format!("{}/{}", PIN_PATH, name);
    let data = MapData::from_pin(&pin)
        .map_err(|e| anyhow::anyhow!("Failed to open {}: {} (is the firewall running?)", pin, e))?;
    let map = Map::HashMap(data);
    HashMap::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as HashMap: {:?}", name, e))
}
