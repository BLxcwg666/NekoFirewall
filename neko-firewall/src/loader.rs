use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, Map, MapData},
    pin::PinError,
    programs::{Xdp, XdpFlags},
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

    let program: &mut Xdp = ebpf
        .program_mut("neko_firewall")
        .unwrap()
        .try_into()
        .context("Failed to get XDP program")?;

    program.load().context("Failed to load XDP program")?;
    program
        .attach(iface, XdpFlags::SKB_MODE)
        .with_context(|| format!("Failed to attach XDP to interface {}", iface))?;

    // Pin maps so other CLI invocations can access them
    std::fs::create_dir_all(PIN_PATH).ok();
    for name in ["BLOCKLIST", "PORT_RULES", "EVENTS"] {
        if let Some(map) = ebpf.map_mut(name) {
            let pin = format!("{}/{}", PIN_PATH, name);
            match map.pin(&pin) {
                Ok(()) => info!("Pinned map {} to {}", name, pin),
                Err(PinError::SyscallError(_)) => {
                    // Likely already pinned from a previous run
                    info!("Map {} pin failed (may already exist), continuing", name);
                }
                Err(e) => log::warn!("Failed to pin map {}: {}", name, e),
            }
        }
    }

    info!("XDP program attached to {}", iface);
    Ok(ebpf)
}

pub fn cleanup_pins() {
    for name in ["BLOCKLIST", "PORT_RULES", "EVENTS"] {
        let pin = format!("{}/{}", PIN_PATH, name);
        std::fs::remove_file(&pin).ok();
    }
    std::fs::remove_dir(PIN_PATH).ok();
}

pub fn open_pinned_map(name: &str) -> Result<HashMap<MapData, u32, u32>> {
    let pin = format!("{}/{}", PIN_PATH, name);
    let data = MapData::from_pin(&pin)
        .map_err(|e| anyhow::anyhow!("Failed to open pinned map at {} (is the firewall running?): {}", pin, e))?;
    let map = Map::HashMap(data);
    let hm: HashMap<_, u32, u32> = HashMap::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as HashMap: {:?}", name, e))?;
    Ok(hm)
}
