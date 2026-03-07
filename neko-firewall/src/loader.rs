use anyhow::{Context, Result};
use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        Array, HashMap, Map, MapData, MapInfo, MapType,
    },
    programs::{
        tc::{self, SchedClassifier, TcAttachType},
        Xdp, XdpFlags,
    },
    Ebpf, EbpfLoader, Pod,
};
use log::info;
use neko_common::{CompoundRule, MAX_COMPOUND_RULES};
use std::process::Command;

const EBPF_OBJ: &[u8] =
    include_bytes!("../../target/bpfel-unknown-none/release/neko-ebpf");
const PIN_PATH: &str = "/sys/fs/bpf/neko";

pub fn load(_iface: &str) -> Result<Ebpf> {

    std::fs::create_dir_all(PIN_PATH)
        .with_context(|| format!("Failed to create pin path {}", PIN_PATH))?;

    // .to_vec() ensures 8-byte alignment required for ELF parsing
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(PIN_PATH)
        .load(&EBPF_OBJ.to_vec())
        .context("Failed to load eBPF program")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        log::warn!("Failed to init eBPF logger: {}", e);
    }

    // Load programs into kernel (but don't attach yet)
    let xdp: &mut Xdp = ebpf
        .program_mut("neko_firewall")
        .unwrap()
        .try_into()
        .context("Failed to get XDP program")?;
    xdp.load().context("Failed to load XDP program")?;

    let tc_prog: &mut SchedClassifier = ebpf
        .program_mut("neko_egress")
        .unwrap()
        .try_into()
        .context("Failed to get TC program")?;
    tc_prog.load().context("Failed to load TC program")?;

    Ok(ebpf)
}

pub fn attach(ebpf: &mut Ebpf, iface: &str) -> Result<()> {
    let xdp: &mut Xdp = ebpf
        .program_mut("neko_firewall")
        .unwrap()
        .try_into()
        .context("Failed to get XDP program")?;
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
    tc_prog
        .attach(iface, TcAttachType::Egress)
        .with_context(|| format!("Failed to attach TC egress to {}", iface))?;
    info!("TC egress program attached to {} (conntrack)", iface);

    Ok(())
}

pub fn reset_runtime_maps(ebpf: &mut Ebpf) -> Result<()> {
    // Don't clear CONNTRACK — preserve existing connections (e.g. SSH)
    clear_lpm_trie::<u32, u32>(ebpf, "GEO_COUNTRY_MAP")?;
    clear_lpm_trie::<u32, u32>(ebpf, "GEO_ASN_MAP")?;
    clear_array::<CompoundRule>(ebpf, "RULES")?;
    Ok(())
}

pub fn cleanup_pins() {
    for name in [
        "ALLOWED_IPS",
        "ALLOWED_PORTS",
        "CONNTRACK",
        "EVENTS",
        "GEO_COUNTRY_MAP",
        "GEO_ASN_MAP",
        "GEO_POLICY",
        "GEO_MAP",
        "RULES",
    ] {
        let pin = format!("{}/{}", PIN_PATH, name);
        std::fs::remove_file(&pin).ok();
    }
    std::fs::remove_dir(PIN_PATH).ok();
}

pub fn force_stop(iface: &str) -> Result<()> {
    let xdp_out = Command::new("ip")
        .args(["link", "set", "dev", iface, "xdpgeneric", "off"])
        .output()
        .context("Failed to run 'ip' command")?;
    if xdp_out.status.success() {
        println!("Detached XDP from {}", iface);
    } else {
        let stderr = String::from_utf8_lossy(&xdp_out.stderr);
        if !stderr.contains("No such device") {
            eprintln!("Warning: XDP detach: {}", stderr.trim());
        }
    }

    let tc_out = Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .output()
        .context("Failed to run 'tc' command")?;
    if tc_out.status.success() {
        println!("Removed TC qdisc from {}", iface);
    } else {
        let stderr = String::from_utf8_lossy(&tc_out.stderr);
        if !stderr.contains("Cannot find") {
            eprintln!("Warning: TC detach: {}", stderr.trim());
        }
    }

    cleanup_pins();
    println!("Cleaned up pinned maps");
    Ok(())
}

pub fn open_pinned_hashmap<K: Pod, V: Pod>(name: &str) -> Result<HashMap<MapData, K, V>> {
    let map = open_pinned_map(name)?;
    HashMap::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as HashMap: {:?}", name, e))
}

pub fn open_pinned_lpm_trie<K: Pod, V: Pod>(name: &str) -> Result<LpmTrie<MapData, K, V>> {
    let map = open_pinned_map(name)?;
    LpmTrie::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as LpmTrie: {:?}", name, e))
}

pub fn open_pinned_perf_event_array(name: &str) -> Result<Map> {
    let map = open_pinned_map(name)?;
    match map {
        Map::PerfEventArray(_) => Ok(map),
        other => Err(anyhow::anyhow!(
            "Failed to open {} as PerfEventArray: actual type {:?}",
            name,
            other
        )),
    }
}

pub fn open_pinned_map(name: &str) -> Result<Map> {
    let pin = format!("{}/{}", PIN_PATH, name);
    let data = MapData::from_pin(&pin)
        .map_err(|e| anyhow::anyhow!("Failed to open {}: {} (is the firewall running?)", pin, e))?;
    let info =
        MapInfo::from_pin(&pin).map_err(|e| anyhow::anyhow!("Failed to inspect {}: {}", pin, e))?;
    let map = match info.map_type()? {
        MapType::Hash => Map::HashMap(data),
        MapType::LruHash => Map::LruHashMap(data),
        MapType::LpmTrie => Map::LpmTrie(data),
        MapType::PerfEventArray => Map::PerfEventArray(data),
        MapType::Array => Map::Array(data),
        other => {
            return Err(anyhow::anyhow!(
                "Unsupported pinned map type {:?} for {}",
                other,
                name
            ));
        }
    };
    Ok(map)
}

fn clear_hash_map<K: Pod, V: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let map = ebpf
        .map_mut(name)
        .with_context(|| format!("{} map not found", name))?;
    let mut typed: HashMap<_, K, V> = HashMap::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as HashMap: {:?}", name, e))?;
    let keys = typed
        .keys()
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to enumerate {}", name))?;
    for key in keys {
        typed
            .remove(&key)
            .with_context(|| format!("Failed to clear {}", name))?;
    }
    Ok(())
}

fn clear_lpm_trie<K: Pod, V: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let map = ebpf
        .map_mut(name)
        .with_context(|| format!("{} map not found", name))?;
    let mut typed: LpmTrie<_, K, V> = LpmTrie::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as LpmTrie: {:?}", name, e))?;
    let keys = typed
        .keys()
        .collect::<std::result::Result<Vec<Key<K>>, _>>()
        .with_context(|| format!("Failed to enumerate {}", name))?;
    for key in keys {
        typed
            .remove(&key)
            .with_context(|| format!("Failed to clear {}", name))?;
    }
    Ok(())
}

fn clear_array<V: Pod + Default>(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let map = ebpf
        .map_mut(name)
        .with_context(|| format!("{} map not found", name))?;
    let mut typed: Array<_, V> = Array::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open {} as Array: {:?}", name, e))?;
    for i in 0..MAX_COMPOUND_RULES {
        let _ = typed.set(i, V::default(), 0);
    }
    Ok(())
}
