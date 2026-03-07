use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Map, MapData};
use ipnetwork::IpNetwork;
use log::info;
use maxminddb::geoip2;

const COUNTRY_MMDB: &[u8] = include_bytes!("../resources/GeoLite2-Country.mmdb");
const ASN_MMDB: &[u8] = include_bytes!("../resources/GeoLite2-ASN.mmdb");

pub fn country_to_id(code: &str) -> u32 {
    let b = code.as_bytes();
    (b[0] as u32) << 8 | b[1] as u32
}

pub fn id_to_country(id: u32) -> String {
    let a = ((id >> 8) & 0xFF) as u8 as char;
    let b = (id & 0xFF) as u8 as char;
    format!("{}{}", a, b)
}

pub fn load_geo_map(ebpf: &mut aya::Ebpf) -> Result<usize> {
    let reader = maxminddb::Reader::from_source(COUNTRY_MMDB.to_vec())
        .context("Failed to load embedded Country mmdb")?;

    let map = ebpf.map_mut("GEO_MAP").context("GEO_MAP not found")?;
    let mut trie: LpmTrie<_, u32, u32> =
        LpmTrie::try_from(map).context("Failed to open GEO_MAP")?;

    let mut count = 0usize;

    for result in reader.networks(Default::default())? {
        let item = result?;
        let record: Option<geoip2::Country> = item.decode()?;
        if let Some(record) = record {
            if let Some(iso_code) = record.country.iso_code {
                if let Ok(IpNetwork::V4(net)) = item.network() {
                    let prefix_len = net.prefix() as u32;
                    let ip_be = u32::from(net.ip()).to_be();
                    let key = Key::new(prefix_len, ip_be);
                    let geo_id = country_to_id(iso_code);
                    let _ = trie.insert(&key, geo_id, 0);
                    count += 1;
                }
            }
        }
    }

    info!("Loaded {} country prefixes into GEO_MAP", count);
    Ok(count)
}

pub fn load_asn_map(ebpf: &mut aya::Ebpf) -> Result<usize> {
    let reader = maxminddb::Reader::from_source(ASN_MMDB.to_vec())
        .context("Failed to load embedded ASN mmdb")?;

    let map = ebpf.map_mut("GEO_MAP").context("GEO_MAP not found")?;
    let mut trie: LpmTrie<_, u32, u32> =
        LpmTrie::try_from(map).context("Failed to open GEO_MAP")?;

    let mut count = 0usize;

    for result in reader.networks(Default::default())? {
        let item = result?;
        let record: Option<geoip2::Asn> = item.decode()?;
        if let Some(record) = record {
            if let Some(asn) = record.autonomous_system_number {
                if let Ok(IpNetwork::V4(net)) = item.network() {
                    let prefix_len = net.prefix() as u32;
                    let ip_be = u32::from(net.ip()).to_be();
                    let key = Key::new(prefix_len, ip_be);
                    let asn_id = 0x80000000 | asn;
                    let _ = trie.insert(&key, asn_id, 0);
                    count += 1;
                }
            }
        }
    }

    info!("Loaded {} ASN prefixes into GEO_MAP", count);
    Ok(count)
}

pub fn set_country_policy(action: u32, code: &str) -> Result<()> {
    let geo_id = country_to_id(&code.to_uppercase());
    let mut map = open_geo_policy()?;
    map.insert(geo_id, action, 0)?;
    Ok(())
}

pub fn remove_country_policy(code: &str) -> Result<()> {
    let geo_id = country_to_id(&code.to_uppercase());
    let mut map = open_geo_policy()?;
    map.remove(&geo_id)?;
    Ok(())
}

pub fn set_asn_policy(action: u32, asn: u32) -> Result<()> {
    let asn_id = 0x80000000 | asn;
    let mut map = open_geo_policy()?;
    map.insert(asn_id, action, 0)?;
    Ok(())
}

pub fn remove_asn_policy(asn: u32) -> Result<()> {
    let asn_id = 0x80000000 | asn;
    let mut map = open_geo_policy()?;
    map.remove(&asn_id)?;
    Ok(())
}

pub fn list_policies() -> Result<()> {
    let map = open_geo_policy()?;
    let mut count = 0u32;
    for res in map.iter() {
        let (id, action) = res.context("Failed to read geo policy")?;
        let action_str = if action == 0 { "ALLOW" } else { "DROP" };
        if id & 0x80000000 != 0 {
            println!("  {} ASN {}", action_str, id & 0x7FFFFFFF);
        } else {
            println!("  {} country {}", action_str, id_to_country(id));
        }
        count += 1;
    }
    if count == 0 {
        println!("  (none)");
    }
    Ok(())
}

fn open_geo_policy() -> Result<aya::maps::HashMap<MapData, u32, u32>> {
    let pin = "/sys/fs/bpf/neko/GEO_POLICY";
    let data = MapData::from_pin(pin)
        .map_err(|e| anyhow::anyhow!("GEO_POLICY: {} (is the firewall running?)", e))?;
    let map = Map::HashMap(data);
    aya::maps::HashMap::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed to open GEO_POLICY: {:?}", e))
}
