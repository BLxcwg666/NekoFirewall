use anyhow::{ensure, Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use ipnetwork::IpNetwork;
use log::info;
use maxminddb::geoip2;

use crate::loader;

use crate::config::Config;

const COUNTRY_MMDB: &[u8] = include_bytes!("../resources/GeoLite2-Country.mmdb");
const ASN_MMDB: &[u8] = include_bytes!("../resources/GeoLite2-ASN.mmdb");

pub fn country_to_id(code: &str) -> Result<u32> {
    let code = normalize_country_code(code)?;
    Ok(country_to_id_unchecked(&code))
}

fn country_to_id_unchecked(code: &str) -> u32 {
    let b = code.as_bytes();
    (b[0] as u32) << 8 | b[1] as u32
}

pub fn id_to_country(id: u32) -> String {
    let a = ((id >> 8) & 0xFF) as u8 as char;
    let b = (id & 0xFF) as u8 as char;
    format!("{}{}", a, b)
}

pub fn load_geo_map(ebpf: &mut aya::Ebpf) -> Result<(usize, usize)> {
    let reader = maxminddb::Reader::from_source(COUNTRY_MMDB.to_vec())
        .context("Failed to load embedded Country mmdb")?;

    let map4 = ebpf.take_map("GEO_COUNTRY_MAP").context("GEO_COUNTRY_MAP not found")?;
    let mut trie4: LpmTrie<_, u32, u32> =
        LpmTrie::try_from(map4).context("Failed to open GEO_COUNTRY_MAP")?;

    let map6 = ebpf.take_map("GEO_COUNTRY_MAP6").context("GEO_COUNTRY_MAP6 not found")?;
    let mut trie6: LpmTrie<_, [u8; 16], u32> =
        LpmTrie::try_from(map6).context("Failed to open GEO_COUNTRY_MAP6")?;

    let mut count4 = 0usize;
    let mut count6 = 0usize;

    for result in reader.networks(Default::default())? {
        let item = result?;
        let record: Option<geoip2::Country> = item.decode()?;
        if let Some(record) = record {
            if let Some(iso_code) = record.country.iso_code {
                let geo_id = match country_to_id(iso_code) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                match item.network() {
                    Ok(IpNetwork::V4(net)) => {
                        let prefix_len = net.prefix() as u32;
                        let ip_be = u32::from(net.ip()).to_be();
                        let key = Key::new(prefix_len, ip_be);
                        let _ = trie4.insert(&key, geo_id, 0);
                        count4 += 1;
                    }
                    Ok(IpNetwork::V6(net)) => {
                        let prefix_len = net.prefix() as u32;
                        let key = Key::new(prefix_len, net.ip().octets());
                        let _ = trie6.insert(&key, geo_id, 0);
                        count6 += 1;
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    info!(
        "Loaded {} IPv4 + {} IPv6 country prefixes",
        count4, count6
    );
    Ok((count4, count6))
}

pub fn load_asn_map(ebpf: &mut aya::Ebpf) -> Result<(usize, usize)> {
    let reader = maxminddb::Reader::from_source(ASN_MMDB.to_vec())
        .context("Failed to load embedded ASN mmdb")?;

    let map4 = ebpf.take_map("GEO_ASN_MAP").context("GEO_ASN_MAP not found")?;
    let mut trie4: LpmTrie<_, u32, u32> =
        LpmTrie::try_from(map4).context("Failed to open GEO_ASN_MAP")?;

    let map6 = ebpf.take_map("GEO_ASN_MAP6").context("GEO_ASN_MAP6 not found")?;
    let mut trie6: LpmTrie<_, [u8; 16], u32> =
        LpmTrie::try_from(map6).context("Failed to open GEO_ASN_MAP6")?;

    let mut count4 = 0usize;
    let mut count6 = 0usize;

    for result in reader.networks(Default::default())? {
        let item = result?;
        let record: Option<geoip2::Asn> = item.decode()?;
        if let Some(record) = record {
            if let Some(asn) = record.autonomous_system_number {
                let asn_id = 0x80000000 | asn;
                match item.network() {
                    Ok(IpNetwork::V4(net)) => {
                        let prefix_len = net.prefix() as u32;
                        let ip_be = u32::from(net.ip()).to_be();
                        let key = Key::new(prefix_len, ip_be);
                        let _ = trie4.insert(&key, asn_id, 0);
                        count4 += 1;
                    }
                    Ok(IpNetwork::V6(net)) => {
                        let prefix_len = net.prefix() as u32;
                        let key = Key::new(prefix_len, net.ip().octets());
                        let _ = trie6.insert(&key, asn_id, 0);
                        count6 += 1;
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    info!("Loaded {} IPv4 + {} IPv6 ASN prefixes", count4, count6);
    Ok((count4, count6))
}

pub fn set_country_policy(action: u32, code: &str) -> Result<()> {
    let geo_id = country_to_id(code)?;
    let mut map = open_geo_policy()?;
    map.insert(geo_id, action, 0)?;

    let mut cfg = Config::load()?;
    cfg.set_country(action, code);
    cfg.save()?;
    Ok(())
}

pub fn set_asn_policy(action: u32, asn: u32) -> Result<()> {
    let asn_id = 0x80000000 | asn;
    let mut map = open_geo_policy()?;
    map.insert(asn_id, action, 0)?;

    let mut cfg = Config::load()?;
    cfg.set_asn(action, asn);
    cfg.save()?;
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

fn open_geo_policy() -> Result<aya::maps::HashMap<aya::maps::MapData, u32, u32>> {
    loader::open_pinned_hashmap("GEO_POLICY")
}

fn normalize_country_code(code: &str) -> Result<String> {
    let code = code.trim();
    ensure!(
        code.len() == 2 && code.is_ascii() && code.bytes().all(|b| b.is_ascii_alphabetic()),
        "Invalid country code: {} (expected ISO 3166-1 alpha-2 like US or CN)",
        code
    );
    Ok(code.to_ascii_uppercase())
}
