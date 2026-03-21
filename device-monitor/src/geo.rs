use maxminddb::{geoip2, Reader};
use serde::Serialize;
use std::net::IpAddr;
use std::path::Path;
use tracing::warn;

use crate::models::Device;

pub struct GeoDb {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GeoInfo {
    pub is_private: bool,
    /// For private IPs: hostname or IP string of the discovered device
    pub device_name: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub asn_number: Option<u32>,
    pub asn_org: Option<String>,
}

impl GeoDb {
    pub fn load(data_dir: &str) -> Self {
        let country = load_reader(data_dir, "GeoLite2-Country.mmdb");
        let asn = load_reader(data_dir, "GeoLite2-ASN.mmdb");
        GeoDb { country, asn }
    }

    pub fn lookup(&self, ip_str: &str, devices: &[Device]) -> GeoInfo {
        let Ok(ip): Result<IpAddr, _> = ip_str.parse() else {
            return GeoInfo::default();
        };

        if is_private(ip) {
            let device_name = if let IpAddr::V4(v4) = ip {
                devices
                    .iter()
                    .find(|d| d.ip == v4)
                    .map(|d| d.hostname.clone().unwrap_or_else(|| d.ip.to_string()))
            } else {
                None
            };
            return GeoInfo {
                is_private: true,
                device_name,
                ..Default::default()
            };
        }

        let mut info = GeoInfo { is_private: false, ..Default::default() };

        if let Some(reader) = &self.country {
            if let Ok(rec) = reader.lookup::<geoip2::Country>(ip) {
                if let Some(c) = rec.country {
                    info.country_code = c.iso_code.map(str::to_owned);
                    info.country_name = c
                        .names
                        .as_ref()
                        .and_then(|m| m.get("en").map(|s| s.to_string()));
                }
            }
        }

        if let Some(reader) = &self.asn {
            if let Ok(rec) = reader.lookup::<geoip2::Asn>(ip) {
                info.asn_number = rec.autonomous_system_number;
                info.asn_org = rec.autonomous_system_organization.map(str::to_owned);
            }
        }

        info
    }
}

fn load_reader(dir: &str, filename: &str) -> Option<Reader<Vec<u8>>> {
    let path = Path::new(dir).join(filename);
    match Reader::open_readfile(&path) {
        Ok(r) => {
            tracing::info!("Loaded {}", path.display());
            Some(r)
        }
        Err(e) => {
            warn!("Could not load {}: {}", path.display(), e);
            None
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _c, _] = v4.octets();
            a == 10
                || a == 127
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 169 && b == 254)
                || (a == 100 && (64..=127).contains(&b))
                || a == 0
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
