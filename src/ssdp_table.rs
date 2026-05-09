//! Loader for SSDP spoof answer tables (TOML format).
//!
//! Schema:
//!
//! ```toml
//! ttl = 1800           # CACHE-CONTROL max-age, default 1800
//! http_port = 5000     # TCP port for the LOCATION HTTP server
//!
//! [[device]]
//! usn = "uuid:abc123::urn:schemas-upnp-org:device:MediaRenderer:1"
//! st  = "urn:schemas-upnp-org:device:MediaRenderer:1"
//! location_path = "/desc.xml"
//! server = "Linux/3.10 UPnP/1.0 WhodisMediaRenderer/1.0"
//! description_xml = """
//! <?xml version="1.0"?>
//! <root xmlns="urn:schemas-upnp-org:device-1-0">
//!   <specVersion><major>1</major><minor>0</minor></specVersion>
//!   <device>
//!     <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
//!     <friendlyName>Whodis Renderer</friendlyName>
//!     <manufacturer>whodis</manufacturer>
//!     <modelName>1</modelName>
//!     <UDN>uuid:abc123</UDN>
//!   </device>
//! </root>
//! """
//! ```

use anyhow::Context;
use serde::Deserialize;

const DEFAULT_TTL: u32 = 1800;
const DEFAULT_HTTP_PORT: u16 = 5000;

#[derive(Debug, Deserialize)]
struct Raw {
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default = "default_http_port")]
    http_port: u16,
    #[serde(default, rename = "device")]
    devices: Vec<RawDevice>,
}

#[derive(Debug, Deserialize)]
struct RawDevice {
    usn: String,
    st: String,
    location_path: String,
    server: String,
    description_xml: String,
}

const fn default_ttl() -> u32 {
    DEFAULT_TTL
}
const fn default_http_port() -> u16 {
    DEFAULT_HTTP_PORT
}

/// One spoofed `UPnP` device's wire-level state.
#[derive(Debug, Clone)]
pub struct SsdpDeviceEntry {
    pub usn: String,
    pub st: String,
    pub location_path: String,
    pub server: String,
    pub description_xml: String,
}

#[derive(Debug, Clone)]
pub struct SsdpAnswerTable {
    pub ttl: u32,
    pub http_port: u16,
    pub devices: Vec<SsdpDeviceEntry>,
}

impl SsdpAnswerTable {
    /// Match an M-SEARCH ST to applicable devices. Per `UPnP` DA §1.3.2:
    /// `ssdp:all` matches everything; `upnp:rootdevice` matches root devices;
    /// otherwise exact case-insensitive match.
    #[must_use]
    pub fn match_st(&self, search_st: &str) -> Vec<&SsdpDeviceEntry> {
        if search_st.eq_ignore_ascii_case("ssdp:all") {
            return self.devices.iter().collect();
        }
        self.devices
            .iter()
            .filter(|d| d.st.eq_ignore_ascii_case(search_st))
            .collect()
    }

    /// Find the device whose `location_path` matches an HTTP request path.
    #[must_use]
    pub fn find_by_path(&self, path: &str) -> Option<&SsdpDeviceEntry> {
        self.devices.iter().find(|d| d.location_path == path)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

pub fn load(toml_src: &str) -> anyhow::Result<SsdpAnswerTable> {
    let raw: Raw = toml::from_str(toml_src).context("parsing SSDP table TOML")?;
    if raw.devices.is_empty() {
        return Err(anyhow::anyhow!("SSDP table has no [[device]] entries"));
    }
    for d in &raw.devices {
        if !d.location_path.starts_with('/') {
            return Err(anyhow::anyhow!(
                "device location_path must start with '/': {}",
                d.location_path
            ));
        }
    }
    let devices = raw
        .devices
        .into_iter()
        .map(|d| SsdpDeviceEntry {
            usn: d.usn,
            st: d.st,
            location_path: d.location_path,
            server: d.server,
            description_xml: d.description_xml,
        })
        .collect();
    Ok(SsdpAnswerTable {
        ttl: raw.ttl,
        http_port: raw.http_port,
        devices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> &'static str {
        r#"
            ttl = 1800
            http_port = 5000

            [[device]]
            usn = "uuid:abc::urn:schemas-upnp-org:device:MediaRenderer:1"
            st = "urn:schemas-upnp-org:device:MediaRenderer:1"
            location_path = "/desc.xml"
            server = "Test/1.0 UPnP/1.0 Test/1.0"
            description_xml = "<?xml version=\"1.0\"?><root/>"
        "#
    }

    #[test]
    fn loads_minimal_table() {
        let t = load(sample_toml()).expect("load");
        assert_eq!(t.devices.len(), 1);
        assert_eq!(t.ttl, 1800);
        assert_eq!(t.http_port, 5000);
        assert_eq!(
            t.devices.first().expect("first device").location_path,
            "/desc.xml"
        );
    }

    #[test]
    fn rejects_empty_device_list() {
        let src = "ttl = 1800";
        assert!(load(src).is_err());
    }

    #[test]
    fn rejects_location_path_without_leading_slash() {
        let src = r#"
            [[device]]
            usn = "uuid:abc::urn:test:1"
            st = "urn:test:1"
            location_path = "desc.xml"
            server = "x"
            description_xml = "<root/>"
        "#;
        assert!(load(src).is_err());
    }

    #[test]
    fn match_st_returns_all_for_ssdp_all() {
        let t = load(sample_toml()).expect("load");
        assert_eq!(t.match_st("ssdp:all").len(), 1);
        assert_eq!(t.match_st("SSDP:ALL").len(), 1);
    }

    #[test]
    fn match_st_is_case_insensitive() {
        let t = load(sample_toml()).expect("load");
        assert_eq!(
            t.match_st("URN:schemas-upnp-org:device:MediaRenderer:1")
                .len(),
            1
        );
    }

    #[test]
    fn match_st_excludes_unrelated_urns() {
        let t = load(sample_toml()).expect("load");
        assert!(
            t.match_st("urn:schemas-upnp-org:device:OtherType:1")
                .is_empty()
        );
    }

    #[test]
    fn find_by_path_locates_device() {
        let t = load(sample_toml()).expect("load");
        assert!(t.find_by_path("/desc.xml").is_some());
        assert!(t.find_by_path("/nope.xml").is_none());
    }
}
