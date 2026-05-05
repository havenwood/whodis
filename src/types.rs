//! Public data types describing mDNS instances and devices.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde serialize_with requires &T signature"
)]
fn serialize_mac<S: serde::Serializer>(mac: &[u8; 6], ser: S) -> Result<S::Ok, S::Error> {
    let [o0, o1, o2, o3, o4, o5] = mac;
    let s = format!("{o0:02x}:{o1:02x}:{o2:02x}:{o3:02x}:{o4:02x}:{o5:02x}");
    ser.serialize_str(&s)
}

fn deserialize_mac<'de, D: serde::Deserializer<'de>>(de: D) -> Result<[u8; 6], D::Error> {
    use serde::de::Error as _;
    let s = String::deserialize(de)?;
    let mut it = s.split(':');
    let parse_octet = |p: Option<&str>| -> Result<u8, D::Error> {
        let part = p.ok_or_else(|| D::Error::custom("expected 6 colon-separated hex octets"))?;
        u8::from_str_radix(part, 16)
            .map_err(|_| D::Error::custom(format!("invalid hex octet: {part}")))
    };
    let mac = [
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
    ];
    if it.next().is_some() {
        return Err(D::Error::custom("too many octets in MAC address"));
    }
    Ok(mac)
}

/// Serialize `Option<Duration>` as `Option<f64>` milliseconds, rounded to 2 decimals.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::ref_option,
    reason = "serde serialize_with requires fn(&T, S) where T is the field type"
)]
fn serialize_rtt_ms<S: serde::Serializer>(
    rtt: &Option<std::time::Duration>,
    ser: S,
) -> Result<S::Ok, S::Error> {
    match rtt {
        Some(d) => {
            let ms = d.as_secs_f64() * 1000.0;
            let rounded = (ms * 100.0).round() / 100.0;
            ser.serialize_some(&rounded)
        }
        None => ser.serialize_none(),
    }
}

/// Result of a single sweep probe, enriched with ARP neighbor data.
#[derive(Debug, Clone, Serialize)]
pub struct SweepResult {
    pub ip: IpAddr,
    pub alive: bool,
    #[serde(serialize_with = "serialize_rtt_ms")]
    pub rtt_ms: Option<std::time::Duration>,
    #[serde(
        serialize_with = "serialize_mac_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub mac: Option<[u8; 6]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::ref_option,
    reason = "serde serialize_with requires fn(&T, S) where T is the field type"
)]
fn serialize_mac_opt<S: serde::Serializer>(
    mac: &Option<[u8; 6]>,
    ser: S,
) -> Result<S::Ok, S::Error> {
    match mac {
        Some(m) => serialize_mac(m, ser),
        None => ser.serialize_none(),
    }
}

/// A single ARP or NDP neighbor cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    #[serde(serialize_with = "serialize_mac", deserialize_with = "deserialize_mac")]
    pub mac: [u8; 6],
    pub vendor: Option<String>,
    pub interface: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "_tcp",
            Self::Udp => "_udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceType {
    pub name: String,
    pub protocol: Protocol,
}

impl ServiceType {
    #[must_use]
    pub fn new(name: impl Into<String>, protocol: Protocol) -> Self {
        Self {
            name: name.into(),
            protocol,
        }
    }

    #[must_use]
    pub fn fqdn(&self) -> String {
        format!(
            "{}.{}.local.",
            crate::name_util::escape_label(&self.name),
            self.protocol.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    pub service_type: ServiceType,
    pub instance_name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub addrs: Vec<IpAddr>,
    #[serde(with = "txt_map_serde")]
    pub txt: BTreeMap<String, Bytes>,
}

impl Instance {
    #[must_use]
    pub fn fqdn(&self) -> String {
        format!(
            "{}.{}.{}.local.",
            crate::name_util::escape_label(&self.instance_name),
            crate::name_util::escape_label(&self.service_type.name),
            self.service_type.protocol.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub instance: Instance,
    pub addrs: Vec<IpAddr>,
    pub fingerprint: Option<Fingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub vendor: String,
    pub product: String,
    pub os_hint: Option<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostAnswer {
    pub host: String,
    pub addrs: Vec<IpAddr>,
}

mod txt_map_serde {
    use std::collections::BTreeMap;
    use std::fmt::Write;

    use bytes::Bytes;
    use serde::{Deserializer, Serializer, ser::SerializeMap};

    pub(super) fn serialize<S: Serializer>(
        map: &BTreeMap<String, Bytes>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            let value =
                std::str::from_utf8(v).map_or_else(|_| format!("0x{}", hex_lower(v)), String::from);
            m.serialize_entry(k, &value)?;
        }
        m.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<BTreeMap<String, Bytes>, D::Error> {
        let raw: BTreeMap<String, String> = serde::Deserialize::deserialize(de)?;
        Ok(raw
            .into_iter()
            .map(|(k, v)| (k, Bytes::from(v.into_bytes())))
            .collect())
    }

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_fqdn_roundtrip() {
        let st = ServiceType::new("_airplay", Protocol::Tcp);
        assert_eq!(st.fqdn(), "_airplay._tcp.local.");
    }

    #[test]
    fn instance_fqdn_includes_all_parts() {
        let inst = Instance {
            service_type: ServiceType::new("_airplay", Protocol::Tcp),
            instance_name: "Living Room".into(),
            host: "Living-Room.local".into(),
            port: 7000,
            addrs: Vec::new(),
            txt: BTreeMap::new(),
        };
        assert_eq!(inst.fqdn(), "Living Room._airplay._tcp.local.");
    }

    #[test]
    fn instance_fqdn_escapes_backslash_in_instance_name() {
        let inst = Instance {
            service_type: ServiceType::new("_airplay", Protocol::Tcp),
            instance_name: "back\\slash".into(),
            host: "h.local".into(),
            port: 0,
            addrs: Vec::new(),
            txt: BTreeMap::new(),
        };
        assert_eq!(inst.fqdn(), "back\\\\slash._airplay._tcp.local.");
    }

    #[test]
    fn instance_fqdn_preserves_unicode_in_instance_name() {
        let inst = Instance {
            service_type: ServiceType::new("_airplay", Protocol::Tcp),
            instance_name: "Shannon\u{2019}s MacBook Pro".into(),
            host: "h.local".into(),
            port: 0,
            addrs: Vec::new(),
            txt: BTreeMap::new(),
        };
        assert_eq!(
            inst.fqdn(),
            "Shannon\u{2019}s MacBook Pro._airplay._tcp.local."
        );
    }

    #[test]
    fn instance_serializes_txt_as_strings() {
        let mut txt = BTreeMap::new();
        txt.insert("model".into(), Bytes::from_static(b"AppleTV11,1"));
        let inst = Instance {
            service_type: ServiceType::new("_airplay", Protocol::Tcp),
            instance_name: "Living".into(),
            host: "h.local".into(),
            port: 7000,
            addrs: Vec::new(),
            txt,
        };
        let s = serde_json::to_string(&inst).expect("serialize");
        assert!(s.contains("\"model\":\"AppleTV11,1\""), "got {s}");
    }

    #[test]
    fn instance_serializes_binary_txt_as_hex() {
        let mut txt = BTreeMap::new();
        txt.insert("flags".into(), Bytes::from_static(&[0xff, 0x00, 0x42]));
        let inst = Instance {
            service_type: ServiceType::new("_x", Protocol::Tcp),
            instance_name: "x".into(),
            host: "x.local".into(),
            port: 1,
            addrs: Vec::new(),
            txt,
        };
        let s = serde_json::to_string(&inst).expect("serialize");
        assert!(s.contains("\"flags\":\"0xff0042\""), "got {s}");
    }

    #[test]
    fn sweep_result_rtt_rounds_to_two_decimals() {
        let result = SweepResult {
            ip: "127.0.0.1".parse().expect("parse ip"),
            alive: true,
            rtt_ms: Some(std::time::Duration::from_secs_f64(0.013_384_625)),
            mac: None,
            vendor: None,
            interface: None,
        };
        let s = serde_json::to_string(&result).expect("serialize");
        assert!(
            s.contains("\"rtt_ms\":13.38"),
            "expected 13.38 in JSON, got {s}"
        );
    }
}
