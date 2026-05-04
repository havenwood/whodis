//! Public data types describing mDNS instances and devices.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

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
        format!("{}.{}.local.", self.name, self.protocol.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    pub service_type: ServiceType,
    pub instance_name: String,
    pub host: String,
    pub port: u16,
    #[serde(with = "txt_map_serde")]
    pub txt: BTreeMap<String, Bytes>,
}

impl Instance {
    #[must_use]
    pub fn fqdn(&self) -> String {
        format!(
            "{}.{}.{}.local.",
            self.instance_name,
            self.service_type.name,
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
            txt: BTreeMap::new(),
        };
        assert_eq!(inst.fqdn(), "Living Room._airplay._tcp.local.");
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
            txt,
        };
        let s = serde_json::to_string(&inst).expect("serialize");
        assert!(s.contains("\"flags\":\"0xff0042\""), "got {s}");
    }
}
