//! Typed observations from each whodis observation source. The inventory
//! graph ingests these as the only input — never raw bytes, never sockets.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ble::{DeviceClass, PeripheralId};

/// One observation event from any source. Tagged via `kind` for JSONL output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation {
    /// ARP/NDP neighbor cache entry — IP↔MAC binding with interface context.
    Neighbor {
        ip: IpAddr,
        mac: [u8; 6],
        vendor: Option<String>,
        interface: String,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    /// Sweep result — IP reachability + latency, optionally with MAC enrichment.
    SweepHost {
        ip: IpAddr,
        alive: bool,
        rtt_ms: Option<f64>,
        mac: Option<[u8; 6]>,
        vendor: Option<String>,
        interface: String,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    /// mDNS instance discovered or updated.
    MdnsInstance {
        fqdn: String,
        service_type: String,
        instance_name: String,
        host: String,
        port: u16,
        addrs: Vec<IpAddr>,
        txt: BTreeMap<String, String>,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    /// mDNS instance goodbye (TTL=0 announce or explicit byebye).
    MdnsGoodbye {
        fqdn: String,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    /// SSDP service announcement (NOTIFY ssdp:alive or M-SEARCH reply).
    SsdpService {
        usn: String,
        st: String,
        location: Option<String>,
        server: Option<String>,
        src_ip: IpAddr,
        max_age: Option<u32>,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    /// SSDP byebye (NOTIFY ssdp:byebye).
    SsdpByebye {
        usn: String,
        src_ip: IpAddr,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    /// BLE peripheral advertisement (one snapshot).
    BleDevice {
        peripheral_id: PeripheralId,
        local_name: Option<String>,
        vendor: Option<String>,
        product: Option<String>,
        device_class: DeviceClass,
        rssi: i16,
        service_uuids: Vec<Uuid>,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
}

impl Observation {
    /// The wall-clock time the observation was recorded.
    #[must_use]
    pub const fn observed_at(&self) -> SystemTime {
        match self {
            Self::Neighbor { observed_at, .. }
            | Self::SweepHost { observed_at, .. }
            | Self::MdnsInstance { observed_at, .. }
            | Self::MdnsGoodbye { observed_at, .. }
            | Self::SsdpService { observed_at, .. }
            | Self::SsdpByebye { observed_at, .. }
            | Self::BleDevice { observed_at, .. } => *observed_at,
        }
    }
}

mod system_time_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub(super) fn serialize<S: Serializer>(t: &SystemTime, ser: S) -> Result<S::Ok, S::Error> {
        let millis = t
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis();
        u64::try_from(millis).unwrap_or(0).serialize(ser)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<SystemTime, D::Error> {
        let millis: u64 = u64::deserialize(de)?;
        Ok(UNIX_EPOCH + Duration::from_millis(millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_round_trips_through_json() {
        let obs = Observation::Neighbor {
            ip: "10.0.5.20".parse().expect("ip"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: Some("Apple".into()),
            interface: "en0".into(),
            observed_at: SystemTime::UNIX_EPOCH,
        };
        let s = serde_json::to_string(&obs).expect("ser");
        let back: Observation = serde_json::from_str(&s).expect("de");
        assert_eq!(obs, back);
        assert!(s.contains(r#""kind":"neighbor""#), "got {s}");
    }

    #[test]
    fn mdns_instance_observation_carries_addrs_and_txt() {
        let mut txt = std::collections::BTreeMap::new();
        txt.insert("model".to_string(), "AppleTV6,2".to_string());
        let obs = Observation::MdnsInstance {
            fqdn: "Living Room._airplay._tcp.local.".into(),
            service_type: "_airplay._tcp.local.".into(),
            instance_name: "Living Room".into(),
            host: "AppleTV.local.".into(),
            port: 7000,
            addrs: vec!["10.0.5.20".parse().expect("ip")],
            txt,
            observed_at: SystemTime::UNIX_EPOCH,
        };
        let s = serde_json::to_string(&obs).expect("ser");
        let back: Observation = serde_json::from_str(&s).expect("de");
        assert_eq!(obs, back);
    }
}
