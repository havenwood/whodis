//! Capture a live BLE peripheral's advertising profile and emit a portable TOML document.
//!
//! The TOML is a hand-off artifact for an external radio — macOS `CBPeripheralManager`
//! filters third-party manufacturer data, so whodis cannot replay BLE locally. Optionally
//! includes a GATT service map captured from a connected peripheral.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ble::types::{AddressType, PeripheralId};

/// Captured BLE peripheral profile: passive advertisement + optional GATT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleClone {
    pub advertisement: BleCloneAdvertisement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gatt: Option<BleCloneGatt>,
}

/// Snapshot of one merged BLE advertisement — the richest combination of
/// fields seen across the scan window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneAdvertisement {
    pub peripheral_id: PeripheralId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_type: Option<AddressType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_power: Option<i8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_uuids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub manufacturer_data: BTreeMap<u16, Vec<u8>>,
}

/// GATT service map captured from a connected peripheral.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneGatt {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<BleCloneService>,
    /// Best-effort: errors during connect / discover / read land here
    /// instead of failing the whole clone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneService {
    pub uuid: Uuid,
    pub characteristics: Vec<BleCloneCharacteristic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneCharacteristic {
    pub uuid: Uuid,
    pub properties: Vec<String>,
    /// Captured value, hex-encoded with a `0x` prefix. None if the
    /// characteristic has no `read` property or the read failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_value: Option<String>,
}

impl BleClone {
    /// Format as TOML for replay by an external BLE radio (`BlueZ` / `nRF`).
    /// Output is deterministic so tests can pin the exact bytes.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut s = String::new();
        let _r = writeln!(
            s,
            "# Cloned from BLE peripheral {}",
            self.advertisement.peripheral_id
        );
        let _r = writeln!(
            s,
            "# Replay with an external BLE radio (BlueZ, nRF). macOS does not"
        );
        let _r = writeln!(
            s,
            "# expose the manufacturer-data slot to third-party advertisers."
        );
        let _r = writeln!(s);

        let _r = writeln!(s, "[advertisement]");
        let _r = writeln!(
            s,
            "peripheral_id = {}",
            quote(self.advertisement.peripheral_id.as_str())
        );
        if let Some(name) = self.advertisement.local_name.as_deref() {
            let _r = writeln!(s, "local_name = {}", quote(name));
        }
        if let Some(addr) = self.advertisement.address_type {
            let _r = writeln!(s, "address_type = {}", quote(&format!("{addr:?}")));
        }
        if let Some(tx) = self.advertisement.tx_power {
            let _r = writeln!(s, "tx_power = {tx}");
        }
        if !self.advertisement.service_uuids.is_empty() {
            let quoted: Vec<String> = self
                .advertisement
                .service_uuids
                .iter()
                .map(|u| quote(&u.to_string()))
                .collect();
            let _r = writeln!(s, "service_uuids = [{}]", quoted.join(", "));
        }
        let _r = writeln!(s);

        for (company_id, data) in &self.advertisement.manufacturer_data {
            let _r = writeln!(s, "[[advertisement.manufacturer_data]]");
            let _r = writeln!(s, "company_id = {company_id:#06x}");
            let _r = writeln!(s, "data = {}", quote(&hex_blob(data)));
            let _r = writeln!(s);
        }

        if let Some(gatt) = &self.gatt {
            for service in &gatt.services {
                let _r = writeln!(s, "[[gatt.service]]");
                let _r = writeln!(s, "uuid = {}", quote(&service.uuid.to_string()));
                let _r = writeln!(s);
                for c in &service.characteristics {
                    let _r = writeln!(s, "[[gatt.service.characteristic]]");
                    let _r = writeln!(s, "uuid = {}", quote(&c.uuid.to_string()));
                    let props: Vec<String> = c.properties.iter().map(|p| quote(p)).collect();
                    let _r = writeln!(s, "properties = [{}]", props.join(", "));
                    if let Some(v) = c.last_value.as_deref() {
                        let _r = writeln!(s, "last_value = {}", quote(v));
                    }
                    let _r = writeln!(s);
                }
            }
            for err in &gatt.errors {
                let _r = writeln!(s, "[[gatt.errors]]");
                let _r = writeln!(s, "message = {}", quote(err));
                let _r = writeln!(s);
            }
        }

        s
    }
}

fn quote(s: &str) -> String {
    crate::name_util::toml_quote(s)
}

fn hex_blob(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        let _r = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_toml_emits_minimal_advertisement() {
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("8EF96E6B-4729-AAAA"),
                local_name: Some("Shannon's iPhone".into()),
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: BTreeMap::new(),
            },
            gatt: None,
        };
        let toml = c.to_toml();
        assert!(toml.contains("[advertisement]"), "missing section: {toml}");
        assert!(
            toml.contains(r#"peripheral_id = "8EF96E6B-4729-AAAA""#),
            "missing id: {toml}"
        );
        assert!(
            toml.contains(r#"local_name = "Shannon's iPhone""#),
            "missing name: {toml}"
        );
        assert!(!toml.contains("[gatt"), "should omit gatt: {toml}");
    }

    #[test]
    fn to_toml_emits_manufacturer_data_with_hex_blob() {
        let mut mfr = BTreeMap::new();
        mfr.insert(0x004C, vec![0x10, 0x05, 0x42, 0x78, 0x90, 0x6c]);
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("p1"),
                local_name: None,
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: mfr,
            },
            gatt: None,
        };
        let toml = c.to_toml();
        assert!(
            toml.contains("[[advertisement.manufacturer_data]]"),
            "missing mfr table: {toml}"
        );
        assert!(toml.contains("company_id = 0x004c"), "missing id: {toml}");
        assert!(
            toml.contains(r#"data = "0x10054278906c""#),
            "expected canonical hex blob in: {toml}"
        );
    }

    #[test]
    fn to_toml_emits_gatt_section_when_present() {
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("p1"),
                local_name: None,
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: BTreeMap::new(),
            },
            gatt: Some(BleCloneGatt {
                services: vec![BleCloneService {
                    uuid: Uuid::parse_str("0000180f-0000-1000-8000-00805f9b34fb")
                        .expect("valid uuid"),
                    characteristics: vec![BleCloneCharacteristic {
                        uuid: Uuid::parse_str("00002a19-0000-1000-8000-00805f9b34fb")
                            .expect("valid uuid"),
                        properties: vec!["read".into(), "notify".into()],
                        last_value: Some("0x64".into()),
                    }],
                }],
                errors: vec![],
            }),
        };
        let toml = c.to_toml();
        assert!(toml.contains("[[gatt.service]]"), "missing svc: {toml}");
        assert!(
            toml.contains("[[gatt.service.characteristic]]"),
            "missing char: {toml}"
        );
        assert!(
            toml.contains(r#"properties = ["read", "notify"]"#),
            "{toml}"
        );
        assert!(toml.contains(r#"last_value = "0x64""#), "{toml}");
    }

    #[test]
    fn to_toml_emits_errors_section_when_present() {
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("p1"),
                local_name: None,
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: BTreeMap::new(),
            },
            gatt: Some(BleCloneGatt {
                services: vec![],
                errors: vec!["connect timed out after 5s".into()],
            }),
        };
        let toml = c.to_toml();
        assert!(toml.contains("[[gatt.errors]]"), "missing errors: {toml}");
        assert!(
            toml.contains(r#"message = "connect timed out after 5s""#),
            "{toml}"
        );
    }
}
