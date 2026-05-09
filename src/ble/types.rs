//! Public BLE data types.
//!
//! [`PeripheralId`] is the universal identifier — on macOS it's the
//! `CoreBluetooth` UUID string, on Linux it's the `BD_ADDR` rendered as
//! `AA:BB:CC:DD:EE:FF`. Treat the inner string as opaque; just use
//! it for equality, hashing, and display.

use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeripheralId(pub String);

impl PeripheralId {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeripheralId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for PeripheralId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressType {
    Public,
    RandomStatic,
    RandomResolvable,
    RandomNonResolvable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AirDropMode {
    Off,
    ContactsOnly,
    Everyone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Phone,
    Tablet,
    Laptop,
    Watch,
    Earbuds,
    Tag,
    SmartLock,
    BadgeReader,
    SmartHome,
    Unknown,
}

/// One BLE advertisement event: what we observed on the radio at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleAdvertisement {
    pub peripheral_id: PeripheralId,
    pub address_type: Option<AddressType>,
    pub rssi: i16,
    pub local_name: Option<String>,
    pub manufacturer_data: BTreeMap<u16, Vec<u8>>,
    pub service_uuids: Vec<Uuid>,
    pub tx_power: Option<i8>,
    #[serde(with = "system_time_millis")]
    pub timestamp: SystemTime,
}

/// Aggregated view of one BLE device after fingerprinting and Continuity decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleDevice {
    pub peripheral_id: PeripheralId,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub device_class: DeviceClass,
    pub continuity: Vec<crate::ble::continuity::ContinuityPayload>,
    pub airdrop_mode: Option<AirDropMode>,
    #[serde(with = "system_time_millis")]
    pub last_seen: SystemTime,
    #[serde(with = "system_time_millis")]
    pub first_seen: SystemTime,
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
    fn peripheral_id_display_round_trips() {
        let id = PeripheralId::new("E5C4A3B1-7F23-4A1C-9D5F-B6E8C2A0B1F3");
        assert_eq!(id.to_string(), "E5C4A3B1-7F23-4A1C-9D5F-B6E8C2A0B1F3");
        assert_eq!(id.as_str(), "E5C4A3B1-7F23-4A1C-9D5F-B6E8C2A0B1F3");
        let parsed: PeripheralId = "AA:BB:CC:DD:EE:FF".parse().expect("parse");
        assert_eq!(parsed.0, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn ble_advertisement_serde_round_trips() {
        let ad = BleAdvertisement {
            peripheral_id: PeripheralId::new("test-id"),
            address_type: Some(AddressType::RandomResolvable),
            rssi: -45,
            local_name: Some("AirPods".into()),
            manufacturer_data: std::iter::once((0x004C, vec![0x12, 0x34])).collect(),
            service_uuids: vec![],
            tx_power: Some(8),
            timestamp: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        };
        let json = serde_json::to_string(&ad).expect("serialize");
        let back: BleAdvertisement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ad, back);
    }
}
