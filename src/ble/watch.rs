//! Recon-flavored BLE watch anomaly tracker.
//!
//! Parallel to [`crate::detect`] but for advertisement events instead of
//! mDNS messages. The tracker is pure logic — feed it [`BleAdvertisement`]
//! observations with a clock, get back a `Vec<BleAnomaly>`. Dedup is
//! permanent within a session via `HashSet<BleAnomalyKey>`.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::ble::{DeviceClass, PeripheralId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Arrived,
    Departed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum BleAnomaly {
    DevicePresence {
        peripheral_id: PeripheralId,
        state: PresenceState,
        #[serde(with = "system_time_millis")]
        since: SystemTime,
    },
    AirDropEveryoneMode {
        peripheral_id: PeripheralId,
        #[serde(with = "system_time_millis")]
        observed_at: SystemTime,
    },
    LockStateChange {
        peripheral_id: PeripheralId,
        prev: LockState,
        curr: LockState,
    },
    DeviceClassClassification {
        peripheral_id: PeripheralId,
        device_class: DeviceClass,
    },
    UnknownContinuityType {
        ty: u8,
        count: usize,
    },
}

impl BleAnomaly {
    /// Severity hint for downstream presentation. v1 is uniformly "high"
    /// because every recon anomaly here is engagement-relevant; the field
    /// is reserved for future tuning.
    #[must_use]
    pub const fn severity(&self) -> &'static str {
        "high"
    }
}

/// Dedup key. One [`BleAnomaly`] variant lands once per session per key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code, reason = "consumed by AnomalyTracker dedup in Task 2")]
pub(crate) enum BleAnomalyKey {
    Presence(PeripheralId, PresenceState),
    AirDropEveryone(PeripheralId),
    LockChange(PeripheralId),
    Classification(PeripheralId),
    UnknownContinuityType(u8),
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
    fn ble_anomaly_serializes_with_class_tag() {
        let a = BleAnomaly::DevicePresence {
            peripheral_id: PeripheralId::new("test"),
            state: PresenceState::Arrived,
            since: SystemTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&a).expect("serialize");
        assert!(json.contains(r#""class":"device_presence""#), "got {json}");
    }

    #[test]
    fn unknown_continuity_type_round_trips() {
        let a = BleAnomaly::UnknownContinuityType { ty: 0xAB, count: 7 };
        let s = serde_json::to_string(&a).expect("ser");
        let back: BleAnomaly = serde_json::from_str(&s).expect("de");
        assert_eq!(a, back);
    }
}
