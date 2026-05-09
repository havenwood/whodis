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
pub(crate) enum BleAnomalyKey {
    Presence(PeripheralId, PresenceState),
    #[allow(dead_code, reason = "consumed by Tasks 3-4")]
    AirDropEveryone(PeripheralId),
    #[allow(dead_code, reason = "consumed by Task 4")]
    LockChange(PeripheralId),
    #[allow(dead_code, reason = "consumed by Task 3")]
    Classification(PeripheralId),
    #[allow(dead_code, reason = "consumed by Task 3")]
    UnknownContinuityType(u8),
}

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::ble::BleAdvertisement;

/// Threshold after which a peripheral is considered Departed.
#[allow(clippy::duration_suboptimal_units, reason = "from_mins not available")]
const DEPARTED_AFTER: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
struct PeripheralState {
    #[allow(dead_code, reason = "consumed by Task 4 lock-state inference")]
    first_seen: SystemTime,
    last_seen: SystemTime,
    #[allow(dead_code, reason = "consumed by Task 4 lock-state inference")]
    last_wake_status: Option<u8>,
    #[allow(dead_code, reason = "consumed by Task 3 classification tracking")]
    classification: Option<DeviceClass>,
}

/// Pure-logic recon anomaly tracker. Public so embedders can drive it
/// directly without sockets.
#[derive(Debug, Default)]
pub struct AnomalyTracker {
    peripherals: HashMap<PeripheralId, PeripheralState>,
    #[allow(dead_code, reason = "consumed by Task 3 unknown-type tracking")]
    unknown_ty_counts: HashMap<u8, usize>,
    reported: HashSet<BleAnomalyKey>,
}

impl AnomalyTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one advertisement at the current real-time clock.
    pub fn observe(&mut self, ad: &BleAdvertisement) -> Vec<BleAnomaly> {
        self.observe_at(ad, SystemTime::now())
    }

    /// Test hook: explicit clock so windowed checks are deterministic.
    pub fn observe_at(&mut self, ad: &BleAdvertisement, now: SystemTime) -> Vec<BleAnomaly> {
        let mut out = Vec::new();
        let id = ad.peripheral_id.clone();

        // Presence: Arrived (first sight or post-Departed re-arrival).
        let arrived_now = self.peripherals.get(&id).is_none_or(|state| {
            now.duration_since(state.last_seen)
                .unwrap_or(Duration::ZERO)
                > DEPARTED_AFTER
        });
        if arrived_now {
            // Clear a prior Departed dedup so the next departure can fire again.
            self.reported.remove(&BleAnomalyKey::Presence(
                id.clone(),
                PresenceState::Departed,
            ));
            let key = BleAnomalyKey::Presence(id.clone(), PresenceState::Arrived);
            if self.reported.insert(key) {
                out.push(BleAnomaly::DevicePresence {
                    peripheral_id: id.clone(),
                    state: PresenceState::Arrived,
                    since: now,
                });
            }
        }

        let entry = self
            .peripherals
            .entry(id)
            .or_insert_with(|| PeripheralState {
                first_seen: now,
                last_seen: now,
                last_wake_status: None,
                classification: None,
            });
        entry.last_seen = now;

        out
    }

    /// Periodic tick: emit `Departed` for peripherals not seen in
    /// `DEPARTED_AFTER`. Call this once per ~30s from the run loop.
    pub fn tick_at(&mut self, now: SystemTime) -> Vec<BleAnomaly> {
        let mut out = Vec::new();
        let stale: Vec<(PeripheralId, SystemTime)> = self
            .peripherals
            .iter()
            .filter_map(|(id, state)| {
                let dur = now
                    .duration_since(state.last_seen)
                    .unwrap_or(Duration::ZERO);
                if dur > DEPARTED_AFTER {
                    Some((id.clone(), state.last_seen))
                } else {
                    None
                }
            })
            .collect();
        for (id, last_seen) in stale {
            // Clear the prior Arrived dedup so re-arrival fires fresh.
            self.reported
                .remove(&BleAnomalyKey::Presence(id.clone(), PresenceState::Arrived));
            let key = BleAnomalyKey::Presence(id.clone(), PresenceState::Departed);
            if self.reported.insert(key) {
                out.push(BleAnomaly::DevicePresence {
                    peripheral_id: id,
                    state: PresenceState::Departed,
                    since: last_seen,
                });
            }
        }
        out
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

#[cfg(test)]
mod presence_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ad(id: &str) -> BleAdvertisement {
        BleAdvertisement {
            peripheral_id: PeripheralId::new(id),
            address_type: None,
            rssi: -50,
            local_name: None,
            manufacturer_data: BTreeMap::new(),
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn first_sight_emits_arrived_once() {
        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let first = t.observe_at(&ad("p1"), now);
        assert!(matches!(
            first.first(),
            Some(BleAnomaly::DevicePresence {
                state: PresenceState::Arrived,
                ..
            })
        ));
        let second = t.observe_at(&ad("p1"), now + Duration::from_secs(1));
        assert!(
            second.is_empty(),
            "second observation should not re-fire arrived, got {second:?}"
        );
    }

    #[test]
    fn departed_fires_when_unseen_past_threshold() {
        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        drop(t.observe_at(&ad("p1"), now));
        let later = now + DEPARTED_AFTER + Duration::from_secs(1);
        let dep = t.tick_at(later);
        assert_eq!(dep.len(), 1);
        assert!(matches!(
            dep.first(),
            Some(BleAnomaly::DevicePresence {
                state: PresenceState::Departed,
                ..
            })
        ));
    }

    #[test]
    fn re_arrival_after_departed_emits_arrived_again() {
        let mut t = AnomalyTracker::new();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        drop(t.observe_at(&ad("p1"), t0));
        drop(t.tick_at(t0 + DEPARTED_AFTER + Duration::from_secs(1)));
        let t2 = t0 + DEPARTED_AFTER + Duration::from_secs(65);
        let again = t.observe_at(&ad("p1"), t2);
        assert!(matches!(
            again.first(),
            Some(BleAnomaly::DevicePresence {
                state: PresenceState::Arrived,
                ..
            })
        ));
    }
}
