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
    AirDropEveryone(PeripheralId),
    LockChange(PeripheralId),
    Classification(PeripheralId),
    UnknownContinuityType(u8),
}

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::ble::BleAdvertisement;

/// Threshold after which a peripheral is considered Departed.
#[allow(clippy::duration_suboptimal_units, reason = "from_mins not available")]
const DEPARTED_AFTER: Duration = Duration::from_secs(600);

/// Threshold for unknown Continuity type observations before emitting anomaly.
const UNKNOWN_TY_THRESHOLD: usize = 5;

const fn lock_state_from_wake(wake_status: u8) -> LockState {
    // The high bit of NearbyInfo's wake_status correlates with screen-on state
    // in observed iOS broadcasts. Best-effort heuristic, not a Bluetooth SIG
    // specification. False positives possible during transient device states.
    if wake_status & 0x40 != 0 {
        LockState::Unlocked
    } else {
        LockState::Locked
    }
}

#[derive(Debug, Clone)]
struct PeripheralState {
    #[allow(dead_code, reason = "consumed by Task 2 (T2) first-arrival timestamp")]
    first_seen: SystemTime,
    last_seen: SystemTime,
    last_wake_status: Option<u8>,
    classification: Option<DeviceClass>,
}

/// Pure-logic recon anomaly tracker. Public so embedders can drive it
/// directly without sockets.
#[derive(Debug, Default)]
pub struct AnomalyTracker {
    peripherals: HashMap<PeripheralId, PeripheralState>,
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
    #[allow(
        clippy::too_many_lines,
        reason = "presence + continuity decode + three dispatch branches for AirDrop/Unknown/Lock/Classification"
    )]
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

        // Decode Continuity payloads once — used by AirDrop / Unknown / lock branches and classification.
        let payloads = ad
            .manufacturer_data
            .get(&0x004C)
            .map(|bytes| crate::ble::continuity::decode(bytes))
            .unwrap_or_default();

        for payload in &payloads {
            match payload {
                crate::ble::continuity::ContinuityPayload::AirDropPair {
                    mode: crate::ble::AirDropMode::Everyone,
                    ..
                } => {
                    let key = BleAnomalyKey::AirDropEveryone(ad.peripheral_id.clone());
                    if self.reported.insert(key) {
                        out.push(BleAnomaly::AirDropEveryoneMode {
                            peripheral_id: ad.peripheral_id.clone(),
                            observed_at: now,
                        });
                    }
                }
                crate::ble::continuity::ContinuityPayload::Unknown { ty, .. } => {
                    let count = self
                        .unknown_ty_counts
                        .entry(*ty)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    if *count >= UNKNOWN_TY_THRESHOLD {
                        let key = BleAnomalyKey::UnknownContinuityType(*ty);
                        if self.reported.insert(key) {
                            out.push(BleAnomaly::UnknownContinuityType {
                                ty: *ty,
                                count: *count,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // Lock-state: NearbyInfo wake_status high-bit toggling.
        for payload in &payloads {
            if let crate::ble::continuity::ContinuityPayload::NearbyInfo { wake_status, .. } =
                payload
            {
                let curr = lock_state_from_wake(*wake_status);
                let prev = self
                    .peripherals
                    .get(&ad.peripheral_id)
                    .and_then(|s| s.last_wake_status)
                    .map(lock_state_from_wake);
                if let Some(prev_state) = prev
                    && prev_state != curr
                {
                    let key = BleAnomalyKey::LockChange(ad.peripheral_id.clone());
                    if self.reported.insert(key) {
                        out.push(BleAnomaly::LockStateChange {
                            peripheral_id: ad.peripheral_id.clone(),
                            prev: prev_state,
                            curr,
                        });
                    }
                }
                if let Some(state) = self.peripherals.get_mut(&ad.peripheral_id) {
                    state.last_wake_status = Some(*wake_status);
                }
                break;
            }
        }

        // Classification settle: emit once when device_class becomes non-Unknown.
        let class = crate::ble::fingerprint::device_class(ad, &payloads);
        if class != DeviceClass::Unknown {
            let prior = self
                .peripherals
                .get(&ad.peripheral_id)
                .and_then(|s| s.classification);
            if prior.is_none() {
                if let Some(state) = self.peripherals.get_mut(&ad.peripheral_id) {
                    state.classification = Some(class);
                }
                let key = BleAnomalyKey::Classification(ad.peripheral_id.clone());
                if self.reported.insert(key) {
                    out.push(BleAnomaly::DeviceClassClassification {
                        peripheral_id: ad.peripheral_id.clone(),
                        device_class: class,
                    });
                }
            }
        }

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

#[cfg(test)]
mod continuity_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ad_with_apple(id: &str, apple: Vec<u8>) -> BleAdvertisement {
        let mut mfr = BTreeMap::new();
        mfr.insert(0x004C, apple);
        BleAdvertisement {
            peripheral_id: PeripheralId::new(id),
            address_type: None,
            rssi: -50,
            local_name: None,
            manufacturer_data: mfr,
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn airdrop_everyone_fires_once_per_peripheral() {
        // AirDrop type 0x05, length 0x12, first byte 0x02 = Everyone bit set
        let mut payload = vec![0x05, 0x12, 0x02];
        payload.extend_from_slice(&[0u8; 17]);
        let ad = ad_with_apple("p1", payload);

        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let first = t.observe_at(&ad, now);
        assert!(
            first
                .iter()
                .any(|a| matches!(a, BleAnomaly::AirDropEveryoneMode { .. })),
            "expected AirDropEveryoneMode, got {first:?}"
        );

        let second = t.observe_at(&ad, now + Duration::from_secs(1));
        assert!(
            !second
                .iter()
                .any(|a| matches!(a, BleAnomaly::AirDropEveryoneMode { .. })),
            "expected dedup, got {second:?}"
        );
    }

    #[test]
    fn unknown_continuity_type_fires_once_after_five_observations() {
        // Unknown type 0xAB, length 0x02, payload 0xCC 0xDD
        let payload = vec![0xAB, 0x02, 0xCC, 0xDD];
        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        for i in 0..4 {
            let id = format!("p{i}");
            let ad = ad_with_apple(&id, payload.clone());
            let out = t.observe_at(&ad, now + Duration::from_secs(i as u64));
            assert!(
                !out.iter()
                    .any(|a| matches!(a, BleAnomaly::UnknownContinuityType { .. })),
                "should not fire before threshold, iter {i}, got {out:?}"
            );
        }
        let id = "p5".to_string();
        let ad = ad_with_apple(&id, payload);
        let fifth = t.observe_at(&ad, now + Duration::from_secs(5));
        let unknown = fifth
            .iter()
            .find(|a| matches!(a, BleAnomaly::UnknownContinuityType { .. }));
        assert!(
            unknown.is_some(),
            "expected UnknownContinuityType after threshold, got {fifth:?}"
        );
    }
}

#[cfg(test)]
mod classification_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn iphone_local_name_settles_classification_once() {
        let ad = BleAdvertisement {
            peripheral_id: PeripheralId::new("p1"),
            address_type: None,
            rssi: -50,
            local_name: Some("Shannon's iPhone".into()),
            manufacturer_data: BTreeMap::new(),
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        };
        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let first = t.observe_at(&ad, now);
        assert!(
            first.iter().any(|a| matches!(
                a,
                BleAnomaly::DeviceClassClassification {
                    device_class: DeviceClass::Phone,
                    ..
                }
            )),
            "got {first:?}"
        );
        let second = t.observe_at(&ad, now + Duration::from_secs(1));
        assert!(
            !second
                .iter()
                .any(|a| matches!(a, BleAnomaly::DeviceClassClassification { .. })),
            "should not re-fire classification, got {second:?}"
        );
    }

    #[test]
    fn unknown_class_does_not_emit_classification() {
        let ad = BleAdvertisement {
            peripheral_id: PeripheralId::new("p1"),
            address_type: None,
            rssi: -50,
            local_name: None,
            manufacturer_data: BTreeMap::new(),
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        };
        let mut t = AnomalyTracker::new();
        let out = t.observe_at(&ad, SystemTime::UNIX_EPOCH);
        assert!(
            !out.iter()
                .any(|a| matches!(a, BleAnomaly::DeviceClassClassification { .. })),
            "got {out:?}"
        );
    }
}

#[cfg(test)]
mod lock_state_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn nearby_info_ad(id: &str, wake_status: u8) -> BleAdvertisement {
        // NearbyInfo type 0x10, length 0x05, status_flags=0x57, wake=wake_status, then 3 zeros
        let mut apple = vec![0x10, 0x05, 0x57, wake_status];
        apple.extend_from_slice(&[0u8; 3]);
        let mut mfr = BTreeMap::new();
        mfr.insert(0x004C, apple);
        BleAdvertisement {
            peripheral_id: PeripheralId::new(id),
            address_type: None,
            rssi: -50,
            local_name: None,
            manufacturer_data: mfr,
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn wake_status_high_bit_change_emits_lock_state_change() {
        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        drop(t.observe_at(&nearby_info_ad("p1", 0x00), now));
        let toggled = t.observe_at(&nearby_info_ad("p1", 0x40), now + Duration::from_secs(1));
        assert!(
            toggled.iter().any(|a| matches!(
                a,
                BleAnomaly::LockStateChange {
                    prev: LockState::Locked,
                    curr: LockState::Unlocked,
                    ..
                }
            )),
            "got {toggled:?}"
        );
    }

    #[test]
    fn no_lock_change_when_wake_status_steady() {
        let mut t = AnomalyTracker::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        drop(t.observe_at(&nearby_info_ad("p1", 0x00), now));
        let same = t.observe_at(&nearby_info_ad("p1", 0x00), now + Duration::from_secs(1));
        assert!(
            !same
                .iter()
                .any(|a| matches!(a, BleAnomaly::LockStateChange { .. })),
            "got {same:?}"
        );
    }
}
