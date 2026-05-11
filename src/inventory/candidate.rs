//! Candidate — the user-facing fused device record.
//!
//! Every field carries at least one `EvidenceLink` entry in `evidence`. BLE identities are kept
//! in a separate `ble_satellites` vector because they are NOT radio-correlated
//! to the IP-having evidence; they are name-matched at best.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ble::{DeviceClass, PeripheralId};
use crate::inventory::link::EvidenceLink;

/// Stable handle for a `Candidate` within a single `IdentityGraph` session.
/// Not persistent across runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateId(pub u64);

/// Liveness band. Driven by `tick()` based on `last_seen` age.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// Observed within the active window (default 60s).
    Active,
    /// Observed within the quiet window (default 5 min) but not the active window.
    Quiet,
    /// Observed within the stale window (default 30 min) but not the quiet window.
    Stale,
    /// Not observed within the stale window — probably departed.
    Gone,
}

/// mDNS service entry attached to a Candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsServiceRef {
    pub fqdn: String,
    pub service_type: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub txt: BTreeMap<String, String>,
}

/// SSDP service entry attached to a Candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsdpServiceRef {
    pub usn: String,
    pub st: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

/// BLE identity tracked alongside a Candidate but NOT merged into it.
/// Cross-link is informational at best (name-based).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleSatellite {
    pub peripheral_id: PeripheralId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    pub device_class: DeviceClass,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_uuids: Vec<Uuid>,
    /// Most recent RSSI sample, dBm.
    pub rssi: i16,
    /// Why this satellite is associated with the parent Candidate.
    /// Empty vec => the BLE row is unparented (its own root Candidate).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceLink>,
}

/// User-facing Candidate row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub id: CandidateId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>,
    /// MAC bytes serialized as colon-hex strings via the helper module.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "mac_list")]
    pub macs: Vec<[u8; 6]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mdns_services: Vec<MdnsServiceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssdp_services: Vec<SsdpServiceRef>,
    /// BLE satellites — informational, not fused into the IP/MAC merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ble_satellites: Vec<BleSatellite>,
    #[serde(with = "system_time_millis")]
    pub first_seen: SystemTime,
    #[serde(with = "system_time_millis")]
    pub last_seen: SystemTime,
    pub status: CandidateStatus,
    /// Every claim on this `Candidate` must trace back to an `EvidenceLink` here.
    pub evidence: Vec<EvidenceLink>,
}

impl Candidate {
    /// Construct a Candidate from a single observation. Caller assigns the
    /// `CandidateId`. Used by the graph to seed new candidates.
    #[must_use]
    pub fn seed(id: CandidateId, now: SystemTime) -> Self {
        Self {
            id,
            display_name: None,
            ips: Vec::new(),
            macs: Vec::new(),
            hostnames: Vec::new(),
            vendors: Vec::new(),
            interfaces: Vec::new(),
            mdns_services: Vec::new(),
            ssdp_services: Vec::new(),
            ble_satellites: Vec::new(),
            first_seen: now,
            last_seen: now,
            status: CandidateStatus::Active,
            evidence: Vec::new(),
        }
    }
}

/// Compute liveness band from `last_seen` age, given configurable thresholds.
#[must_use]
pub fn liveness_band(
    last_seen: SystemTime,
    now: SystemTime,
    active_after: Duration,
    quiet_after: Duration,
    stale_after: Duration,
) -> CandidateStatus {
    let age = now.duration_since(last_seen).unwrap_or(Duration::ZERO);
    if age <= active_after {
        CandidateStatus::Active
    } else if age <= quiet_after {
        CandidateStatus::Quiet
    } else if age <= stale_after {
        CandidateStatus::Stale
    } else {
        CandidateStatus::Gone
    }
}

mod mac_list {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(macs: &[[u8; 6]], ser: S) -> Result<S::Ok, S::Error> {
        let strings: Vec<String> = macs
            .iter()
            .map(|m| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            })
            .collect();
        strings.serialize(ser)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<[u8; 6]>, D::Error> {
        let strings: Vec<String> = Vec::deserialize(de)?;
        let mut out = Vec::with_capacity(strings.len());
        for s in strings {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 6 {
                return Err(serde::de::Error::custom(format!("bad mac string: {s}")));
            }
            let mut mac = [0u8; 6];
            for (i, p) in parts.iter().enumerate() {
                if let Some(b) = mac.get_mut(i) {
                    *b = u8::from_str_radix(p, 16).map_err(serde::de::Error::custom)?;
                }
            }
            out.push(mac);
        }
        Ok(out)
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
    #[allow(
        clippy::duration_suboptimal_units,
        reason = "test constants are in seconds"
    )]
    fn liveness_band_transitions() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let active = Duration::from_secs(60);
        let quiet = Duration::from_secs(300);
        let stale = Duration::from_secs(1800);

        assert_eq!(
            liveness_band(now, now, active, quiet, stale),
            CandidateStatus::Active
        );
        assert_eq!(
            liveness_band(now - Duration::from_secs(120), now, active, quiet, stale),
            CandidateStatus::Quiet
        );
        assert_eq!(
            liveness_band(now - Duration::from_secs(600), now, active, quiet, stale),
            CandidateStatus::Stale
        );
        assert_eq!(
            liveness_band(now - Duration::from_secs(3600), now, active, quiet, stale),
            CandidateStatus::Gone
        );
    }

    #[test]
    fn candidate_serializes_mac_as_colon_hex() {
        let mut c = Candidate::seed(CandidateId(1), SystemTime::UNIX_EPOCH);
        c.macs.push([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let s = serde_json::to_string(&c).expect("ser");
        assert!(s.contains(r#""aa:bb:cc:dd:ee:ff""#), "got {s}");
    }

    #[test]
    fn candidate_round_trips_through_json() {
        let mut c = Candidate::seed(CandidateId(42), SystemTime::UNIX_EPOCH);
        c.ips.push("10.0.5.20".parse().expect("ip"));
        c.macs.push([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        c.evidence.push(EvidenceLink {
            kind: crate::inventory::link::LinkKind::SameMac,
            confidence: crate::inventory::link::Confidence::VeryHigh,
            note: "10.0.5.20 ↔ aa:bb:cc:dd:ee:ff (en0 ARP)".into(),
            observed_at: SystemTime::UNIX_EPOCH,
        });
        let s = serde_json::to_string(&c).expect("ser");
        let back: Candidate = serde_json::from_str(&s).expect("de");
        assert_eq!(c, back);
    }
}
