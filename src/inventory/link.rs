//! Typed evidence links with explicit confidence.
//!
//! Every claim on a `Candidate` (an IP, a MAC, a hostname, a service entry, a BLE identity)
//! is backed by one or more `EvidenceLink` entries the operator can inspect.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Kind of evidence backing a Candidate field or a cross-Candidate merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// Two observations share a MAC address — strongest binding.
    SameMac,
    /// An mDNS host record resolves to an IP we have other evidence for.
    HostnameResolvesToIp,
    /// An mDNS instance's `host` target is a hostname we already track.
    MdnsInstanceTargetsHost,
    /// SSDP NOTIFY / reply arrived from a source IP we already track.
    SsdpLocationOnIp,
    /// LLMNR response said `name -> ip`; medium because LLMNR is spoof-prone.
    LlmnrNameResolvesToIp,
    /// BLE `local_name` string matches an mDNS instance name — informational.
    BleNameMatchesMdnsName,
    /// Vendor lookup match across sources — display only, never merges.
    VendorMatch,
}

/// Confidence band that determines whether a link triggers a merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Display only — never causes a merge, never auto-attaches.
    Informational,
    /// Recorded as evidence on both candidates but does not merge them.
    Low,
    /// Recorded as evidence; auto-merge ONLY when combined with another
    /// `Medium`-or-stronger link between the same pair of candidates.
    Medium,
    /// Merges immediately.
    High,
    /// Merges immediately and survives conflicts (newer `High` does not override).
    VeryHigh,
}

impl LinkKind {
    /// Default confidence for this link kind.
    #[must_use]
    pub const fn default_confidence(&self) -> Confidence {
        match self {
            Self::SameMac => Confidence::VeryHigh,
            Self::HostnameResolvesToIp | Self::MdnsInstanceTargetsHost | Self::SsdpLocationOnIp => {
                Confidence::High
            }
            Self::LlmnrNameResolvesToIp => Confidence::Medium,
            Self::BleNameMatchesMdnsName => Confidence::Low,
            Self::VendorMatch => Confidence::Informational,
        }
    }

    /// Whether this link kind, at its default confidence, can trigger
    /// automatic merging of two candidates.
    #[must_use]
    pub const fn auto_merges(&self) -> bool {
        matches!(
            self.default_confidence(),
            Confidence::High | Confidence::VeryHigh
        )
    }
}

/// One typed piece of evidence attached to a Candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub kind: LinkKind,
    pub confidence: Confidence,
    /// Free-form note describing the link concretely. Operator-readable.
    /// Examples: "10.0.5.20 ↔ aa:bb:cc:dd:ee:ff (en0 ARP)",
    /// "AppleTV.local. → 10.0.5.20 (mDNS A record)".
    pub note: String,
    #[serde(with = "system_time_millis")]
    pub observed_at: SystemTime,
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
    fn same_mac_is_very_high_and_auto_merges() {
        assert_eq!(LinkKind::SameMac.default_confidence(), Confidence::VeryHigh);
        assert!(LinkKind::SameMac.auto_merges());
    }

    #[test]
    fn ble_name_match_is_low_and_does_not_auto_merge() {
        assert_eq!(
            LinkKind::BleNameMatchesMdnsName.default_confidence(),
            Confidence::Low
        );
        assert!(!LinkKind::BleNameMatchesMdnsName.auto_merges());
    }

    #[test]
    fn vendor_match_is_informational() {
        assert_eq!(
            LinkKind::VendorMatch.default_confidence(),
            Confidence::Informational
        );
        assert!(!LinkKind::VendorMatch.auto_merges());
    }

    #[test]
    fn evidence_link_round_trips_through_json() {
        let link = EvidenceLink {
            kind: LinkKind::SameMac,
            confidence: Confidence::VeryHigh,
            note: "10.0.5.20 ↔ aa:bb:cc:dd:ee:ff (en0 ARP)".into(),
            observed_at: SystemTime::UNIX_EPOCH,
        };
        let s = serde_json::to_string(&link).expect("ser");
        let back: EvidenceLink = serde_json::from_str(&s).expect("de");
        assert_eq!(link, back);
    }
}
