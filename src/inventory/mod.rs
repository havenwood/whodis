//! Unified device inventory: fuse ARP / sweep / mDNS / SSDP / BLE observations
//! into typed Candidate rows with explicit, operator-inspectable evidence.

pub mod candidate;
pub mod graph;
pub mod link;
pub mod log;
pub mod observation;

pub use candidate::{
    BleSatellite, Candidate, CandidateId, CandidateStatus, MdnsServiceRef, SsdpServiceRef,
    liveness_band,
};
pub use graph::{CandidateChange, IdentityGraph, LivenessConfig};
pub use link::{Confidence, EvidenceLink, LinkKind};
pub use observation::Observation;
