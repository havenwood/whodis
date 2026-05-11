//! `IdentityGraph`: pure-logic state machine that fuses Observation events
//! into Candidate rows. No I/O, no clocks except those passed in by the
//! caller. Fully testable.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[allow(unused_imports, reason = "consumed by Task 4 status state machine")]
use crate::inventory::candidate::liveness_band;
use crate::inventory::candidate::{
    Candidate, CandidateId, CandidateStatus, MdnsServiceRef, SsdpServiceRef,
};
use crate::inventory::link::{Confidence, EvidenceLink, LinkKind};
use crate::inventory::observation::Observation;

/// Default liveness thresholds. `active_after` is the boundary between
/// Active and Quiet; `quiet_after` the boundary between Quiet and Stale;
/// `stale_after` the boundary between Stale and Gone.
#[derive(Debug, Clone, Copy)]
pub struct LivenessConfig {
    pub active_after: Duration,
    pub quiet_after: Duration,
    pub stale_after: Duration,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            active_after: Duration::from_mins(1),
            quiet_after: Duration::from_mins(5),
            stale_after: Duration::from_mins(30),
        }
    }
}

/// Diff event emitted by `observe()` and `tick()` so callers can render
/// incremental changes without re-walking the whole graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateChange {
    /// New Candidate created.
    Created(CandidateId),
    /// Existing Candidate updated in place.
    Updated(CandidateId),
    /// Two Candidates merged; `survivor` absorbed `absorbed`.
    Merged {
        survivor: CandidateId,
        absorbed: CandidateId,
    },
    /// Status band changed.
    StatusChanged {
        id: CandidateId,
        from: CandidateStatus,
        to: CandidateStatus,
    },
}

pub struct IdentityGraph {
    next_id: u64,
    candidates: HashMap<CandidateId, Candidate>,
    by_mac: HashMap<[u8; 6], CandidateId>,
    by_ip: HashMap<IpAddr, CandidateId>,
    by_hostname: HashMap<String, CandidateId>,
    by_ble: HashMap<crate::ble::PeripheralId, CandidateId>,
    liveness: LivenessConfig,
}

impl Default for IdentityGraph {
    fn default() -> Self {
        Self {
            next_id: 1,
            candidates: HashMap::new(),
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
            by_hostname: HashMap::new(),
            by_ble: HashMap::new(),
            liveness: LivenessConfig::default(),
        }
    }
}

impl IdentityGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_liveness(mut self, cfg: LivenessConfig) -> Self {
        self.liveness = cfg;
        self
    }

    /// Iterate over all current Candidates.
    pub fn candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates.values()
    }

    /// Number of distinct Candidates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Ingest one Observation and return the resulting diff events.
    pub fn observe(&mut self, obs: Observation) -> Vec<CandidateChange> {
        match obs {
            Observation::Neighbor {
                ip,
                mac,
                vendor,
                interface,
                observed_at,
            } => self.observe_neighbor(ip, mac, vendor, interface, observed_at),
            Observation::SweepHost {
                ip,
                alive,
                rtt_ms: _,
                mac,
                vendor,
                interface,
                observed_at,
            } => self.observe_sweep(ip, alive, mac, vendor, interface, observed_at),
            Observation::MdnsInstance {
                fqdn,
                service_type,
                instance_name: _,
                host,
                port,
                addrs,
                txt,
                observed_at,
            } => self.observe_mdns(fqdn, service_type, host, port, addrs, txt, observed_at),
            Observation::SsdpService {
                usn,
                st,
                location,
                server,
                src_ip,
                max_age: _,
                observed_at,
            } => self.observe_ssdp(usn, st, location, server, src_ip, observed_at),
            Observation::BleDevice {
                peripheral_id,
                local_name,
                vendor,
                product,
                device_class,
                rssi,
                service_uuids,
                observed_at,
            } => self.observe_ble(
                peripheral_id,
                local_name,
                vendor,
                product,
                device_class,
                rssi,
                service_uuids,
                observed_at,
            ),
            Observation::MdnsGoodbye { .. } | Observation::SsdpByebye { .. } => Vec::new(),
        }
    }

    fn allocate_id(&mut self) -> CandidateId {
        let id = CandidateId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "called from observe() with Observation-owned data; taking refs would require cloning at call site"
    )]
    fn observe_neighbor(
        &mut self,
        ip: IpAddr,
        mac: [u8; 6],
        vendor: Option<String>,
        interface: String,
        observed_at: SystemTime,
    ) -> Vec<CandidateChange> {
        let mut changes = Vec::new();
        // Look up by MAC first (strongest); fall back to IP.
        let target_id = if let Some(&id) = self.by_mac.get(&mac) {
            Some(id)
        } else {
            self.by_ip.get(&ip).copied()
        };

        let id = if let Some(id) = target_id {
            changes.push(CandidateChange::Updated(id));
            id
        } else {
            let new_id = self.allocate_id();
            self.candidates
                .insert(new_id, Candidate::seed(new_id, observed_at));
            changes.push(CandidateChange::Created(new_id));
            new_id
        };

        // Update Candidate fields + record evidence.
        if let Some(c) = self.candidates.get_mut(&id) {
            if !c.ips.contains(&ip) {
                c.ips.push(ip);
            }
            if !c.macs.contains(&mac) {
                c.macs.push(mac);
            }
            if let Some(v) = vendor.as_deref()
                && !c.vendors.iter().any(|x| x == v)
            {
                c.vendors.push(v.to_string());
            }
            if !c.interfaces.iter().any(|x| x == &interface) {
                c.interfaces.push(interface.clone());
            }
            c.last_seen = observed_at;
            c.evidence.push(EvidenceLink {
                kind: LinkKind::SameMac,
                confidence: Confidence::VeryHigh,
                note: format!("{ip} ↔ {} ({interface} ARP/NDP)", format_mac(mac)),
                observed_at,
            });
        }

        // Update indices.
        self.by_mac.insert(mac, id);
        self.by_ip.insert(ip, id);
        changes
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "wraps a fixed Observation variant; keeps internal signature flat"
    )]
    fn observe_sweep(
        &mut self,
        ip: IpAddr,
        alive: bool,
        mac: Option<[u8; 6]>,
        vendor: Option<String>,
        interface: String,
        observed_at: SystemTime,
    ) -> Vec<CandidateChange> {
        let mut changes = Vec::new();
        if !alive {
            // Dead sweep results don't create candidates; they may update an
            // existing candidate's last_seen if we already track it.
            if let Some(&id) = self.by_ip.get(&ip)
                && let Some(c) = self.candidates.get_mut(&id)
            {
                c.last_seen = observed_at;
                changes.push(CandidateChange::Updated(id));
            }
            return changes;
        }

        // If MAC enriched, route through the neighbor merge path.
        if let Some(m) = mac {
            return self.observe_neighbor(ip, m, vendor, interface, observed_at);
        }

        // Alive but no MAC -- look up by IP, create tentative if absent.
        let id = if let Some(id) = self.by_ip.get(&ip).copied() {
            changes.push(CandidateChange::Updated(id));
            id
        } else {
            let new_id = self.allocate_id();
            self.candidates
                .insert(new_id, Candidate::seed(new_id, observed_at));
            changes.push(CandidateChange::Created(new_id));
            new_id
        };

        if let Some(c) = self.candidates.get_mut(&id) {
            if !c.ips.contains(&ip) {
                c.ips.push(ip);
            }
            if !c.interfaces.iter().any(|x| x == &interface) {
                c.interfaces.push(interface.clone());
            }
            c.last_seen = observed_at;
            c.evidence.push(EvidenceLink {
                kind: LinkKind::HostnameResolvesToIp,
                confidence: Confidence::Medium,
                note: format!("{ip} alive on sweep ({interface})"),
                observed_at,
            });
        }
        self.by_ip.insert(ip, id);
        changes
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::needless_pass_by_value,
        reason = "wraps a fixed Observation variant; Strings are Observation-owned data"
    )]
    fn observe_mdns(
        &mut self,
        fqdn: String,
        service_type: String,
        host: String,
        port: u16,
        addrs: Vec<IpAddr>,
        txt: BTreeMap<String, String>,
        observed_at: SystemTime,
    ) -> Vec<CandidateChange> {
        let mut changes = Vec::new();
        // Find candidates referenced by either an existing IP or the hostname.
        let mut targets: Vec<CandidateId> = Vec::new();
        for ip in &addrs {
            if let Some(&id) = self.by_ip.get(ip)
                && !targets.contains(&id)
            {
                targets.push(id);
            }
        }
        if let Some(&id) = self.by_hostname.get(&host)
            && !targets.contains(&id)
        {
            targets.push(id);
        }

        let id = if let Some(first) = targets.first().copied() {
            // If multiple existing Candidates share this evidence, merge them.
            for &absorbed in targets.iter().skip(1) {
                if absorbed != first
                    && let Some(change) = self.merge_into(first, absorbed, observed_at)
                {
                    changes.push(change);
                }
            }
            changes.push(CandidateChange::Updated(first));
            first
        } else {
            let new_id = self.allocate_id();
            self.candidates
                .insert(new_id, Candidate::seed(new_id, observed_at));
            changes.push(CandidateChange::Created(new_id));
            new_id
        };

        // Attach the mDNS service ref + evidence.
        if let Some(c) = self.candidates.get_mut(&id) {
            if !c.hostnames.iter().any(|h| h == &host) {
                c.hostnames.push(host.clone());
            }
            for ip in &addrs {
                if !c.ips.contains(ip) {
                    c.ips.push(*ip);
                }
            }
            let svc_ref = MdnsServiceRef {
                fqdn: fqdn.clone(),
                service_type,
                port,
                txt,
            };
            if !c.mdns_services.contains(&svc_ref) {
                c.mdns_services.push(svc_ref);
            }
            c.last_seen = observed_at;
            c.evidence.push(EvidenceLink {
                kind: LinkKind::MdnsInstanceTargetsHost,
                confidence: Confidence::High,
                note: format!("{fqdn} \u{2192} {host}:{port}"),
                observed_at,
            });
            for ip in &addrs {
                c.evidence.push(EvidenceLink {
                    kind: LinkKind::HostnameResolvesToIp,
                    confidence: Confidence::High,
                    note: format!("{host} \u{2192} {ip} (mDNS A/AAAA)"),
                    observed_at,
                });
            }
        }

        self.by_hostname.insert(host, id);
        for ip in addrs {
            self.by_ip.insert(ip, id);
        }
        changes
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "called from observe() with Observation-owned data"
    )]
    fn observe_ssdp(
        &mut self,
        usn: String,
        st: String,
        location: Option<String>,
        server: Option<String>,
        src_ip: IpAddr,
        observed_at: SystemTime,
    ) -> Vec<CandidateChange> {
        let mut changes = Vec::new();
        let id = if let Some(id) = self.by_ip.get(&src_ip).copied() {
            changes.push(CandidateChange::Updated(id));
            id
        } else {
            let new_id = self.allocate_id();
            self.candidates
                .insert(new_id, Candidate::seed(new_id, observed_at));
            changes.push(CandidateChange::Created(new_id));
            new_id
        };

        if let Some(c) = self.candidates.get_mut(&id) {
            if !c.ips.contains(&src_ip) {
                c.ips.push(src_ip);
            }
            let svc_ref = SsdpServiceRef {
                usn: usn.clone(),
                st: st.clone(),
                location,
                server,
            };
            if !c.ssdp_services.contains(&svc_ref) {
                c.ssdp_services.push(svc_ref);
            }
            c.last_seen = observed_at;
            c.evidence.push(EvidenceLink {
                kind: LinkKind::SsdpLocationOnIp,
                confidence: Confidence::High,
                note: format!("{usn} ({st}) on {src_ip}"),
                observed_at,
            });
        }

        self.by_ip.insert(src_ip, id);
        changes
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::needless_pass_by_value,
        reason = "wraps a fixed Observation variant; keeps internal signature flat"
    )]
    fn observe_ble(
        &mut self,
        peripheral_id: crate::ble::PeripheralId,
        local_name: Option<String>,
        vendor: Option<String>,
        product: Option<String>,
        device_class: crate::ble::DeviceClass,
        rssi: i16,
        service_uuids: Vec<uuid::Uuid>,
        observed_at: SystemTime,
    ) -> Vec<CandidateChange> {
        use crate::inventory::candidate::BleSatellite;
        let mut changes = Vec::new();

        // Root: always create or update a BLE-only Candidate keyed by peripheral_id.
        let root_id = if let Some(id) = self.by_ble.get(&peripheral_id).copied() {
            changes.push(CandidateChange::Updated(id));
            id
        } else {
            let new_id = self.allocate_id();
            self.candidates
                .insert(new_id, Candidate::seed(new_id, observed_at));
            changes.push(CandidateChange::Created(new_id));
            new_id
        };

        if let Some(c) = self.candidates.get_mut(&root_id) {
            let satellite = BleSatellite {
                peripheral_id: peripheral_id.clone(),
                local_name: local_name.clone(),
                vendor: vendor.clone(),
                product: product.clone(),
                device_class,
                service_uuids: service_uuids.clone(),
                rssi,
                evidence: Vec::new(),
            };
            if let Some(existing) = c
                .ble_satellites
                .iter_mut()
                .find(|s| s.peripheral_id == peripheral_id)
            {
                *existing = satellite;
            } else {
                c.ble_satellites.push(satellite);
            }
            if c.display_name.is_none() {
                c.display_name.clone_from(&local_name);
            }
            c.last_seen = observed_at;
        }
        self.by_ble.insert(peripheral_id.clone(), root_id);

        // Soft cross-link: attach the BLE row as a satellite on any IP-having
        // Candidate whose hostname or display_name matches local_name
        // (case-insensitive substring).
        if let Some(name) = local_name.as_deref()
            && !name.is_empty()
        {
            let name_lower = name.to_lowercase();
            let matching: Vec<CandidateId> = self
                .candidates
                .iter()
                .filter(|(id, c)| {
                    **id != root_id
                        && (c
                            .hostnames
                            .iter()
                            .any(|h| h.to_lowercase().contains(&name_lower))
                            || c.display_name
                                .as_deref()
                                .is_some_and(|d| d.to_lowercase().contains(&name_lower)))
                })
                .map(|(id, _)| *id)
                .collect();
            for target in matching {
                if let Some(c) = self.candidates.get_mut(&target) {
                    let satellite = BleSatellite {
                        peripheral_id: peripheral_id.clone(),
                        local_name: local_name.clone(),
                        vendor: vendor.clone(),
                        product: product.clone(),
                        device_class,
                        service_uuids: service_uuids.clone(),
                        rssi,
                        evidence: vec![EvidenceLink {
                            kind: LinkKind::BleNameMatchesMdnsName,
                            confidence: Confidence::Low,
                            note: format!("BLE local_name {name:?} matches mDNS hostname/instance"),
                            observed_at,
                        }],
                    };
                    if let Some(existing) = c
                        .ble_satellites
                        .iter_mut()
                        .find(|s| s.peripheral_id == peripheral_id)
                    {
                        *existing = satellite;
                    } else {
                        c.ble_satellites.push(satellite);
                    }
                    changes.push(CandidateChange::Updated(target));
                }
            }
        }

        changes
    }

    /// Merge `absorbed` into `survivor`. Idempotent: merging a Candidate
    /// into itself is a no-op and returns `None`.
    fn merge_into(
        &mut self,
        survivor: CandidateId,
        absorbed: CandidateId,
        observed_at: SystemTime,
    ) -> Option<CandidateChange> {
        if survivor == absorbed {
            return None;
        }
        let absorbed_candidate = self.candidates.remove(&absorbed)?;
        let surv = self.candidates.get_mut(&survivor)?;
        for ip in absorbed_candidate.ips {
            if !surv.ips.contains(&ip) {
                surv.ips.push(ip);
            }
            self.by_ip.insert(ip, survivor);
        }
        for mac in absorbed_candidate.macs {
            if !surv.macs.contains(&mac) {
                surv.macs.push(mac);
            }
            self.by_mac.insert(mac, survivor);
        }
        for h in absorbed_candidate.hostnames {
            if !surv.hostnames.iter().any(|x| x == &h) {
                surv.hostnames.push(h.clone());
            }
            self.by_hostname.insert(h, survivor);
        }
        for v in absorbed_candidate.vendors {
            if !surv.vendors.iter().any(|x| x == &v) {
                surv.vendors.push(v);
            }
        }
        for i in absorbed_candidate.interfaces {
            if !surv.interfaces.iter().any(|x| x == &i) {
                surv.interfaces.push(i);
            }
        }
        for s in absorbed_candidate.mdns_services {
            if !surv.mdns_services.contains(&s) {
                surv.mdns_services.push(s);
            }
        }
        for s in absorbed_candidate.ssdp_services {
            if !surv.ssdp_services.contains(&s) {
                surv.ssdp_services.push(s);
            }
        }
        for sat in absorbed_candidate.ble_satellites {
            surv.ble_satellites.push(sat);
        }
        surv.evidence.extend(absorbed_candidate.evidence);
        surv.first_seen = surv.first_seen.min(absorbed_candidate.first_seen);
        surv.last_seen = surv.last_seen.max(observed_at);
        Some(CandidateChange::Merged { survivor, absorbed })
    }
}

fn format_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::SystemTime;

    fn now0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn neighbor_creates_candidate_with_evidence() {
        let mut g = IdentityGraph::new();
        let changes = g.observe(Observation::Neighbor {
            ip: ip("10.0.5.20"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: Some("Apple".into()),
            interface: "en0".into(),
            observed_at: now0(),
        });
        assert_eq!(g.len(), 1);
        assert!(
            matches!(changes.first(), Some(CandidateChange::Created(_))),
            "got {changes:?}"
        );
        let c = g.candidates().next().expect("one candidate");
        assert_eq!(c.ips, vec![ip("10.0.5.20")]);
        assert_eq!(c.vendors, vec!["Apple".to_string()]);
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == LinkKind::SameMac && e.confidence == Confidence::VeryHigh),
            "expected SameMac evidence, got {:?}",
            c.evidence
        );
    }

    #[test]
    fn second_neighbor_with_same_mac_updates_existing() {
        let mut g = IdentityGraph::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        drop(g.observe(Observation::Neighbor {
            ip: ip("10.0.5.20"),
            mac,
            vendor: None,
            interface: "en0".into(),
            observed_at: now0(),
        }));
        let changes = g.observe(Observation::Neighbor {
            ip: ip("fe80::1"),
            mac,
            vendor: None,
            interface: "en0".into(),
            observed_at: now0() + Duration::from_secs(1),
        });
        assert_eq!(g.len(), 1, "should be one candidate");
        assert!(matches!(changes.first(), Some(CandidateChange::Updated(_))));
        let c = g.candidates().next().expect("one candidate");
        assert_eq!(c.ips.len(), 2, "both IPs attached");
    }

    #[test]
    fn mdns_with_addrs_merges_into_arp_candidate_by_ip() {
        let mut g = IdentityGraph::new();
        drop(g.observe(Observation::Neighbor {
            ip: ip("10.0.5.20"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: Some("Apple".into()),
            interface: "en0".into(),
            observed_at: now0(),
        }));
        drop(g.observe(Observation::MdnsInstance {
            fqdn: "Living._airplay._tcp.local.".into(),
            service_type: "_airplay._tcp.local.".into(),
            instance_name: "Living".into(),
            host: "AppleTV.local.".into(),
            port: 7000,
            addrs: vec![ip("10.0.5.20")],
            txt: BTreeMap::default(),
            observed_at: now0() + Duration::from_secs(1),
        }));
        assert_eq!(g.len(), 1, "should fuse into one candidate");
        let c = g.candidates().next().expect("one candidate");
        assert_eq!(c.mdns_services.len(), 1);
        assert!(c.hostnames.contains(&"AppleTV.local.".to_string()));
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == LinkKind::MdnsInstanceTargetsHost),
            "expected MdnsInstanceTargetsHost evidence"
        );
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == LinkKind::HostnameResolvesToIp),
            "expected HostnameResolvesToIp evidence"
        );
    }

    #[test]
    fn mdns_then_neighbor_late_merge_collapses_candidates() {
        let mut g = IdentityGraph::new();
        // mDNS arrives first, no addrs yet -> tentative candidate keyed by hostname.
        drop(g.observe(Observation::MdnsInstance {
            fqdn: "Living._airplay._tcp.local.".into(),
            service_type: "_airplay._tcp.local.".into(),
            instance_name: "Living".into(),
            host: "AppleTV.local.".into(),
            port: 7000,
            addrs: vec![],
            txt: BTreeMap::default(),
            observed_at: now0(),
        }));
        assert_eq!(g.len(), 1);
        // Neighbor arrives with the IP that mDNS will later confirm.
        drop(g.observe(Observation::Neighbor {
            ip: ip("10.0.5.20"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: Some("Apple".into()),
            interface: "en0".into(),
            observed_at: now0() + Duration::from_secs(1),
        }));
        assert_eq!(g.len(), 2, "two candidates before the merging mDNS");
        // Now mDNS sees addrs -- should merge the two by hostname + IP.
        drop(g.observe(Observation::MdnsInstance {
            fqdn: "Living._airplay._tcp.local.".into(),
            service_type: "_airplay._tcp.local.".into(),
            instance_name: "Living".into(),
            host: "AppleTV.local.".into(),
            port: 7000,
            addrs: vec![ip("10.0.5.20")],
            txt: BTreeMap::default(),
            observed_at: now0() + Duration::from_secs(2),
        }));
        assert_eq!(g.len(), 1, "late-evidence merge should collapse to one");
    }

    #[test]
    fn ssdp_attaches_to_arp_candidate_by_src_ip() {
        let mut g = IdentityGraph::new();
        drop(g.observe(Observation::Neighbor {
            ip: ip("10.0.5.30"),
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            vendor: None,
            interface: "en0".into(),
            observed_at: now0(),
        }));
        drop(g.observe(Observation::SsdpService {
            usn: "uuid:abc::urn:schemas-upnp-org:device:MediaRenderer:1".into(),
            st: "urn:schemas-upnp-org:device:MediaRenderer:1".into(),
            location: Some("http://10.0.5.30:8200/dev.xml".into()),
            server: Some("Linux/4.19 UPnP/1.0".into()),
            src_ip: ip("10.0.5.30"),
            max_age: Some(1800),
            observed_at: now0() + Duration::from_secs(1),
        }));
        assert_eq!(g.len(), 1);
        let c = g.candidates().next().expect("one");
        assert_eq!(c.ssdp_services.len(), 1);
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == LinkKind::SsdpLocationOnIp),
            "expected SsdpLocationOnIp evidence"
        );
    }

    #[test]
    fn merge_into_self_is_noop() {
        let mut g = IdentityGraph::new();
        drop(g.observe(Observation::Neighbor {
            ip: ip("10.0.5.20"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: None,
            interface: "en0".into(),
            observed_at: now0(),
        }));
        let id = g.candidates().next().expect("one").id;
        let r = g.merge_into(id, id, now0() + Duration::from_secs(1));
        assert!(r.is_none(), "self-merge should be no-op");
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn ble_always_creates_own_candidate_no_merge() {
        let mut g = IdentityGraph::new();
        drop(g.observe(Observation::Neighbor {
            ip: ip("10.0.5.20"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: None,
            interface: "en0".into(),
            observed_at: now0(),
        }));
        drop(g.observe(Observation::MdnsInstance {
            fqdn: "Shannon's iPhone._companion-link._tcp.local.".into(),
            service_type: "_companion-link._tcp.local.".into(),
            instance_name: "Shannon's iPhone".into(),
            host: "iPhone.local.".into(),
            port: 49152,
            addrs: vec![ip("10.0.5.20")],
            txt: BTreeMap::default(),
            observed_at: now0() + Duration::from_secs(1),
        }));
        assert_eq!(g.len(), 1, "ARP + mDNS fuse");

        drop(g.observe(Observation::BleDevice {
            peripheral_id: crate::ble::PeripheralId::new("CB-UUID-XYZ"),
            local_name: Some("iPhone.local.".into()),
            vendor: Some("Apple".into()),
            product: None,
            device_class: crate::ble::DeviceClass::Phone,
            rssi: -50,
            service_uuids: vec![],
            observed_at: now0() + Duration::from_secs(2),
        }));

        // BLE must add its own root Candidate even with a name match.
        assert_eq!(g.len(), 2, "BLE never auto-merges");

        // The mDNS Candidate should now carry a BLE satellite (soft cross-link).
        let with_sat = g
            .candidates()
            .find(|c| !c.mdns_services.is_empty())
            .expect("mDNS candidate");
        assert_eq!(
            with_sat.ble_satellites.len(),
            1,
            "BLE satellite attached to mDNS candidate"
        );
        assert!(
            with_sat.ble_satellites.first().is_some_and(|sat| sat
                .evidence
                .iter()
                .any(|e| e.kind == LinkKind::BleNameMatchesMdnsName
                    && e.confidence == Confidence::Low)),
            "satellite carries low-confidence cross-link evidence"
        );
    }

    #[test]
    fn repeat_ble_observation_updates_rssi() {
        let mut g = IdentityGraph::new();
        let pid = crate::ble::PeripheralId::new("CB-UUID-XYZ");
        drop(g.observe(Observation::BleDevice {
            peripheral_id: pid.clone(),
            local_name: None,
            vendor: None,
            product: None,
            device_class: crate::ble::DeviceClass::Unknown,
            rssi: -80,
            service_uuids: vec![],
            observed_at: now0(),
        }));
        drop(g.observe(Observation::BleDevice {
            peripheral_id: pid,
            local_name: None,
            vendor: None,
            product: None,
            device_class: crate::ble::DeviceClass::Unknown,
            rssi: -40,
            service_uuids: vec![],
            observed_at: now0() + Duration::from_secs(1),
        }));
        assert_eq!(g.len(), 1);
        let c = g.candidates().next().expect("one");
        assert_eq!(c.ble_satellites.len(), 1);
        assert_eq!(
            c.ble_satellites.first().map(|s| s.rssi),
            Some(-40),
            "RSSI should be updated"
        );
    }
}
