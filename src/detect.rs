//! Passive detector for hostile or buggy mDNS responders on the LAN.
//!
//! Listens to multicast traffic and emits `Anomaly` events when patterns match
//! known spoofing signatures: multi-source ownership of a unique RR, cache-flush
//! rate exceeding RFC 6762 §8.3, goodbye storms, goodbye/takeover sequences,
//! and the `whodis-conflict` signature emitted by our own `flood conflict`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::hickory_compat::{MessageExt, RecordExt};
use crate::mode::Mode;
use crate::transport::{Transport, recv_one};

const CACHE_FLUSH_WINDOW: Duration = Duration::from_secs(1);
const CACHE_FLUSH_LIMIT: usize = 2;
const GOODBYE_WINDOW: Duration = Duration::from_secs(2);
const GOODBYE_LIMIT: usize = 5;
const TAKEOVER_WINDOW: Duration = Duration::from_secs(5);
const TYPE_GOODBYE_WINDOW: Duration = Duration::from_secs(5);
const TYPE_GOODBYE_LIMIT: usize = 5;
const MAX_TRACKED_NAMES: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum Anomaly {
    MultiSourceUniqueRr {
        name: String,
        qtype: String,
        sources: Vec<SourceObservation>,
    },
    WhodisConflictSignature {
        name: String,
        qtype: String,
        src: String,
    },
    CacheFlushRateExceeded {
        name: String,
        qtype: String,
        src: String,
        per_sec: usize,
    },
    GoodbyeStorm {
        name: String,
        src: String,
        count: usize,
    },
    GoodbyeThenTakeover {
        name: String,
        qtype: String,
        src_goodbye: String,
        src_takeover: String,
    },
    ServiceTypeGoodbyeBurst {
        service_type: String,
        src: String,
        instance_count: usize,
    },
    SourceIpMismatch {
        name: String,
        qtype: String,
        src: String,
        advertised: String,
    },
    UnsolicitedAdditional {
        name: String,
        qtype: String,
        src: String,
    },
    LlmnrPoisonResponder {
        name: String,
        src: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceObservation {
    pub src: String,
    pub rdata: String,
}

impl Anomaly {
    #[must_use]
    pub const fn severity(&self) -> &'static str {
        match self {
            Self::GoodbyeStorm { .. }
            | Self::ServiceTypeGoodbyeBurst { .. }
            | Self::UnsolicitedAdditional { .. } => "medium",
            Self::MultiSourceUniqueRr { .. }
            | Self::WhodisConflictSignature { .. }
            | Self::CacheFlushRateExceeded { .. }
            | Self::GoodbyeThenTakeover { .. }
            | Self::SourceIpMismatch { .. }
            | Self::LlmnrPoisonResponder { .. } => "high",
        }
    }
}

#[derive(Debug, Default)]
struct State {
    unique_rr_owners: HashMap<(String, RecordType), HashMap<IpAddr, String>>,
    cache_flush_times: HashMap<(String, RecordType, IpAddr, String), VecDeque<Instant>>,
    goodbye_times: HashMap<(String, IpAddr), VecDeque<Instant>>,
    last_goodbye: HashMap<String, (IpAddr, Instant)>,
    type_goodbye_targets: HashMap<(String, IpAddr), VecDeque<(Instant, String)>>,
    reported: HashSet<AnomalyKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AnomalyKey {
    MultiSource(String, RecordType),
    Whodis(String, RecordType),
    CacheFlush(String, RecordType, IpAddr, String),
    GoodbyeStorm(String, IpAddr),
    Takeover(String, RecordType, IpAddr, IpAddr),
    ServiceTypeGoodbyeBurst(String, IpAddr),
    SourceIpMismatch(String, RecordType, IpAddr, IpAddr),
    UnsolicitedAdditional(String, RecordType, IpAddr),
    LlmnrPoison(String, IpAddr),
}

/// Pure, transport-free anomaly tracker. Public so tests and embedders can drive it directly.
#[derive(Debug, Default)]
pub struct AnomalyTracker {
    state: State,
}

impl AnomalyTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, msg: &Message, src: SocketAddr) -> Vec<Anomaly> {
        self.observe_at(msg, src, Instant::now())
    }

    pub fn observe_llmnr_response(&mut self, name: &str, source: std::net::IpAddr) -> Vec<Anomaly> {
        let key = AnomalyKey::LlmnrPoison(name.to_string(), source);
        if !self.state.reported.insert(key) {
            return Vec::new();
        }
        vec![Anomaly::LlmnrPoisonResponder {
            name: name.to_string(),
            src: source.to_string(),
        }]
    }

    /// Test hook: explicit clock so windowed checks are deterministic.
    pub fn observe_at(&mut self, msg: &Message, src: SocketAddr, now: Instant) -> Vec<Anomaly> {
        if !matches!(msg.message_type(), MessageType::Response) {
            return Vec::new();
        }
        let packet_self_asserts = msg.answers().iter().any(|r| match r.data() {
            Some(RData::A(a)) => IpAddr::V4(a.0) == src.ip(),
            Some(RData::AAAA(a)) => IpAddr::V6(a.0) == src.ip(),
            _ => false,
        });
        let mut out = Vec::new();
        for record in msg.answers() {
            observe_record(
                &mut self.state,
                record,
                src.ip(),
                now,
                packet_self_asserts,
                &mut out,
            );
        }
        check_unsolicited_additionals(&mut self.state, msg, src.ip(), &mut out);
        if self.state.unique_rr_owners.len() > MAX_TRACKED_NAMES
            && let Some(k) = self.state.unique_rr_owners.keys().next().cloned()
        {
            self.state.unique_rr_owners.remove(&k);
        }
        out
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "linear per-anomaly checks; splitting hides the per-record dispatch flow"
)]
fn observe_record(
    state: &mut State,
    record: &Record,
    src: IpAddr,
    now: Instant,
    packet_self_asserts: bool,
    out: &mut Vec<Anomaly>,
) {
    let name = record.name().to_string();
    let qtype = record.record_type();
    let cache_flush = record.mdns_cache_flush;
    let ttl = record.ttl();

    check_source_ip_mismatch(state, record, &name, qtype, src, packet_self_asserts, out);

    if let Some(RData::SRV(srv)) = record.data()
        && srv
            .target
            .to_string()
            .to_ascii_lowercase()
            .contains("whodis-conflict")
    {
        let key = AnomalyKey::Whodis(name.clone(), qtype);
        if state.reported.insert(key) {
            out.push(Anomaly::WhodisConflictSignature {
                name: name.clone(),
                qtype: format!("{qtype:?}"),
                src: src.to_string(),
            });
        }
    }

    if cache_flush && matches!(qtype, RecordType::A | RecordType::AAAA) {
        let rdata = format_rdata(record);
        let owners = state
            .unique_rr_owners
            .entry((name.clone(), qtype))
            .or_default();
        owners.insert(src, rdata);
        let distinct: HashSet<&String> = owners.values().collect();
        if distinct.len() > 1 {
            let key = AnomalyKey::MultiSource(name.clone(), qtype);
            if state.reported.insert(key) {
                let mut sources: Vec<SourceObservation> = owners
                    .iter()
                    .map(|(ip, rd)| SourceObservation {
                        src: ip.to_string(),
                        rdata: rd.clone(),
                    })
                    .collect();
                sources.sort_by(|a, b| a.src.cmp(&b.src));
                out.push(Anomaly::MultiSourceUniqueRr {
                    name: name.clone(),
                    qtype: format!("{qtype:?}"),
                    sources,
                });
            }
        }
    }

    if cache_flush && ttl > 0 && !is_reverse_dns_name(&name) {
        let rdata_fp = format_rdata(record);
        let times = state
            .cache_flush_times
            .entry((name.clone(), qtype, src, rdata_fp.clone()))
            .or_default();
        times.push_back(now);
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) > CACHE_FLUSH_WINDOW)
        {
            times.pop_front();
        }
        if times.len() > CACHE_FLUSH_LIMIT {
            let key = AnomalyKey::CacheFlush(name.clone(), qtype, src, rdata_fp);
            if state.reported.insert(key) {
                out.push(Anomaly::CacheFlushRateExceeded {
                    name: name.clone(),
                    qtype: format!("{qtype:?}"),
                    src: src.to_string(),
                    per_sec: times.len(),
                });
            }
        }
    }

    if ttl == 0 {
        let times = state.goodbye_times.entry((name.clone(), src)).or_default();
        times.push_back(now);
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) > GOODBYE_WINDOW)
        {
            times.pop_front();
        }
        if times.len() > GOODBYE_LIMIT {
            let key = AnomalyKey::GoodbyeStorm(name.clone(), src);
            if state.reported.insert(key) {
                out.push(Anomaly::GoodbyeStorm {
                    name: name.clone(),
                    src: src.to_string(),
                    count: times.len(),
                });
            }
        }

        if qtype == RecordType::PTR
            && let Some(RData::PTR(ptr)) = record.data()
        {
            let target = ptr.0.to_string();
            let entries = state
                .type_goodbye_targets
                .entry((name.clone(), src))
                .or_default();
            entries.push_back((now, target));
            while entries
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t) > TYPE_GOODBYE_WINDOW)
            {
                entries.pop_front();
            }
            let distinct: HashSet<&String> = entries.iter().map(|(_, t)| t).collect();
            if distinct.len() > TYPE_GOODBYE_LIMIT {
                let key = AnomalyKey::ServiceTypeGoodbyeBurst(name.clone(), src);
                if state.reported.insert(key) {
                    out.push(Anomaly::ServiceTypeGoodbyeBurst {
                        service_type: name.clone(),
                        src: src.to_string(),
                        instance_count: distinct.len(),
                    });
                }
            }
        }

        state.last_goodbye.insert(name, (src, now));
    } else if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::SRV)
        && let Some((prev_src, prev_time)) = state.last_goodbye.get(&name)
        && *prev_src != src
        && now.duration_since(*prev_time) <= TAKEOVER_WINDOW
    {
        let key = AnomalyKey::Takeover(name.clone(), qtype, *prev_src, src);
        if state.reported.insert(key) {
            out.push(Anomaly::GoodbyeThenTakeover {
                name,
                qtype: format!("{qtype:?}"),
                src_goodbye: prev_src.to_string(),
                src_takeover: src.to_string(),
            });
        }
    }
}

fn check_unsolicited_additionals(
    state: &mut State,
    msg: &Message,
    src: IpAddr,
    out: &mut Vec<Anomaly>,
) {
    if src.is_loopback() || msg.additionals().is_empty() {
        return;
    }
    let mut reachable: HashSet<String> = HashSet::new();
    for r in msg.answers() {
        reachable.insert(normalize_name(&r.name().to_string()));
        expand_reachable_via_rdata(r, &mut reachable);
    }
    // Expand reachability through additional-section SRV/PTR records whose owner is
    // already reachable. This covers the multi-service Apple/Cast pattern where the
    // SRV linking instance->host sits in additionals, not answers. Iterate to fixed
    // point because chains like PTR -> SRV -> A may need multiple passes.
    let mut changed = true;
    while changed {
        changed = false;
        for r in msg.additionals() {
            let owner = normalize_name(&r.name().to_string());
            if !reachable.contains(&owner) {
                continue;
            }
            let before = reachable.len();
            expand_reachable_via_rdata(r, &mut reachable);
            if reachable.len() != before {
                changed = true;
            }
        }
    }
    for r in msg.additionals() {
        let qtype = r.record_type();
        if !matches!(qtype, RecordType::A | RecordType::AAAA) {
            continue;
        }
        let owner_raw = r.name().to_string();
        let owner = normalize_name(&owner_raw);
        if reachable.contains(&owner) {
            continue;
        }
        let key = AnomalyKey::UnsolicitedAdditional(owner.clone(), qtype, src);
        if state.reported.insert(key) {
            out.push(Anomaly::UnsolicitedAdditional {
                name: owner_raw,
                qtype: format!("{qtype:?}"),
                src: src.to_string(),
            });
        }
    }
}

fn normalize_name(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

fn expand_reachable_via_rdata(record: &Record, reachable: &mut HashSet<String>) {
    match record.data() {
        Some(RData::PTR(ptr)) => {
            reachable.insert(normalize_name(&ptr.0.to_string()));
        }
        Some(RData::SRV(srv)) => {
            reachable.insert(normalize_name(&srv.target.to_string()));
        }
        _ => {}
    }
}

fn is_reverse_dns_name(s: &str) -> bool {
    let n = normalize_name(s);
    n.ends_with(".in-addr.arpa") || n.ends_with(".ip6.arpa")
}

fn check_source_ip_mismatch(
    state: &mut State,
    record: &Record,
    name: &str,
    qtype: RecordType,
    src: IpAddr,
    packet_self_asserts: bool,
    out: &mut Vec<Anomaly>,
) {
    if src.is_loopback() || packet_self_asserts {
        return;
    }
    let advertised = match record.data() {
        Some(RData::A(a)) => IpAddr::V4(a.0),
        Some(RData::AAAA(a)) => IpAddr::V6(a.0),
        _ => return,
    };
    if advertised == src {
        return;
    }
    let key = AnomalyKey::SourceIpMismatch(name.to_string(), qtype, src, advertised);
    if state.reported.insert(key) {
        out.push(Anomaly::SourceIpMismatch {
            name: name.to_string(),
            qtype: format!("{qtype:?}"),
            src: src.to_string(),
            advertised: advertised.to_string(),
        });
    }
}

fn format_rdata(record: &Record) -> String {
    match record.data() {
        Some(RData::A(a)) => a.0.to_string(),
        Some(RData::AAAA(a)) => a.0.to_string(),
        Some(RData::SRV(s)) => format!("{}:{}", s.target, s.port),
        Some(RData::PTR(p)) => p.0.to_string(),
        Some(other) => format!("{other:?}"),
        None => "<no rdata>".to_string(),
    }
}

pub struct Detector {
    transport: Arc<Transport>,
    tracker: Mutex<AnomalyTracker>,
    cancel: CancellationToken,
    event_callback: Option<Arc<dyn Fn(Anomaly) + Send + Sync>>,
    include_local: bool,
}

impl Detector {
    pub fn new(mode: Mode) -> Result<Self> {
        if !mode.binds_port() {
            return Err(Error::InvalidServiceType(format!(
                "Detector requires Listen, Authoritative, or Custom mode, got {mode:?}"
            )));
        }
        let transport = Arc::new(Transport::build(mode)?);
        Ok(Self {
            transport,
            tracker: Mutex::new(AnomalyTracker::new()),
            cancel: CancellationToken::new(),
            event_callback: None,
            include_local: false,
        })
    }

    #[must_use]
    pub fn with_event_callback(
        mut self,
        callback: impl Fn(Anomaly) + Send + Sync + 'static,
    ) -> Self {
        self.event_callback = Some(Arc::new(callback));
        self
    }

    /// When true, observe traffic from local interface IPs as well. Off by default
    /// so a long-running watch on a multi-purpose host isn't drowned in legitimate
    /// local mDNS announces. Turn on to dogfood the detector against your own
    /// `flood`/`spoof` running on the same host.
    #[must_use]
    pub const fn with_include_local(mut self, include_local: bool) -> Self {
        self.include_local = include_local;
        self
    }

    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub async fn run(self) -> Result<()> {
        let v4 = self.transport.v4();
        let v6 = self.transport.v6();
        let mut buf = vec![0u8; 9000];
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                r = recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                    match r {
                        Ok(Some((n, src))) => {
                            if !self.include_local && self.transport.is_local_addr(src.ip()) {
                                continue;
                            }
                            let payload = buf.get(..n).unwrap_or(&[]);
                            let Ok(msg) = Message::from_bytes(payload) else {
                                continue;
                            };
                            self.dispatch(&msg, src);
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!(error = %e, "watch rx error, continuing"),
                    }
                }
            }
        }
    }

    fn dispatch(&self, msg: &Message, src: SocketAddr) {
        let Ok(mut tracker) = self.tracker.lock() else {
            return;
        };
        let anomalies = tracker.observe(msg, src);
        drop(tracker);
        if let Some(cb) = self.event_callback.as_ref() {
            for a in anomalies {
                cb(a);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, SRV};
    use hickory_proto::rr::{DNSClass, Name, RData, Record};

    use super::*;
    use crate::hickory_compat::RecordExt;

    fn response_with_a(name: &str, ip: Ipv4Addr, ttl: u32, cache_flush: bool) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let n = Name::from_utf8(name).expect("name");
        let mut rec = Record::from_rdata(n, ttl, RData::A(A(ip)));
        rec.set_dns_class(DNSClass::IN);
        if cache_flush {
            rec.set_mdns_cache_flush(true);
        }
        msg.add_answer(rec);
        msg
    }

    fn src(ip: &str) -> SocketAddr {
        format!("{ip}:5353").parse().expect("addr")
    }

    #[test]
    fn multi_source_unique_rr_fires_on_two_distinct_sources() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m1 = response_with_a("Camera.local.", Ipv4Addr::new(192, 168, 1, 42), 120, true);
        let m2 = response_with_a("Camera.local.", Ipv4Addr::new(192, 168, 1, 99), 120, true);
        drop(t.observe_at(&m1, src("192.168.1.42"), now));
        let out = t.observe_at(&m2, src("192.168.1.99"), now);
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::MultiSourceUniqueRr { .. })),
            "expected MultiSourceUniqueRr, got {out:?}"
        );
    }

    #[test]
    fn multi_source_does_not_fire_for_same_source_repeating() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::new(192, 168, 1, 42), 120, true);
        drop(t.observe_at(&m, src("192.168.1.42"), now));
        let out = t.observe_at(&m, src("192.168.1.42"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::MultiSourceUniqueRr { .. })),
            "single source should not fire MultiSourceUniqueRr"
        );
    }

    #[test]
    fn cache_flush_rate_fires_when_exceeded() {
        // RFC 6762 §8.2 allows announce + repeat after ~1s (2 in 1s), so 3+ is the
        // threshold for "exceeded".
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::UNSPECIFIED, 120, true);
        drop(t.observe_at(&m, src("10.0.0.1"), now));
        drop(t.observe_at(&m, src("10.0.0.1"), now + Duration::from_millis(100)));
        let out = t.observe_at(&m, src("10.0.0.1"), now + Duration::from_millis(200));
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::CacheFlushRateExceeded { .. })),
            "expected CacheFlushRateExceeded for 3-in-1s, got {out:?}"
        );
    }

    #[test]
    fn cache_flush_rate_does_not_fire_when_within_limit() {
        let mut t = AnomalyTracker::new();
        let base = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::UNSPECIFIED, 120, true);
        drop(t.observe_at(&m, src("10.0.0.1"), base));
        let out = t.observe_at(&m, src("10.0.0.1"), base + Duration::from_millis(1500));
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::CacheFlushRateExceeded { .. })),
            "1.5s gap should not exceed 1pps cache-flush limit"
        );
    }

    fn response_with_ptr_goodbye(owner: &str, target: &str) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let n = Name::from_utf8(owner).expect("owner");
        let t = Name::from_utf8(target).expect("target");
        let mut rec = Record::from_rdata(n, 0, RData::PTR(hickory_proto::rr::rdata::PTR(t)));
        rec.set_dns_class(DNSClass::IN);
        msg.add_answer(rec);
        msg
    }

    #[test]
    fn service_type_goodbye_burst_fires_on_six_distinct_instances() {
        let mut t = AnomalyTracker::new();
        let base = Instant::now();
        let owner = "_googlecast._tcp.local.";
        let mut anomalies: Vec<Anomaly> = Vec::new();
        for i in 0..6 {
            let target = format!("Speaker{i}._googlecast._tcp.local.");
            let m = response_with_ptr_goodbye(owner, &target);
            anomalies.extend(t.observe_at(
                &m,
                src("10.0.0.1"),
                base + Duration::from_millis(i * 100),
            ));
        }
        assert!(
            anomalies
                .iter()
                .any(|a| matches!(a, Anomaly::ServiceTypeGoodbyeBurst { .. })),
            "expected ServiceTypeGoodbyeBurst after 6 distinct instance goodbyes, got {anomalies:?}"
        );
    }

    #[test]
    fn service_type_goodbye_burst_does_not_fire_for_one_repeated_instance() {
        let mut t = AnomalyTracker::new();
        let base = Instant::now();
        let owner = "_googlecast._tcp.local.";
        let target = "OnlySpeaker._googlecast._tcp.local.";
        let mut anomalies: Vec<Anomaly> = Vec::new();
        for i in 0..6 {
            let m = response_with_ptr_goodbye(owner, target);
            anomalies.extend(t.observe_at(
                &m,
                src("10.0.0.1"),
                base + Duration::from_millis(i * 100),
            ));
        }
        assert!(
            !anomalies
                .iter()
                .any(|a| matches!(a, Anomaly::ServiceTypeGoodbyeBurst { .. })),
            "single repeated instance must not fire ServiceTypeGoodbyeBurst (that's GoodbyeStorm), got {anomalies:?}"
        );
    }

    #[test]
    fn goodbye_storm_fires_when_limit_exceeded() {
        let mut t = AnomalyTracker::new();
        let base = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::UNSPECIFIED, 0, false);
        for i in 0..5 {
            drop(t.observe_at(&m, src("10.0.0.1"), base + Duration::from_millis(i * 100)));
        }
        let out = t.observe_at(&m, src("10.0.0.1"), base + Duration::from_millis(600));
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::GoodbyeStorm { .. })),
            "expected GoodbyeStorm after 6 goodbyes within window, got {out:?}"
        );
    }

    #[test]
    fn goodbye_then_takeover_fires_when_different_source_announces() {
        let mut t = AnomalyTracker::new();
        let base = Instant::now();
        let goodbye = response_with_a("Camera.local.", Ipv4Addr::UNSPECIFIED, 0, false);
        drop(t.observe_at(&goodbye, src("192.168.1.42"), base));
        let takeover = response_with_a("Camera.local.", Ipv4Addr::new(192, 168, 1, 99), 120, true);
        let out = t.observe_at(
            &takeover,
            src("192.168.1.99"),
            base + Duration::from_secs(2),
        );
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::GoodbyeThenTakeover { .. })),
            "expected GoodbyeThenTakeover, got {out:?}"
        );
    }

    #[test]
    fn whodis_conflict_signature_fires_on_srv_target() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let n = Name::from_utf8("Foo._airplay._tcp.local.").expect("name");
        let target = Name::from_utf8("whodis-conflict.local.").expect("target");
        let mut rec = Record::from_rdata(n, 120, RData::SRV(SRV::new(0, 0, 0, target)));
        rec.set_dns_class(DNSClass::IN);
        msg.add_answer(rec);
        let out = t.observe_at(&msg, src("10.0.0.99"), now);
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::WhodisConflictSignature { .. })),
            "expected WhodisConflictSignature, got {out:?}"
        );
    }

    #[test]
    fn anomalies_dedup_within_session() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m1 = response_with_a("X.local.", Ipv4Addr::new(1, 1, 1, 1), 120, true);
        let m2 = response_with_a("X.local.", Ipv4Addr::new(2, 2, 2, 2), 120, true);
        drop(t.observe_at(&m1, src("10.0.0.1"), now));
        let first = t.observe_at(&m2, src("10.0.0.2"), now);
        let again = t.observe_at(&m2, src("10.0.0.2"), now);
        assert!(
            first
                .iter()
                .any(|a| matches!(a, Anomaly::MultiSourceUniqueRr { .. }))
        );
        assert!(
            !again
                .iter()
                .any(|a| matches!(a, Anomaly::MultiSourceUniqueRr { .. })),
            "same anomaly should not refire within a session"
        );
    }

    fn response_with_two_a(name: &str, ip1: Ipv4Addr, ip2: Ipv4Addr) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let n = Name::from_utf8(name).expect("name");
        let mut r1 = Record::from_rdata(n.clone(), 120, RData::A(A(ip1)));
        r1.set_dns_class(DNSClass::IN);
        msg.add_answer(r1);
        let mut r2 = Record::from_rdata(n, 120, RData::A(A(ip2)));
        r2.set_dns_class(DNSClass::IN);
        msg.add_answer(r2);
        msg
    }

    fn response_with_aaaa(name: &str, ip: std::net::Ipv6Addr) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let n = Name::from_utf8(name).expect("name");
        let mut rec = Record::from_rdata(n, 120, RData::AAAA(hickory_proto::rr::rdata::AAAA(ip)));
        rec.set_dns_class(DNSClass::IN);
        msg.add_answer(rec);
        msg
    }

    #[test]
    fn source_ip_mismatch_fires_when_record_claims_unrelated_address() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::new(10, 0, 0, 50), 120, false);
        let out = t.observe_at(&m, src("192.168.1.99"), now);
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::SourceIpMismatch { .. })),
            "expected SourceIpMismatch, got {out:?}"
        );
    }

    #[test]
    fn source_ip_mismatch_does_not_fire_when_advertised_matches_src() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::new(192, 168, 1, 5), 120, false);
        let out = t.observe_at(&m, src("192.168.1.5"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::SourceIpMismatch { .. })),
            "self-assert must not fire, got {out:?}"
        );
    }

    #[test]
    fn source_ip_mismatch_does_not_fire_when_other_record_in_packet_matches_src() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_two_a(
            "Camera.local.",
            Ipv4Addr::new(192, 168, 1, 5),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let out = t.observe_at(&m, src("192.168.1.5"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::SourceIpMismatch { .. })),
            "multi-homed self-assert (one record matches src) must suppress, got {out:?}"
        );
    }

    #[test]
    fn source_ip_mismatch_fires_for_unspecified_address() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::UNSPECIFIED, 120, true);
        let out = t.observe_at(&m, src("192.168.1.42"), now);
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::SourceIpMismatch { advertised, .. } if advertised == "0.0.0.0")),
            "sinkhole flood (0.0.0.0) must fire, got {out:?}"
        );
    }

    #[test]
    fn source_ip_mismatch_does_not_fire_for_loopback_src() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::new(10, 0, 0, 50), 120, false);
        let out = t.observe_at(&m, src("127.0.0.1"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::SourceIpMismatch { .. })),
            "loopback src must not fire (test infra carve-out), got {out:?}"
        );
    }

    #[test]
    fn source_ip_mismatch_fires_for_aaaa_when_src_is_v4_and_no_a_self_asserts() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_aaaa(
            "Camera.local.",
            std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xdead, 0xbeef),
        );
        let out = t.observe_at(&m, src("192.168.1.99"), now);
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::SourceIpMismatch { qtype, .. } if qtype == "AAAA")),
            "v4 src + AAAA-only with no v4 self-assert must fire, got {out:?}"
        );
    }

    fn response_with_ptr_answer_and_decoy_a(
        service_type: &str,
        instance: &str,
        decoy_owner: &str,
        decoy_ip: Ipv4Addr,
    ) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let owner = Name::from_utf8(service_type).expect("st");
        let target = Name::from_utf8(instance).expect("inst");
        let mut ptr = Record::from_rdata(
            owner,
            120,
            RData::PTR(hickory_proto::rr::rdata::PTR(target)),
        );
        ptr.set_dns_class(DNSClass::IN);
        msg.add_answer(ptr);
        let decoy_name = Name::from_utf8(decoy_owner).expect("decoy");
        let mut decoy = Record::from_rdata(decoy_name, 120, RData::A(A(decoy_ip)));
        decoy.set_dns_class(DNSClass::IN);
        decoy.set_mdns_cache_flush(true);
        msg.add_additional(decoy);
        msg
    }

    fn response_with_ptr_answer_and_legit_srv_additional(
        service_type: &str,
        instance: &str,
    ) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let owner = Name::from_utf8(service_type).expect("st");
        let inst = Name::from_utf8(instance).expect("inst");
        let mut ptr = Record::from_rdata(
            owner,
            120,
            RData::PTR(hickory_proto::rr::rdata::PTR(inst.clone())),
        );
        ptr.set_dns_class(DNSClass::IN);
        msg.add_answer(ptr);
        let host = Name::from_utf8("FakeHost.local.").expect("host");
        let mut srv = Record::from_rdata(
            inst,
            120,
            RData::SRV(hickory_proto::rr::rdata::SRV::new(0, 0, 7000, host)),
        );
        srv.set_dns_class(DNSClass::IN);
        msg.add_additional(srv);
        msg
    }

    #[test]
    fn unsolicited_additional_fires_on_unreferenced_owner() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_ptr_answer_and_decoy_a(
            "_airplay._tcp.local.",
            "FakeATV._airplay._tcp.local.",
            "Camera.local.",
            Ipv4Addr::UNSPECIFIED,
        );
        let out = t.observe_at(&m, src("192.168.1.99"), now);
        assert!(
            out.iter().any(|a| matches!(
                a,
                Anomaly::UnsolicitedAdditional { name, .. }
                    if name.eq_ignore_ascii_case("Camera.local.")
            )),
            "expected UnsolicitedAdditional for Camera.local., got {out:?}"
        );
    }

    #[test]
    fn unsolicited_additional_does_not_fire_on_apple_pattern() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_ptr_answer_and_legit_srv_additional(
            "_airplay._tcp.local.",
            "FakeATV._airplay._tcp.local.",
        );
        let out = t.observe_at(&m, src("192.168.1.42"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::UnsolicitedAdditional { .. })),
            "Apple-style PTR-then-SRV additional must not fire, got {out:?}"
        );
    }

    #[test]
    fn unsolicited_additional_does_not_fire_when_srv_in_additionals_links_to_a() {
        // Cast/Apple multi-service pattern: PTR answer, SRV in additionals owned by
        // the PTR's target, A in additionals owned by the SRV's target.
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let st = Name::from_utf8("_googlecast._tcp.local.").expect("st");
        let inst = Name::from_utf8("9c2aded4._googlecast._tcp.local.").expect("inst");
        let host = Name::from_utf8("9c2aded4.local.").expect("host");
        let mut ptr = Record::from_rdata(
            st,
            120,
            RData::PTR(hickory_proto::rr::rdata::PTR(inst.clone())),
        );
        ptr.set_dns_class(DNSClass::IN);
        msg.add_answer(ptr);
        let mut srv = Record::from_rdata(
            inst,
            120,
            RData::SRV(hickory_proto::rr::rdata::SRV::new(0, 0, 8009, host.clone())),
        );
        srv.set_dns_class(DNSClass::IN);
        msg.add_additional(srv);
        let mut a = Record::from_rdata(host, 120, RData::A(A(Ipv4Addr::new(192, 168, 50, 224))));
        a.set_dns_class(DNSClass::IN);
        msg.add_additional(a);
        let out = t.observe_at(&msg, src("192.168.50.224"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::UnsolicitedAdditional { .. })),
            "PTR -> SRV (additional) -> A (additional) chain must not fire, got {out:?}"
        );
    }

    #[test]
    fn cache_flush_rate_skips_reverse_dns_names() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a(
            "166.50.168.192.in-addr.arpa.",
            Ipv4Addr::new(192, 168, 50, 166),
            120,
            true,
        );
        drop(t.observe_at(&m, src("192.168.50.166"), now));
        let out = t.observe_at(&m, src("192.168.50.166"), now + Duration::from_millis(200));
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::CacheFlushRateExceeded { .. })),
            "reverse-DNS PTRs must not trip cache-flush rate, got {out:?}"
        );
    }

    #[test]
    fn unsolicited_additional_skips_non_a_aaaa_types() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let owner = Name::from_utf8("_printer._tcp.local.").expect("owner");
        let inst = Name::from_utf8("Foo._printer._tcp.local.").expect("inst");
        let mut ptr =
            Record::from_rdata(owner, 120, RData::PTR(hickory_proto::rr::rdata::PTR(inst)));
        ptr.set_dns_class(DNSClass::IN);
        msg.add_answer(ptr);
        let other = Name::from_utf8("Bar._pdl-datastream._tcp.local.").expect("other");
        let mut txt = Record::from_rdata(
            other,
            120,
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["a=b".to_string()])),
        );
        txt.set_dns_class(DNSClass::IN);
        msg.add_additional(txt);
        let out = t.observe_at(&msg, src("192.168.50.103"), now);
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::UnsolicitedAdditional { .. })),
            "TXT/SRV/PTR/NSEC additionals must not fire unsolicited (multi-service noise), got {out:?}"
        );
    }

    #[test]
    fn goodbye_then_takeover_skips_ptr_records() {
        let mut t = AnomalyTracker::new();
        let base = Instant::now();
        let mut goodbye = Message::new(0, MessageType::Query, OpCode::Query);
        goodbye
            .set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let owner = Name::from_utf8("_remotepairing._tcp.local.").expect("owner");
        let inst_a = Name::from_utf8("DeviceA._remotepairing._tcp.local.").expect("a");
        let mut ptr_g = Record::from_rdata(
            owner.clone(),
            0,
            RData::PTR(hickory_proto::rr::rdata::PTR(inst_a)),
        );
        ptr_g.set_dns_class(DNSClass::IN);
        goodbye.add_answer(ptr_g);
        drop(t.observe_at(&goodbye, src("192.168.50.166"), base));

        let mut announce = Message::new(0, MessageType::Query, OpCode::Query);
        announce
            .set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        let inst_b = Name::from_utf8("DeviceB._remotepairing._tcp.local.").expect("b");
        let mut ptr_a = Record::from_rdata(
            owner,
            120,
            RData::PTR(hickory_proto::rr::rdata::PTR(inst_b)),
        );
        ptr_a.set_dns_class(DNSClass::IN);
        announce.add_answer(ptr_a);
        let out = t.observe_at(
            &announce,
            src("192.168.50.223"),
            base + Duration::from_secs(2),
        );
        assert!(
            !out.iter()
                .any(|a| matches!(a, Anomaly::GoodbyeThenTakeover { .. })),
            "shared PTR rotation must not fire takeover, got {out:?}"
        );
    }

    #[test]
    fn queries_are_ignored() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Query);
        let out = t.observe_at(&msg, src("10.0.0.1"), now);
        assert!(out.is_empty(), "queries should not produce anomalies");
    }

    #[test]
    fn llmnr_poison_responder_fires_on_unknown_source() {
        let mut tracker = AnomalyTracker::new();
        let src1: std::net::IpAddr = "10.0.0.5".parse().expect("ip");

        let anomalies = tracker.observe_llmnr_response("wpad", src1);
        assert!(
            anomalies.iter().any(|a| matches!(
                a,
                Anomaly::LlmnrPoisonResponder { name, src }
                    if name == "wpad" && src == &src1.to_string()
            )),
            "expected LlmnrPoisonResponder with correct name and src, got {anomalies:?}"
        );

        // Same source for the same name does not re-fire (dedup).
        let again = tracker.observe_llmnr_response("wpad", src1);
        assert!(again.is_empty(), "expected dedup, got {again:?}");
    }

    #[test]
    fn llmnr_poison_responder_fires_per_source_per_name() {
        let mut tracker = AnomalyTracker::new();
        let src1: std::net::IpAddr = "10.0.0.5".parse().expect("ip");
        let src2: std::net::IpAddr = "10.0.0.6".parse().expect("ip");

        drop(tracker.observe_llmnr_response("wpad", src1));
        let second = tracker.observe_llmnr_response("wpad", src2);
        assert!(
            second.iter().any(|a| matches!(
                a,
                Anomaly::LlmnrPoisonResponder { src, .. } if src == &src2.to_string()
            )),
            "expected LlmnrPoisonResponder with src2, got {second:?}"
        );
    }
}
