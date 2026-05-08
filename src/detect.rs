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
const CACHE_FLUSH_LIMIT: usize = 1;
const GOODBYE_WINDOW: Duration = Duration::from_secs(2);
const GOODBYE_LIMIT: usize = 5;
const TAKEOVER_WINDOW: Duration = Duration::from_secs(5);
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
            Self::GoodbyeStorm { .. } => "medium",
            Self::MultiSourceUniqueRr { .. }
            | Self::WhodisConflictSignature { .. }
            | Self::CacheFlushRateExceeded { .. }
            | Self::GoodbyeThenTakeover { .. } => "high",
        }
    }
}

#[derive(Debug, Default)]
struct State {
    unique_rr_owners: HashMap<(String, RecordType), HashMap<IpAddr, String>>,
    cache_flush_times: HashMap<(String, RecordType, IpAddr), VecDeque<Instant>>,
    goodbye_times: HashMap<(String, IpAddr), VecDeque<Instant>>,
    last_goodbye: HashMap<String, (IpAddr, Instant)>,
    reported: HashSet<AnomalyKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AnomalyKey {
    MultiSource(String, RecordType),
    Whodis(String, RecordType),
    CacheFlush(String, RecordType, IpAddr),
    GoodbyeStorm(String, IpAddr),
    Takeover(String, RecordType, IpAddr, IpAddr),
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

    /// Test hook: explicit clock so windowed checks are deterministic.
    pub fn observe_at(&mut self, msg: &Message, src: SocketAddr, now: Instant) -> Vec<Anomaly> {
        if !matches!(msg.message_type(), MessageType::Response) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for record in msg.answers() {
            observe_record(&mut self.state, record, src.ip(), now, &mut out);
        }
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
    out: &mut Vec<Anomaly>,
) {
    let name = record.name().to_string();
    let qtype = record.record_type();
    let cache_flush = record.mdns_cache_flush;
    let ttl = record.ttl();

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

    if cache_flush && ttl > 0 {
        let times = state
            .cache_flush_times
            .entry((name.clone(), qtype, src))
            .or_default();
        times.push_back(now);
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) > CACHE_FLUSH_WINDOW)
        {
            times.pop_front();
        }
        if times.len() > CACHE_FLUSH_LIMIT {
            let key = AnomalyKey::CacheFlush(name.clone(), qtype, src);
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
        state.last_goodbye.insert(name, (src, now));
    } else if matches!(
        qtype,
        RecordType::A | RecordType::AAAA | RecordType::SRV | RecordType::PTR
    ) && let Some((prev_src, prev_time)) = state.last_goodbye.get(&name)
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
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let m = response_with_a("Camera.local.", Ipv4Addr::UNSPECIFIED, 120, true);
        drop(t.observe_at(&m, src("10.0.0.1"), now));
        let out = t.observe_at(&m, src("10.0.0.1"), now + Duration::from_millis(200));
        assert!(
            out.iter()
                .any(|a| matches!(a, Anomaly::CacheFlushRateExceeded { .. })),
            "expected CacheFlushRateExceeded, got {out:?}"
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

    #[test]
    fn queries_are_ignored() {
        let mut t = AnomalyTracker::new();
        let now = Instant::now();
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Query);
        let out = t.observe_at(&msg, src("10.0.0.1"), now);
        assert!(out.is_empty(), "queries should not produce anomalies");
    }
}
