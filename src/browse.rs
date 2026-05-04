//! Continuous mDNS service browser.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::mode::Mode;
use crate::transport::{Destination, Transport};
use crate::types::{Instance, Protocol, ServiceType};

const META_QUERY: &str = "_services._dns-sd._udp.local.";
const BACKOFF_STEPS_MS: &[u64] = &[1_000, 2_000, 4_000, 8_000];
const STEADY_INTERVAL: Duration = Duration::from_mins(1);

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    ServiceTypeFound { service_type: ServiceType },
    InstanceFound { instance: Instance },
    InstanceUpdated { instance: Instance },
    InstanceGoodbye { fqdn: String },
}

#[derive(Debug)]
struct CacheEntry {
    instance: Instance,
}

pub struct Browser {
    transport: Arc<Transport>,
    cache: Arc<DashMap<String, CacheEntry>>,
    known_service_types: Arc<DashMap<String, ServiceType>>,
    cancel: CancellationToken,
}

impl Browser {
    pub fn new(mode: Mode) -> Result<Self> {
        let transport = Arc::new(Transport::build(mode)?);
        Ok(Self {
            transport,
            cache: Arc::new(DashMap::new()),
            known_service_types: Arc::new(DashMap::new()),
            cancel: CancellationToken::new(),
        })
    }

    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn run(self) -> impl Stream<Item = Event> + Send + 'static {
        let (tx, rx) = mpsc::channel::<Event>(1024);
        let cancel = self.cancel.clone();

        let rx_transport = self.transport.clone();
        let rx_cache = self.cache.clone();
        let rx_types = self.known_service_types.clone();
        let rx_cancel = cancel.clone();
        tokio::spawn(async move {
            run_rx(rx_transport, rx_cache, rx_types, tx, rx_cancel).await;
        });

        let tx_transport = self.transport;
        let tx_types = self.known_service_types;
        tokio::spawn(async move {
            run_tx(tx_transport, tx_types, cancel).await;
        });

        ReceiverStream::new(rx)
    }
}

async fn run_tx(
    transport: Arc<Transport>,
    known: Arc<DashMap<String, ServiceType>>,
    cancel: CancellationToken,
) {
    for (idx, ms) in BACKOFF_STEPS_MS.iter().enumerate() {
        if send_round(&transport, &known).await.is_err() {
            tracing::debug!("tx round {idx} send failed, continuing");
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(Duration::from_millis(*ms)) => {}
        }
    }
    loop {
        if send_round(&transport, &known).await.is_err() {
            tracing::debug!("steady tx send failed, continuing");
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(STEADY_INTERVAL) => {}
        }
    }
}

async fn send_round(transport: &Transport, known: &DashMap<String, ServiceType>) -> Result<()> {
    let meta = build_query(META_QUERY, RecordType::PTR)?;
    transport.send_query(&meta, Destination::Multicast).await?;
    #[allow(
        clippy::explicit_iter_loop,
        reason = "DashMap::iter() returns a specialized type, not IntoIterator"
    )]
    for entry in known.iter() {
        let q = build_query(&entry.value().fqdn(), RecordType::PTR)?;
        transport.send_query(&q, Destination::Multicast).await?;
    }
    Ok(())
}

fn build_query(name: &str, qtype: RecordType) -> Result<Vec<u8>> {
    let n =
        Name::from_utf8(name).map_err(|_| crate::Error::InvalidServiceType(name.to_string()))?;
    let mut m = Message::new();
    m.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    let q = Query::query(n, qtype);
    m.add_query(q);
    Ok(m.to_bytes()?)
}

async fn run_rx(
    transport: Arc<Transport>,
    cache: Arc<DashMap<String, CacheEntry>>,
    known: Arc<DashMap<String, ServiceType>>,
    out: mpsc::Sender<Event>,
    cancel: CancellationToken,
) {
    let v4 = transport.v4();
    let v6 = transport.v6();
    let mut buf = vec![0u8; 9000];
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            r = recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                match r {
                    Ok(Some(n)) => {
                        let payload = buf.get(..n).unwrap_or(&[]);
                        if let Ok(msg) = Message::from_bytes(payload) {
                            handle_message(&msg, &cache, &known, &out).await;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!(error = %e, "rx error, continuing"),
                }
            }
        }
    }
}

async fn recv_one(
    v4: Option<&Arc<tokio::net::UdpSocket>>,
    v6: Option<&Arc<tokio::net::UdpSocket>>,
    buf: &mut [u8],
) -> std::io::Result<Option<usize>> {
    match (v4, v6) {
        (Some(s4), Some(s6)) => {
            let mut b6 = vec![0u8; buf.len()];
            tokio::select! {
                r = s4.recv_from(buf) => r.map(|(n, _)| Some(n)),
                r = s6.recv_from(&mut b6) => {
                    match r {
                        Ok((n, _)) => {
                            if let (Some(dst), Some(src)) = (buf.get_mut(..n), b6.get(..n)) {
                                dst.copy_from_slice(src);
                            }
                            Ok(Some(n))
                        }
                        Err(e) => Err(e),
                    }
                },
            }
        }
        (Some(s4), None) => s4.recv_from(buf).await.map(|(n, _)| Some(n)),
        (None, Some(s6)) => s6.recv_from(buf).await.map(|(n, _)| Some(n)),
        (None, None) => Ok(None),
    }
}

#[allow(
    clippy::cognitive_complexity,
    reason = "DNS record-type dispatch is naturally branchy"
)]
async fn handle_message(
    msg: &Message,
    cache: &DashMap<String, CacheEntry>,
    known: &DashMap<String, ServiceType>,
    out: &mpsc::Sender<Event>,
) {
    let records: Vec<&Record> = msg.answers().iter().chain(msg.additionals()).collect();
    let mut staged: BTreeMap<String, Instance> = BTreeMap::new();

    for r in &records {
        match r.data() {
            Some(RData::PTR(ptr)) => {
                let target = ptr_target(ptr);
                let owner = r.name().to_string();
                if owner == META_QUERY {
                    if let Some(svc) = parse_service_type_from_owner(&target.to_string())
                        && known.insert(svc.fqdn(), svc.clone()).is_none()
                    {
                        out.send(Event::ServiceTypeFound { service_type: svc })
                            .await
                            .ok();
                    }
                } else if let Some(svc) = parse_service_type_from_owner(&owner) {
                    let inst_name = leftmost_label(target);
                    let target_str = target.to_string();
                    let inst = staged
                        .entry(target_str.clone())
                        .or_insert_with(|| Instance {
                            service_type: svc.clone(),
                            instance_name: inst_name,
                            host: String::new(),
                            port: 0,
                            txt: BTreeMap::new(),
                        });
                    if r.ttl() == 0 {
                        out.send(Event::InstanceGoodbye {
                            fqdn: target_str.clone(),
                        })
                        .await
                        .ok();
                        cache.remove(&target_str);
                        staged.remove(&target_str);
                    } else {
                        inst.service_type = svc;
                    }
                }
            }
            Some(RData::SRV(srv)) => {
                let key = r.name().to_string();
                let inst = staged.entry(key.clone()).or_insert_with(|| Instance {
                    service_type: parse_service_type_from_owner(&key).unwrap_or_else(empty_service),
                    instance_name: leftmost_label(r.name()),
                    host: String::new(),
                    port: 0,
                    txt: BTreeMap::new(),
                });
                inst.host = srv.target().to_string();
                inst.port = srv.port();
            }
            Some(RData::TXT(txt)) => {
                let key = r.name().to_string();
                let inst = staged.entry(key.clone()).or_insert_with(|| Instance {
                    service_type: parse_service_type_from_owner(&key).unwrap_or_else(empty_service),
                    instance_name: leftmost_label(r.name()),
                    host: String::new(),
                    port: 0,
                    txt: BTreeMap::new(),
                });
                for kv in txt.iter() {
                    if let Some((k, v)) = split_kv(kv) {
                        inst.txt.insert(k, v);
                    }
                }
            }
            _ => {}
        }
    }

    emit_staged(staged, cache, out).await;
}

async fn emit_staged(
    staged: BTreeMap<String, Instance>,
    cache: &DashMap<String, CacheEntry>,
    out: &mpsc::Sender<Event>,
) {
    for (key, inst) in staged {
        match cache.get(&key) {
            None => {
                if inst.port == 0 {
                    continue;
                }
                out.send(Event::InstanceFound {
                    instance: inst.clone(),
                })
                .await
                .ok();
                cache.insert(key, CacheEntry { instance: inst });
            }
            Some(prev) => {
                let mut merged = prev.instance.clone();
                let original = merged.clone();
                drop(prev);
                merge_partial(&mut merged, inst);
                if merged == original || merged.port == 0 {
                    continue;
                }
                out.send(Event::InstanceUpdated {
                    instance: merged.clone(),
                })
                .await
                .ok();
                cache.insert(key, CacheEntry { instance: merged });
            }
        }
    }
}

fn merge_partial(base: &mut Instance, partial: Instance) {
    if partial.service_type.name != "_unknown" {
        base.service_type = partial.service_type;
    }
    if !partial.instance_name.is_empty() {
        base.instance_name = partial.instance_name;
    }
    if !partial.host.is_empty() {
        base.host = partial.host;
    }
    if partial.port != 0 {
        base.port = partial.port;
    }
    base.txt.extend(partial.txt);
}

/// Extract the target Name from a PTR record. hickory-proto 0.24 represents PTR as
/// `PTR(pub Name)` (tuple struct with public field).
fn ptr_target(ptr: &hickory_proto::rr::rdata::PTR) -> &Name {
    &ptr.0
}

fn parse_service_type_from_owner(s: &str) -> Option<ServiceType> {
    let trimmed = s.trim_end_matches('.').trim_end_matches(".local");
    let parts: Vec<&str> = trimmed.split('.').collect();
    let n = parts.len();
    if n < 2 {
        return None;
    }
    let proto = match parts.get(n - 1).copied() {
        Some("_tcp") => Protocol::Tcp,
        Some("_udp") => Protocol::Udp,
        _ => return None,
    };
    let svc = (*parts.get(n - 2)?).to_string();
    if !svc.starts_with('_') {
        return None;
    }
    Some(ServiceType::new(svc, proto))
}

fn empty_service() -> ServiceType {
    ServiceType::new("_unknown", Protocol::Tcp)
}

fn leftmost_label(name: &Name) -> String {
    name.iter()
        .next()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

fn split_kv(raw: &[u8]) -> Option<(String, Bytes)> {
    let eq = raw.iter().position(|b| *b == b'=')?;
    let (k, rest) = raw.split_at(eq);
    let key = std::str::from_utf8(k).ok()?.to_string();
    let value = Bytes::copy_from_slice(rest.get(1..)?);
    Some((key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_service_type_accepts_canonical() {
        let s = parse_service_type_from_owner("_airplay._tcp.local.").expect("parse");
        assert_eq!(s.name, "_airplay");
        assert_eq!(s.protocol, Protocol::Tcp);
    }

    #[test]
    fn parse_service_type_accepts_udp() {
        let s = parse_service_type_from_owner("_dns-sd._udp.local.").expect("parse");
        assert_eq!(s.protocol, Protocol::Udp);
    }

    #[test]
    fn parse_service_type_rejects_non_underscore_service() {
        assert!(parse_service_type_from_owner("foo._tcp.local.").is_none());
    }

    #[test]
    fn build_query_returns_nonempty_bytes() {
        let bytes = build_query("_airplay._tcp.local.", RecordType::PTR).expect("build");
        assert!(bytes.len() > 12);
    }

    #[test]
    fn merge_partial_preserves_cached_fields() {
        let mut base = Instance {
            service_type: ServiceType::new("_airplay", Protocol::Tcp),
            instance_name: "Living".into(),
            host: "Living.local.".into(),
            port: 7000,
            txt: BTreeMap::new(),
        };
        let mut partial_txt = BTreeMap::new();
        partial_txt.insert("model".into(), Bytes::from_static(b"AppleTV11,1"));
        let partial = Instance {
            service_type: empty_service(),
            instance_name: "Living".into(),
            host: String::new(),
            port: 0,
            txt: partial_txt,
        };

        merge_partial(&mut base, partial);

        assert_eq!(base.host, "Living.local.");
        assert_eq!(base.port, 7000);
        assert!(base.txt.contains_key("model"));
    }
}
