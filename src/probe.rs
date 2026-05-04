//! One-shot directed mDNS queries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};
use crate::types::{HostAnswer, Instance, Protocol, ServiceType};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub timeout: Duration,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

pub async fn probe_service(service: &ServiceType, opts: &ProbeOptions) -> Result<Vec<Instance>> {
    let transport = Transport::build(Mode::QueryOnly)?;
    let qname = parse_name(&service.fqdn())?;
    let msg = build_query(&qname, RecordType::PTR);
    send_and_collect(&transport, &msg, opts.timeout, |records| {
        decode_instances(service, records)
    })
    .await
}

pub async fn probe_instance(
    instance_name: &str,
    service: &ServiceType,
    opts: &ProbeOptions,
) -> Result<Vec<Instance>> {
    let transport = Transport::build(Mode::QueryOnly)?;
    let fqdn = format!("{}.{}", instance_name, service.fqdn());
    let qname = parse_name(&fqdn)?;
    let msg = build_query(&qname, RecordType::SRV);
    send_and_collect(&transport, &msg, opts.timeout, |records| {
        decode_instances(service, records)
    })
    .await
}

pub async fn probe_host(host: &str, opts: &ProbeOptions) -> Result<Vec<HostAnswer>> {
    let transport = Transport::build(Mode::QueryOnly)?;
    let qname = parse_name(host)?;
    let mut msg = build_query(&qname, RecordType::A);
    msg.add_query(Query::query(qname.clone(), RecordType::AAAA));
    send_and_collect(&transport, &msg, opts.timeout, |records| {
        decode_host_answers(host, records)
    })
    .await
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceTypeSummary {
    pub fqdn: String,
    pub instance_count: usize,
}

const META_QUERY: &str = "_services._dns-sd._udp.local.";

/// Run an mDNS DNS-SD meta-query and return one summary per service type seen on the LAN,
/// each tagged with the number of distinct instances it is currently advertising.
pub async fn discover_service_types(opts: &ProbeOptions) -> Result<Vec<ServiceTypeSummary>> {
    let transport = Transport::build(Mode::QueryOnly)?;
    let half = opts.timeout / 2;

    // Phase 1: ask for service-type names.
    let meta_q = build_query(&parse_name(META_QUERY)?, RecordType::PTR);
    let types: Vec<ServiceType> =
        send_and_collect(&transport, &meta_q, half, decode_service_types).await?;

    let mut unique: Vec<ServiceType> = types;
    unique.sort_by(|a, b| (a.protocol.as_str(), &a.name).cmp(&(b.protocol.as_str(), &b.name)));
    unique.dedup();
    if unique.is_empty() {
        return Ok(Vec::new());
    }

    // Phase 2: ask for instance PTRs of every discovered type in one batch.
    let mut q_msg = Message::new();
    q_msg
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    for st in &unique {
        let n = parse_name(&st.fqdn())?;
        let mut q = Query::query(n, RecordType::PTR);
        q.set_query_class(DNSClass::IN);
        q_msg.add_query(q);
    }

    let pairs: Vec<(String, String)> =
        send_and_collect(&transport, &q_msg, half, decode_ptr_pairs).await?;

    let mut counts: HashMap<String, HashSet<String>> = HashMap::new();
    for (owner, target) in pairs {
        counts.entry(owner).or_default().insert(target);
    }

    Ok(unique
        .into_iter()
        .map(|st| {
            let fqdn = st.fqdn();
            let instance_count = counts.get(&fqdn).map_or(0, HashSet::len);
            ServiceTypeSummary {
                fqdn,
                instance_count,
            }
        })
        .collect())
}

fn decode_service_types(records: &[Record]) -> Vec<ServiceType> {
    records
        .iter()
        .filter_map(|r| {
            if r.record_type() != RecordType::PTR
                || r.name().to_string().trim_end_matches('.') != META_QUERY.trim_end_matches('.')
            {
                return None;
            }
            match r.data() {
                Some(RData::PTR(ptr)) => parse_service_type_from_name(&ptr.0.to_string()),
                _ => None,
            }
        })
        .collect()
}

fn decode_ptr_pairs(records: &[Record]) -> Vec<(String, String)> {
    records
        .iter()
        .filter_map(|r| {
            if r.record_type() != RecordType::PTR {
                return None;
            }
            match r.data() {
                Some(RData::PTR(ptr)) => Some((r.name().to_string(), ptr.0.to_string())),
                _ => None,
            }
        })
        .collect()
}

fn parse_service_type_from_name(s: &str) -> Option<ServiceType> {
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

fn parse_name(s: &str) -> Result<Name> {
    Name::from_utf8(s).map_err(|_| Error::InvalidServiceType(s.to_string()))
}

fn build_query(name: &Name, qtype: RecordType) -> Message {
    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    let mut q = Query::query(name.clone(), qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg
}

async fn send_and_collect<T, F>(
    transport: &Transport,
    msg: &Message,
    timeout: Duration,
    decode: F,
) -> Result<Vec<T>>
where
    F: Fn(&[Record]) -> Vec<T>,
{
    let bytes = msg.to_bytes()?;
    transport.send_query(&bytes, Destination::Multicast).await?;
    let mut buf = vec![0u8; 9000];
    let mut records: Vec<Record> = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = async {
            if let Some(s) = transport.v4() {
                s.recv_from(&mut buf).await
            } else if let Some(s) = transport.v6() {
                s.recv_from(&mut buf).await
            } else {
                Err(std::io::Error::other("no socket"))
            }
        };
        match tokio::time::timeout(remaining, recv).await {
            Ok(Ok((n, _addr))) => {
                if let Ok(parsed) = Message::from_bytes(buf.get(..n).unwrap_or(&[])) {
                    for r in parsed.answers() {
                        records.push(r.clone());
                    }
                    for r in parsed.additionals() {
                        records.push(r.clone());
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "probe recv error, dropping packet");
            }
            Err(_) => break,
        }
    }
    Ok(decode(&records))
}

#[allow(
    clippy::cognitive_complexity,
    reason = "match arms enumerate DNS record types; splitting hurts readability"
)]
fn decode_instances(service: &ServiceType, records: &[Record]) -> Vec<Instance> {
    let mut by_name: BTreeMap<Name, Instance> = BTreeMap::new();

    for r in records {
        match r.data() {
            Some(RData::SRV(srv)) => {
                let entry = by_name.entry(r.name().clone()).or_insert_with(|| Instance {
                    service_type: service.clone(),
                    instance_name: leftmost_label(r.name()),
                    host: srv.target().to_string(),
                    port: srv.port(),
                    txt: BTreeMap::new(),
                });
                entry.host = srv.target().to_string();
                entry.port = srv.port();
            }
            Some(RData::TXT(txt)) => {
                let entry = by_name.entry(r.name().clone()).or_insert_with(|| Instance {
                    service_type: service.clone(),
                    instance_name: leftmost_label(r.name()),
                    host: String::new(),
                    port: 0,
                    txt: BTreeMap::new(),
                });
                for kv in txt.iter() {
                    if let Some((k, v)) = split_kv(kv) {
                        entry.txt.insert(k, v);
                    }
                }
            }
            _ => {}
        }
    }

    by_name.into_values().filter(|i| i.port != 0).collect()
}

fn decode_host_answers(host: &str, records: &[Record]) -> Vec<HostAnswer> {
    let mut addrs: Vec<IpAddr> = Vec::new();
    for r in records {
        match r.data() {
            Some(RData::A(A(ip))) => addrs.push(IpAddr::V4(*ip)),
            Some(RData::AAAA(AAAA(ip))) => addrs.push(IpAddr::V6(*ip)),
            _ => {}
        }
    }
    if addrs.is_empty() {
        return Vec::new();
    }
    vec![HostAnswer {
        host: host.to_string(),
        addrs,
    }]
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

#[derive(Debug, Clone, Serialize)]
pub struct HostEnumeration {
    pub host: String,
    pub addrs: Vec<IpAddr>,
    pub services: Vec<HostServiceMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostServiceMatch {
    pub service_type: String,
    pub instance_name: String,
    pub port: u16,
    pub txt: BTreeMap<String, String>,
}

pub async fn enum_host(host: &str, opts: &ProbeOptions) -> Result<HostEnumeration> {
    let transport = Transport::build(Mode::QueryOnly)?;
    let half = opts.timeout / 2;

    // Phase 1: discover service types via meta-query.
    let meta_q = build_query(&parse_name(META_QUERY)?, RecordType::PTR);
    let types: Vec<ServiceType> =
        send_and_collect(&transport, &meta_q, half / 2, decode_service_types).await?;

    let mut unique: Vec<ServiceType> = types;
    unique.sort_by(|a, b| (a.protocol.as_str(), &a.name).cmp(&(b.protocol.as_str(), &b.name)));
    unique.dedup();

    // Phase 2: query PTR for every discovered type in one batch plus A/AAAA for host.
    let mut q_msg = Message::new();
    q_msg
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    for st in &unique {
        let n = parse_name(&st.fqdn())?;
        let mut q = Query::query(n, RecordType::PTR);
        q.set_query_class(DNSClass::IN);
        q_msg.add_query(q);
    }
    let host_name = parse_name(host)?;
    {
        let mut q = Query::query(host_name.clone(), RecordType::A);
        q.set_query_class(DNSClass::IN);
        q_msg.add_query(q);
        let mut q = Query::query(host_name, RecordType::AAAA);
        q.set_query_class(DNSClass::IN);
        q_msg.add_query(q);
    }

    let remaining = opts.timeout.saturating_sub(half / 2);
    let records: Vec<Record> =
        send_and_collect(&transport, &q_msg, remaining, <[Record]>::to_vec).await?;

    let host_norm = strip_trailing_dot(host).to_ascii_lowercase();

    let mut addrs: Vec<IpAddr> = Vec::new();
    // owner -> (port, ServiceType)
    let mut srv_owners: BTreeMap<String, (u16, ServiceType)> = BTreeMap::new();
    let mut txt_by_owner: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for r in &records {
        match r.data() {
            Some(RData::A(A(ip)))
                if matches_host(&r.name().to_string(), &host_norm) =>
            {
                addrs.push(IpAddr::V4(*ip));
            }
            Some(RData::AAAA(AAAA(ip)))
                if matches_host(&r.name().to_string(), &host_norm) =>
            {
                addrs.push(IpAddr::V6(*ip));
            }
            Some(RData::SRV(srv)) => {
                let target = srv.target().to_string();
                if matches_host(&target, &host_norm) {
                    let owner = r.name().to_string();
                    let svc = parse_service_type_from_name(&owner)
                        .unwrap_or_else(|| ServiceType::new("_unknown", Protocol::Tcp));
                    srv_owners.insert(owner, (srv.port(), svc));
                }
            }
            Some(RData::TXT(txt)) => {
                let owner = r.name().to_string();
                let mut map: BTreeMap<String, String> = BTreeMap::new();
                for kv in txt.iter() {
                    if let Some((k, v)) = split_kv_string(kv) {
                        map.insert(k, v);
                    }
                }
                txt_by_owner.entry(owner).or_default().extend(map);
            }
            _ => {}
        }
    }

    let mut services: Vec<HostServiceMatch> = srv_owners
        .into_iter()
        .map(|(owner, (port, svc))| {
            let instance_name = leftmost_label_string(&owner);
            let txt = txt_by_owner.get(&owner).cloned().unwrap_or_default();
            HostServiceMatch {
                service_type: svc.fqdn(),
                instance_name,
                port,
                txt,
            }
        })
        .collect();
    services.sort_by(|a, b| a.service_type.cmp(&b.service_type));

    addrs.sort();
    addrs.dedup();

    Ok(HostEnumeration {
        host: host.to_string(),
        addrs,
        services,
    })
}

fn matches_host(rec_name: &str, host_norm: &str) -> bool {
    strip_trailing_dot(rec_name).to_ascii_lowercase() == host_norm
}

fn strip_trailing_dot(s: &str) -> &str {
    s.trim_end_matches('.')
}

fn split_kv_string(raw: &[u8]) -> Option<(String, String)> {
    let eq = raw.iter().position(|b| *b == b'=')?;
    let (k, rest) = raw.split_at(eq);
    let key = std::str::from_utf8(k).ok()?.to_string();
    let value_bytes = rest.get(1..)?;
    let value = std::str::from_utf8(value_bytes).map_or_else(
        |_| {
            let mut s = String::with_capacity(value_bytes.len() * 2 + 2);
            s.push_str("0x");
            for b in value_bytes {
                // SAFETY: write! on String is infallible
                let _r = std::fmt::Write::write_fmt(
                    &mut s,
                    format_args!("{b:02x}"),
                );
            }
            s
        },
        String::from,
    );
    Some((key, value))
}

fn leftmost_label_string(name: &str) -> String {
    name.split('.').next().unwrap_or(name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_accepts_local_fqdn() {
        let n = parse_name("_airplay._tcp.local.").expect("parse");
        assert_eq!(n.to_string(), "_airplay._tcp.local.");
    }

    #[test]
    fn parse_name_rejects_garbage() {
        assert!(parse_name("\0\0\0").is_err());
    }

    #[test]
    fn build_query_sets_correct_fields() {
        let n = parse_name("_airplay._tcp.local.").expect("parse");
        let m = build_query(&n, RecordType::PTR);
        assert_eq!(m.message_type(), MessageType::Query);
        assert_eq!(m.queries().len(), 1);
    }

    #[test]
    fn split_kv_parses_string_value() {
        let (k, v) = split_kv(b"model=AppleTV11,1").expect("split");
        assert_eq!(k, "model");
        assert_eq!(v.as_ref(), b"AppleTV11,1");
    }

    #[test]
    fn split_kv_returns_none_on_no_equals() {
        assert!(split_kv(b"flag").is_none());
    }

    #[test]
    fn split_kv_string_parses_utf8_value() {
        let (k, v) = split_kv_string(b"model=AppleTV11,1").expect("split");
        assert_eq!(k, "model");
        assert_eq!(v, "AppleTV11,1");
    }

    #[test]
    fn split_kv_string_returns_none_on_no_equals() {
        assert!(split_kv_string(b"flag").is_none());
    }

    #[test]
    fn split_kv_string_hex_fallback_for_binary_value() {
        let (k, v) = split_kv_string(b"flags=\xff\x00").expect("split");
        assert_eq!(k, "flags");
        assert_eq!(v, "0xff00");
    }

    #[test]
    fn leftmost_label_string_returns_first_label() {
        assert_eq!(
            leftmost_label_string("Brother HL-L2350DW._ipp._tcp.local."),
            "Brother HL-L2350DW"
        );
    }

    #[test]
    fn matches_host_strips_dot_and_lowercases() {
        assert!(matches_host("BedroomTV.local.", "bedroomtv.local"));
        assert!(!matches_host("OtherHost.local.", "bedroomtv.local"));
    }

    #[test]
    fn strip_trailing_dot_removes_trailing_dot() {
        assert_eq!(strip_trailing_dot("foo.local."), "foo.local");
        assert_eq!(strip_trailing_dot("foo.local"), "foo.local");
    }
}
