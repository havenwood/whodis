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

use crate::error::Result;
use crate::hickory_compat::{MessageExt, RecordExt, SrvExt, TxtExt};
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

pub async fn probe_service(
    service: &ServiceType,
    opts: &ProbeOptions,
    no_dns_sd: bool,
) -> Result<Vec<Instance>> {
    let transport = Transport::build(Mode::Listen)?;
    let qname = parse_name(&service.fqdn())?;
    let msg = build_query(&qname, RecordType::PTR);
    let started = tokio::time::Instant::now();
    let first_window = opts.timeout / 2;
    let first_window = if first_window.is_zero() {
        opts.timeout
    } else {
        first_window
    };
    let mut records = collect_records(&transport, &msg, first_window).await?;
    let targets = decode_ptr_targets(&service.fqdn(), &records);
    if !targets.is_empty() {
        let remaining = opts.timeout.saturating_sub(first_window);
        let second_window = if remaining.is_zero() {
            opts.timeout
        } else {
            remaining
        };
        let followup = build_instance_queries(&targets)?;
        records.extend(collect_records(&transport, &followup, second_window).await?);
    }
    hydrate_host_records(&transport, &mut records, opts.timeout, started).await?;
    let wire_results = decode_instances(service, &records);
    if wire_results.is_empty()
        && !no_dns_sd
        && crate::dns_sd::is_apple_service_type(&service.fqdn())
    {
        let fallback = crate::dns_sd::browse_service(&service.fqdn(), opts.timeout).await;
        match fallback {
            Ok(instances) => {
                let n = instances.len();
                if n > 0 {
                    tracing::info!(
                        source = "dns_sd",
                        count = n,
                        "fallback supplemented wire results"
                    );
                }
                return Ok(instances);
            }
            Err(e) => {
                tracing::debug!(error = %e, "dns_sd fallback failed");
            }
        }
    }
    Ok(wire_results)
}

pub async fn probe_instance(
    instance_name: &str,
    service: &ServiceType,
    opts: &ProbeOptions,
) -> Result<Vec<Instance>> {
    let transport = Transport::build(Mode::Listen)?;
    let fqdn = format!("{}.{}", instance_name, service.fqdn());
    let qname = parse_name(&fqdn)?;
    let mut msg = build_query(&qname, RecordType::SRV);
    let mut txt_q = Query::query(qname, RecordType::TXT);
    txt_q.set_query_class(DNSClass::IN);
    msg.add_query(txt_q);
    let started = tokio::time::Instant::now();
    let first_window = opts.timeout / 2;
    let first_window = if first_window.is_zero() {
        opts.timeout
    } else {
        first_window
    };
    let mut records = collect_records(&transport, &msg, first_window).await?;
    hydrate_host_records(&transport, &mut records, opts.timeout, started).await?;
    Ok(decode_instances(service, &records))
}

pub async fn probe_host(host: &str, opts: &ProbeOptions) -> Result<Vec<HostAnswer>> {
    let transport = Transport::build(Mode::Listen)?;
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

#[derive(Debug, Clone, Serialize)]
pub struct HostSummary {
    pub host: String,
    pub service_count: usize,
}

const META_QUERY: &str = "_services._dns-sd._udp.local.";

/// Run an mDNS DNS-SD meta-query and return one summary per service type seen on the LAN,
/// each tagged with the number of distinct instances it is currently advertising.
///
/// Uses the continuous browser internally because the browser sends single-question
/// queries on a backoff schedule (1s, 2s, 4s, 8s) and tolerates responders that ignore
/// multi-question packets. A one-shot multi-question probe is unreliable in practice.
pub async fn discover_service_types(opts: &ProbeOptions) -> Result<Vec<ServiceTypeSummary>> {
    use tokio_stream::StreamExt;

    let browser = crate::browse::Browser::new(Mode::Listen)?;
    let cancel = browser.cancel_token();
    let stream = browser.run();
    tokio::pin!(stream);

    let mut counts: HashMap<String, HashSet<String>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + opts.timeout;
    while let Some(remaining) = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|d| !d.is_zero())
    {
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(crate::browse::Event::ServiceTypeFound { service_type })) => {
                counts.entry(service_type.fqdn()).or_default();
            }
            Ok(Some(crate::browse::Event::InstanceFound { instance })) => {
                counts
                    .entry(instance.service_type.fqdn())
                    .or_default()
                    .insert(format!(
                        "{}.{}",
                        instance.instance_name,
                        instance.service_type.fqdn()
                    ));
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    cancel.cancel();

    let mut summaries: Vec<ServiceTypeSummary> = counts
        .into_iter()
        .map(|(fqdn, instances)| ServiceTypeSummary {
            fqdn,
            instance_count: instances.len(),
        })
        .collect();
    summaries.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));
    Ok(summaries)
}

/// Aggregate distinct hostnames seen on the LAN.
///
/// Each entry is tagged with the number of distinct service types that host
/// advertises. Mirrors [`discover_service_types`] but keys on the SRV target
/// host rather than the service-type fqdn.
pub async fn discover_hosts(opts: &ProbeOptions) -> Result<Vec<HostSummary>> {
    use tokio_stream::StreamExt;

    let browser = crate::browse::Browser::new(Mode::Listen)?;
    let cancel = browser.cancel_token();
    let stream = browser.run();
    tokio::pin!(stream);

    let mut services_by_host: HashMap<String, HashSet<String>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + opts.timeout;
    while let Some(remaining) = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|d| !d.is_zero())
    {
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(
                crate::browse::Event::InstanceFound { instance }
                | crate::browse::Event::InstanceUpdated { instance },
            )) => {
                let host = strip_trailing_dot(&instance.host).to_string();
                if host.is_empty() {
                    continue;
                }
                services_by_host
                    .entry(host)
                    .or_default()
                    .insert(instance.service_type.fqdn());
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    cancel.cancel();

    let mut summaries: Vec<HostSummary> = services_by_host
        .into_iter()
        .map(|(host, services)| HostSummary {
            host,
            service_count: services.len(),
        })
        .collect();
    summaries.sort_by(|a, b| a.host.cmp(&b.host));
    Ok(summaries)
}

fn decode_service_types(records: &[Record]) -> Vec<ServiceType> {
    let meta_norm = META_QUERY.trim_end_matches('.');
    records
        .iter()
        .filter_map(|r| {
            if r.record_type() != RecordType::PTR {
                return None;
            }
            let owner = r.name().to_string();
            // Case 1: a meta-query response -- owner is `_services._dns-sd._udp.local.`,
            // PTR target points at a service-type fqdn.
            if owner.trim_end_matches('.') == meta_norm {
                return match r.data() {
                    Some(RData::PTR(ptr)) => parse_service_type_from_name(&ptr.0.to_string()),
                    _ => None,
                };
            }
            // Case 2: an ambient service announcement -- owner IS the service-type fqdn,
            // e.g. `_airplay._tcp.local. -> Foo._airplay._tcp.local.`. macOS responders
            // mostly publish via this shape rather than answering the meta-query directly.
            parse_service_type_from_name(&owner)
        })
        .collect()
}

/// Extract `_<svc>._<tcp|udp>` from the trailing labels of an SRV/TXT owner Name.
/// Reads label bytes directly, so an instance name containing `.` or `\` does
/// not confuse the boundary detection.
fn parse_service_type_from_owner(name: &Name) -> Option<ServiceType> {
    let labels: Vec<&[u8]> = name.iter().collect();
    let n = labels.len();
    if n < 4 {
        return None;
    }
    let last = std::str::from_utf8(labels.get(n - 1)?).ok()?;
    if !last.eq_ignore_ascii_case("local") {
        return None;
    }
    let proto = match std::str::from_utf8(labels.get(n - 2)?).ok()? {
        "_tcp" => Protocol::Tcp,
        "_udp" => Protocol::Udp,
        _ => return None,
    };
    let svc = std::str::from_utf8(labels.get(n - 3)?).ok()?.to_string();
    if !svc.starts_with('_') {
        return None;
    }
    Some(ServiceType::new(svc, proto))
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
    crate::name_util::lax_from_str(s)
}

fn build_query(name: &Name, qtype: RecordType) -> Message {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    let mut q = Query::query(name.clone(), qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg
}

fn build_instance_queries(targets: &[String]) -> Result<Message> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    for target in targets {
        let name = parse_name(target)?;
        let mut srv_q = Query::query(name.clone(), RecordType::SRV);
        srv_q.set_query_class(DNSClass::IN);
        msg.add_query(srv_q);
        let mut txt_q = Query::query(name, RecordType::TXT);
        txt_q.set_query_class(DNSClass::IN);
        msg.add_query(txt_q);
    }
    Ok(msg)
}

fn build_host_queries(hosts: &[String]) -> Result<Message> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    for host in hosts {
        let name = parse_name(host)?;
        let mut a_q = Query::query(name.clone(), RecordType::A);
        a_q.set_query_class(DNSClass::IN);
        msg.add_query(a_q);
        let mut aaaa_q = Query::query(name, RecordType::AAAA);
        aaaa_q.set_query_class(DNSClass::IN);
        msg.add_query(aaaa_q);
    }
    Ok(msg)
}

async fn hydrate_host_records(
    transport: &Transport,
    records: &mut Vec<Record>,
    total_timeout: Duration,
    started: tokio::time::Instant,
) -> Result<()> {
    let hosts = hosts_missing_addrs(records);
    if hosts.is_empty() {
        return Ok(());
    }
    let remaining = total_timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Ok(());
    }
    let followup = build_host_queries(&hosts)?;
    records.extend(collect_records(transport, &followup, remaining).await?);
    Ok(())
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
    let records = collect_records(transport, msg, timeout).await?;
    Ok(decode(&records))
}

async fn collect_records(
    transport: &Transport,
    msg: &Message,
    timeout: Duration,
) -> Result<Vec<Record>> {
    let bytes = msg.to_bytes()?;
    transport.send_query(&bytes, Destination::Multicast).await?;
    let mut records: Vec<Record> = Vec::with_capacity(msg.queries().len() * 4);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, transport.recv_packet()).await {
            Ok(Ok(payload)) => {
                if let Ok(parsed) = Message::from_bytes(&payload) {
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
    Ok(records)
}

fn decode_ptr_targets(owner: &str, records: &[Record]) -> Vec<String> {
    let owner_norm = strip_trailing_dot(owner).to_ascii_lowercase();
    let mut targets: Vec<String> = records
        .iter()
        .filter_map(|r| {
            if r.record_type() != RecordType::PTR
                || strip_trailing_dot(&r.name().to_string()).to_ascii_lowercase() != owner_norm
            {
                return None;
            }
            match r.data() {
                Some(RData::PTR(ptr)) => Some(ptr.0.to_string()),
                _ => None,
            }
        })
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

fn hosts_missing_addrs(records: &[Record]) -> Vec<String> {
    let mut hosts = Vec::new();
    for r in records {
        if let Some(RData::SRV(srv)) = r.data() {
            let host = srv.target().to_string();
            if !has_addr_for_host(&host, records) {
                hosts.push(host);
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

fn has_addr_for_host(host: &str, records: &[Record]) -> bool {
    let host_norm = strip_trailing_dot(host).to_ascii_lowercase();
    records.iter().any(|r| {
        matches!(r.data(), Some(RData::A(_) | RData::AAAA(_)))
            && matches_host(&r.name().to_string(), &host_norm)
    })
}

fn decode_host_addr_map(records: &[Record]) -> BTreeMap<String, Vec<IpAddr>> {
    let mut by_host: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    for r in records {
        let addr = match r.data() {
            Some(RData::A(A(ip))) => IpAddr::V4(*ip),
            Some(RData::AAAA(AAAA(ip))) => IpAddr::V6(*ip),
            _ => continue,
        };
        let key = strip_trailing_dot(&r.name().to_string()).to_ascii_lowercase();
        by_host.entry(key).or_default().push(addr);
    }
    for addrs in by_host.values_mut() {
        addrs.sort();
        addrs.dedup();
    }
    by_host
}

#[allow(
    clippy::cognitive_complexity,
    reason = "match arms enumerate DNS record types; splitting hurts readability"
)]
fn decode_instances(service: &ServiceType, records: &[Record]) -> Vec<Instance> {
    let mut by_name: BTreeMap<Name, Instance> = BTreeMap::new();
    let addrs_by_host = decode_host_addr_map(records);

    for r in records {
        match r.data() {
            Some(RData::SRV(srv)) => {
                let host = srv.target().to_string();
                let addrs = addrs_by_host
                    .get(&strip_trailing_dot(&host).to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_default();
                let entry = by_name.entry(r.name().clone()).or_insert_with(|| Instance {
                    service_type: service.clone(),
                    instance_name: leftmost_label(r.name()),
                    host: host.clone(),
                    port: srv.port(),
                    addrs: addrs.clone(),
                    txt: BTreeMap::new(),
                });
                entry.host = host;
                entry.port = srv.port();
                entry.addrs = addrs;
            }
            Some(RData::TXT(txt)) => {
                let entry = by_name.entry(r.name().clone()).or_insert_with(|| Instance {
                    service_type: service.clone(),
                    instance_name: leftmost_label(r.name()),
                    host: String::new(),
                    port: 0,
                    addrs: Vec::new(),
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

    by_name
        .into_values()
        .filter(|i| i.port != 0)
        .map(|mut i| {
            if i.addrs.is_empty()
                && let Some(addrs) =
                    addrs_by_host.get(&strip_trailing_dot(&i.host).to_ascii_lowercase())
            {
                i.addrs.clone_from(addrs);
            }
            i
        })
        .collect()
}

fn decode_host_answers(host: &str, records: &[Record]) -> Vec<HostAnswer> {
    let host_norm = strip_trailing_dot(host).to_ascii_lowercase();
    let mut addrs: Vec<IpAddr> = Vec::with_capacity(2);
    for r in records {
        if !matches_host(&r.name().to_string(), &host_norm) {
            continue;
        }
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
    let transport = Transport::build(Mode::Listen)?;
    let half = opts.timeout / 2;

    // Phase 1: discover service types via meta-query.
    let meta_q = build_query(&parse_name(META_QUERY)?, RecordType::PTR);
    let types: Vec<ServiceType> =
        send_and_collect(&transport, &meta_q, half / 2, decode_service_types).await?;

    let mut unique: Vec<ServiceType> = types;
    unique.sort_by(|a, b| (a.protocol.as_str(), &a.name).cmp(&(b.protocol.as_str(), &b.name)));
    unique.dedup();

    // Phase 2: query PTR for every discovered type in one batch plus A/AAAA for host.
    let mut q_msg = Message::new(0, MessageType::Query, OpCode::Query);
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

    let mut addrs: Vec<IpAddr> = Vec::with_capacity(2);
    let mut srv_owners: BTreeMap<Name, (u16, ServiceType)> = BTreeMap::new();
    let mut txt_by_owner: BTreeMap<Name, BTreeMap<String, String>> = BTreeMap::new();

    for r in &records {
        match r.data() {
            Some(RData::A(A(ip))) if matches_host(&r.name().to_string(), &host_norm) => {
                addrs.push(IpAddr::V4(*ip));
            }
            Some(RData::AAAA(AAAA(ip))) if matches_host(&r.name().to_string(), &host_norm) => {
                addrs.push(IpAddr::V6(*ip));
            }
            Some(RData::SRV(srv)) => {
                let target = srv.target().to_string();
                if matches_host(&target, &host_norm) {
                    let svc = parse_service_type_from_owner(r.name())
                        .unwrap_or_else(|| ServiceType::new("_unknown", Protocol::Tcp));
                    srv_owners.insert(r.name().clone(), (srv.port(), svc));
                }
            }
            Some(RData::TXT(txt)) => {
                let mut map: BTreeMap<String, String> = BTreeMap::new();
                for kv in txt.iter() {
                    if let Some((k, v)) = split_kv_string(kv) {
                        map.insert(k, v);
                    }
                }
                txt_by_owner
                    .entry(r.name().clone())
                    .or_default()
                    .extend(map);
            }
            _ => {}
        }
    }

    let mut services: Vec<HostServiceMatch> = srv_owners
        .into_iter()
        .map(|(owner_name, (port, svc))| {
            let instance_name = leftmost_label(&owner_name);
            let txt = txt_by_owner.get(&owner_name).cloned().unwrap_or_default();
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
                let _r = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
            }
            s
        },
        String::from,
    );
    Some((key, value))
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
    fn build_instance_queries_adds_srv_and_txt_for_each_target() {
        let msg = build_instance_queries(&[
            "Living._airplay._tcp.local.".to_string(),
            "Office._airplay._tcp.local.".to_string(),
        ])
        .expect("queries");
        assert_eq!(msg.queries().len(), 4);
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
    fn parse_service_type_from_owner_extracts_last_two_labels() {
        let name = crate::name_util::lax_from_str("Foo._airplay._tcp.local.").expect("name");
        let svc = parse_service_type_from_owner(&name).expect("service");
        assert_eq!(svc.name, "_airplay");
        assert_eq!(svc.protocol, Protocol::Tcp);
    }

    #[test]
    fn parse_service_type_from_owner_handles_dot_in_instance_label() {
        let labels: Vec<&[u8]> = vec![
            b"v1.0 Speaker".as_slice(),
            b"_airplay".as_slice(),
            b"_tcp".as_slice(),
            b"local".as_slice(),
        ];
        let name = Name::from_labels(labels).expect("name");
        let svc = parse_service_type_from_owner(&name).expect("service");
        assert_eq!(svc.name, "_airplay");
    }

    #[test]
    fn leftmost_label_returns_full_label_with_embedded_dot() {
        let labels: Vec<&[u8]> = vec![
            b"v1.0 Speaker".as_slice(),
            b"_airplay".as_slice(),
            b"_tcp".as_slice(),
            b"local".as_slice(),
        ];
        let name = Name::from_labels(labels).expect("name");
        assert_eq!(leftmost_label(&name), "v1.0 Speaker");
    }

    #[test]
    fn leftmost_label_decodes_unicode_label_bytes() {
        let labels: Vec<&[u8]> = vec![
            "Shannon\u{2019}s MacBook Pro".as_bytes(),
            b"_airplay".as_slice(),
            b"_tcp".as_slice(),
            b"local".as_slice(),
        ];
        let name = Name::from_labels(labels).expect("name");
        assert_eq!(leftmost_label(&name), "Shannon\u{2019}s MacBook Pro");
    }

    #[test]
    fn instance_fqdn_escapes_dot_in_instance_name() {
        let inst = crate::types::Instance {
            service_type: crate::types::ServiceType::new("_airplay", Protocol::Tcp),
            instance_name: "v1.0 Speaker".into(),
            host: "host.local.".into(),
            port: 7000,
            addrs: Vec::new(),
            txt: BTreeMap::new(),
        };
        assert_eq!(inst.fqdn(), "v1\\.0 Speaker._airplay._tcp.local.");
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

    #[test]
    fn decode_host_answers_filters_to_queried_host() {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{DNSClass, Name, RData, Record};

        let our_host = Name::from_utf8("BedroomTV.local.").expect("name");
        let other_host = Name::from_utf8("Living.local.").expect("name");

        let mut ours = Record::from_rdata(
            our_host,
            60,
            RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, 5))),
        );
        ours.set_dns_class(DNSClass::IN);
        let mut theirs = Record::from_rdata(
            other_host,
            60,
            RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, 99))),
        );
        theirs.set_dns_class(DNSClass::IN);

        let answers = decode_host_answers("BedroomTV.local.", &[ours, theirs]);
        assert_eq!(answers.len(), 1);
        let answer = answers.first().expect("one answer");
        assert_eq!(answer.host, "BedroomTV.local.");
        assert_eq!(
            answer.addrs,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5))]
        );
    }

    #[test]
    fn decode_instances_attaches_host_addresses() {
        use hickory_proto::rr::rdata::{A, SRV};
        use hickory_proto::rr::{DNSClass, Name, RData, Record};

        let instance = Name::from_utf8("Living._airplay._tcp.local.").expect("instance");
        let host = Name::from_utf8("Living.local.").expect("host");
        let mut srv =
            Record::from_rdata(instance, 60, RData::SRV(SRV::new(0, 0, 7000, host.clone())));
        srv.set_dns_class(DNSClass::IN);
        let mut a = Record::from_rdata(host, 60, RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, 7))));
        a.set_dns_class(DNSClass::IN);

        let service = ServiceType::new("_airplay", Protocol::Tcp);
        let instances = decode_instances(&service, &[srv, a]);
        assert_eq!(instances.len(), 1);
        let instance = instances.first().expect("instance");
        assert_eq!(
            instance.addrs,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7))]
        );
    }
}
