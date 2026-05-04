//! One-shot directed mDNS queries.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::error::{Error, Result};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};
use crate::types::{HostAnswer, Instance, ServiceType};

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
}
