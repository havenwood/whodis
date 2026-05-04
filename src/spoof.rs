//! Authoritative mDNS responder for spoofing answers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio_util::sync::CancellationToken;

use crate::auth::Authorization;
use crate::error::{Error, Result};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};

const DEFAULT_TTL: u32 = 120;

#[derive(Debug, Clone)]
pub struct AnswerEntry {
    pub name: String,
    pub qtype: RecordType,
    pub records: Vec<Record>,
}

#[derive(Debug, Default)]
pub struct AnswerTableBuilder {
    entries: Vec<AnswerEntry>,
    ttl: u32,
}

impl AnswerTableBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            ttl: DEFAULT_TTL,
        }
    }

    #[must_use]
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn answer(
        mut self,
        name: impl Into<String>,
        qtype: RecordType,
        rdata: RData,
    ) -> Result<Self> {
        let name_str = name.into();
        let rec_name = crate::name_util::lax_from_str(&name_str)?;
        self.push_entry(name_str, rec_name, qtype, rdata);
        Ok(self)
    }

    /// Like [`answer`] but accepts a pre-built [`Name`] for labels that contain characters
    /// rejected by the STD3 validator (e.g. `@` in RAOP instance names).
    pub fn answer_name(mut self, rec_name: Name, qtype: RecordType, rdata: RData) -> Result<Self> {
        let name_str = rec_name.to_string();
        self.push_entry(name_str, rec_name, qtype, rdata);
        Ok(self)
    }

    fn push_entry(&mut self, name_str: String, rec_name: Name, qtype: RecordType, rdata: RData) {
        let mut rec = Record::from_rdata(rec_name, self.ttl, rdata);
        rec.set_dns_class(DNSClass::IN);
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.name == name_str && e.qtype == qtype)
        {
            existing.records.push(rec);
        } else {
            self.entries.push(AnswerEntry {
                name: name_str,
                qtype,
                records: vec![rec],
            });
        }
    }

    #[must_use]
    pub fn build(self) -> AnswerTable {
        let entries = self.entries;
        // Reverse-lookup map for chasing additionals (PTR -> SRV/TXT, SRV -> A/AAAA).
        let mut by_key: HashMap<(String, RecordType), Vec<Record>> =
            HashMap::with_capacity(entries.len());
        for e in &entries {
            by_key
                .entry((normalize(&e.name), e.qtype))
                .or_default()
                .extend(e.records.iter().cloned());
        }

        let mut srv_target_to_instances: HashMap<String, Vec<String>> =
            HashMap::with_capacity(entries.len());
        for e in &entries {
            if e.qtype != RecordType::SRV {
                continue;
            }
            for r in &e.records {
                if let Some(RData::SRV(srv)) = r.data() {
                    srv_target_to_instances
                        .entry(normalize(&srv.target().to_string()))
                        .or_default()
                        .push(r.name().to_string());
                }
            }
        }

        let mut map: HashMap<(String, RecordType), ResponseEntry> =
            HashMap::with_capacity(entries.len());
        for e in &entries {
            let mut msg = Message::new();
            msg.set_message_type(MessageType::Response)
                .set_authoritative(true)
                .set_response_code(ResponseCode::NoError);
            for r in &e.records {
                msg.add_answer(r.clone());
            }
            attach_additionals(&mut msg, &e.records, e.qtype, &by_key);
            if let Ok(bytes) = msg.to_bytes() {
                let auth_names = auth_names_for_entry(e, &srv_target_to_instances);
                map.insert(
                    (normalize(&e.name), e.qtype),
                    ResponseEntry { bytes, auth_names },
                );
            }
        }

        let mut srv_ports: Vec<u16> = Vec::with_capacity(entries.len());
        for e in &entries {
            if e.qtype == RecordType::SRV {
                for r in &e.records {
                    if let Some(RData::SRV(srv)) = r.data() {
                        srv_ports.push(srv.port());
                    }
                }
            }
        }
        srv_ports.sort_unstable();
        srv_ports.dedup();

        AnswerTable { map, srv_ports }
    }
}

fn auth_names_for_entry(
    entry: &AnswerEntry,
    srv_target_to_instances: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut names = Vec::with_capacity(entry.records.len() * 3 + 1);
    names.push(entry.name.clone());
    for r in &entry.records {
        names.push(r.name().to_string());
        match r.data() {
            Some(RData::PTR(ptr)) => names.push(ptr.0.to_string()),
            Some(RData::SRV(srv)) => names.push(srv.target().to_string()),
            _ => {}
        }
        if matches!(entry.qtype, RecordType::A | RecordType::AAAA)
            && let Some(instances) = srv_target_to_instances.get(&normalize(&r.name().to_string()))
        {
            names.extend(instances.iter().cloned());
        }
    }
    names.sort_by_key(|name| normalize(name));
    names.dedup_by(|a, b| normalize(a) == normalize(b));
    names
}

fn attach_additionals(
    msg: &mut Message,
    answers: &[Record],
    qtype: RecordType,
    by_key: &HashMap<(String, RecordType), Vec<Record>>,
) {
    let mut hosts_to_resolve: Vec<String> = Vec::with_capacity(answers.len());
    match qtype {
        RecordType::PTR => {
            for r in answers {
                let Some(RData::PTR(ptr)) = r.data() else {
                    continue;
                };
                let target = ptr.0.to_string();
                push_records(msg, by_key, &target, RecordType::SRV);
                push_records(msg, by_key, &target, RecordType::TXT);
                if let Some(srv_records) = by_key.get(&(normalize(&target), RecordType::SRV)) {
                    for sr in srv_records {
                        if let Some(RData::SRV(srv)) = sr.data() {
                            hosts_to_resolve.push(srv.target().to_string());
                        }
                    }
                }
            }
        }
        RecordType::SRV => {
            for r in answers {
                if let Some(RData::SRV(srv)) = r.data() {
                    hosts_to_resolve.push(srv.target().to_string());
                }
            }
        }
        _ => {}
    }
    for host in hosts_to_resolve {
        push_records(msg, by_key, &host, RecordType::A);
        push_records(msg, by_key, &host, RecordType::AAAA);
    }
}

fn push_records(
    msg: &mut Message,
    by_key: &HashMap<(String, RecordType), Vec<Record>>,
    name: &str,
    qtype: RecordType,
) {
    if let Some(records) = by_key.get(&(normalize(name), qtype)) {
        for r in records {
            msg.add_additional(r.clone());
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AnswerTable {
    map: HashMap<(String, RecordType), ResponseEntry>,
    srv_ports: Vec<u16>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResponseEntry {
    pub(crate) bytes: Vec<u8>,
    pub(crate) auth_names: Vec<String>,
}

impl AnswerTable {
    #[must_use]
    pub fn lookup(&self, name: &str, qtype: RecordType) -> Option<&[u8]> {
        self.lookup_response(name, qtype)
            .map(|response| response.bytes.as_slice())
    }

    #[must_use]
    pub(crate) fn lookup_response(&self, name: &str, qtype: RecordType) -> Option<&ResponseEntry> {
        self.map.get(&(normalize(name), qtype))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[must_use]
    pub fn srv_ports(&self) -> &[u16] {
        &self.srv_ports
    }
}

fn normalize(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

pub struct Responder {
    transport: Arc<Transport>,
    auth: Authorization,
    table: Arc<AnswerTable>,
    burst: u8,
    cancel: CancellationToken,
}

impl Responder {
    pub fn new(mode: Mode, auth: Authorization, table: AnswerTable, burst: u8) -> Result<Self> {
        if !mode.sends_responses() {
            return Err(Error::InvalidServiceType(format!(
                "Responder requires Authoritative or Custom mode, got {mode:?}"
            )));
        }
        let transport = Arc::new(Transport::build(mode)?);
        auth.warn_once_if_permissive("spoof");
        Ok(Self {
            transport,
            auth,
            table: Arc::new(table),
            burst: burst.max(1),
            cancel: CancellationToken::new(),
        })
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
                            let payload = buf.get(..n).unwrap_or(&[]);
                            self.handle_query(payload, src).await;
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!(error = %e, "spoof rx error, continuing"),
                    }
                }
            }
        }
    }

    async fn handle_query(&self, payload: &[u8], src: std::net::SocketAddr) {
        let msg = match Message::from_bytes(payload) {
            Ok(m) if m.message_type() == MessageType::Query => m,
            _ => return,
        };
        if !self.auth.permits_addr(src.ip()) {
            tracing::debug!(%src, "blocked by allow-list");
            return;
        }
        for q in msg.queries() {
            let name = q.name().to_string();
            if let Some(response) = self.table.lookup_response(&name, q.query_type()) {
                if !response
                    .auth_names
                    .iter()
                    .any(|candidate| self.auth.permits_instance(candidate))
                {
                    continue;
                }
                for i in 0..self.burst {
                    if let Err(e) = self
                        .transport
                        .send_query(&response.bytes, Destination::Multicast)
                        .await
                    {
                        tracing::debug!(error = %e, "send failed");
                    }
                    if i + 1 < self.burst {
                        tokio::time::sleep(Duration::from_micros(500)).await;
                    }
                }
                tracing::info!(query = %name, qtype = ?q.query_type(), %src, "spoofed");
            }
        }
    }
}

async fn recv_one(
    v4: Option<&Arc<tokio::net::UdpSocket>>,
    v6: Option<&Arc<tokio::net::UdpSocket>>,
    buf: &mut [u8],
) -> std::io::Result<Option<(usize, std::net::SocketAddr)>> {
    match (v4, v6) {
        (Some(s4), Some(s6)) => {
            let mut b6 = vec![0u8; buf.len()];
            tokio::select! {
                r = s4.recv_from(buf) => r.map(|(n, a)| Some((n, a))),
                r = s6.recv_from(&mut b6) => {
                    match r {
                        Ok((n, a)) => {
                            if let (Some(dst), Some(src)) = (buf.get_mut(..n), b6.get(..n)) {
                                dst.copy_from_slice(src);
                            }
                            Ok(Some((n, a)))
                        }
                        Err(e) => Err(e),
                    }
                },
            }
        }
        (Some(s4), None) => s4.recv_from(buf).await.map(|(n, a)| Some((n, a))),
        (None, Some(s6)) => s6.recv_from(buf).await.map(|(n, a)| Some((n, a))),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::rdata::A;

    use super::*;

    #[test]
    fn empty_table_returns_no_match() {
        let t = AnswerTableBuilder::new().build();
        assert!(t.is_empty());
        assert!(t.lookup("anything.local.", RecordType::A).is_none());
    }

    #[test]
    fn answer_table_lookup_finds_entry() {
        let t = AnswerTableBuilder::new()
            .ttl(60)
            .answer(
                "spoofed.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(192, 168, 1, 42))),
            )
            .expect("answer")
            .build();
        let bytes = t.lookup("spoofed.local.", RecordType::A).expect("lookup");
        assert!(bytes.len() > 12);
    }

    #[test]
    fn answer_table_lookup_is_case_insensitive() {
        let t = AnswerTableBuilder::new()
            .answer(
                "Spoofed.Local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
            )
            .expect("answer")
            .build();
        assert!(t.lookup("spoofed.local.", RecordType::A).is_some());
        assert!(t.lookup("SPOOFED.LOCAL", RecordType::A).is_some());
    }

    #[test]
    fn ptr_response_authorizes_against_target_instance() {
        let instance = "LivingRoom._airplay._tcp.local.";
        let t = AnswerTableBuilder::new()
            .answer(
                "_airplay._tcp.local.",
                RecordType::PTR,
                RData::PTR(hickory_proto::rr::rdata::PTR(
                    Name::from_utf8(instance).expect("name"),
                )),
            )
            .expect("answer")
            .build();
        let response = t
            .lookup_response("_airplay._tcp.local.", RecordType::PTR)
            .expect("response");
        let auth = Authorization::new().allow_instance("LivingRoom");
        assert!(
            response
                .auth_names
                .iter()
                .any(|candidate| auth.permits_instance(candidate))
        );
    }
}
