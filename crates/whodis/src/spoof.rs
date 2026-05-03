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
        Self { entries: Vec::new(), ttl: DEFAULT_TTL }
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
        let rec_name = Name::from_utf8(&name_str)
            .map_err(|_| Error::InvalidServiceType(name_str.clone()))?;
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
        Ok(self)
    }

    #[must_use]
    pub fn build(self) -> AnswerTable {
        let mut map: HashMap<(String, RecordType), Vec<u8>> = HashMap::new();
        for e in self.entries {
            let mut msg = Message::new();
            msg.set_message_type(MessageType::Response)
                .set_authoritative(true)
                .set_response_code(ResponseCode::NoError);
            for r in &e.records {
                msg.add_answer(r.clone());
            }
            if let Ok(bytes) = msg.to_bytes() {
                map.insert((normalize(&e.name), e.qtype), bytes);
            }
        }
        AnswerTable { map }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AnswerTable {
    map: HashMap<(String, RecordType), Vec<u8>>,
}

impl AnswerTable {
    #[must_use]
    pub fn lookup(&self, name: &str, qtype: RecordType) -> Option<&[u8]> {
        self.map.get(&(normalize(name), qtype)).map(Vec::as_slice)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
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
    pub fn new(
        mode: Mode,
        auth: Authorization,
        table: AnswerTable,
        burst: u8,
    ) -> Result<Self> {
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
            if !self.auth.permits_instance(&strip_dot(&name)) {
                continue;
            }
            if let Some(bytes) = self.table.lookup(&name, q.query_type()) {
                for i in 0..self.burst {
                    if let Err(e) = self.transport.send_query(bytes, Destination::Multicast).await {
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

fn strip_dot(s: &str) -> String {
    s.trim_end_matches('.').to_string()
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
}
