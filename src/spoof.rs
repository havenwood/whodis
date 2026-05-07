//! Authoritative mDNS responder for spoofing answers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio_util::sync::CancellationToken;

use crate::auth::Authorization;
use crate::error::{Error, Result};
use crate::hickory_compat::{MessageExt, RecordExt, SrvExt};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};

const DEFAULT_TTL: u32 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ReplyMode {
    /// Reply via mDNS multicast. This preserves the original whodis behavior.
    Multicast,
    /// Reply directly to the querying source address and port.
    Unicast,
    /// Unicast only when the query sets the mDNS unicast-response bit.
    Auto,
}

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
        let mut conflict_claims: HashSet<ConflictClaim> = HashSet::with_capacity(entries.len());
        for e in &entries {
            for record in &e.records {
                if let Some(claim) = conflict_claim_for_record(record) {
                    conflict_claims.insert(claim);
                }
            }
        }
        for e in &entries {
            let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
            msg.set_message_type(MessageType::Response)
                .set_authoritative(true)
                .set_response_code(ResponseCode::NoError);
            for r in &e.records {
                let mut owned = r.clone();
                owned.set_mdns_cache_flush(true);
                msg.add_answer(owned);
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

        let mut any_entries: HashMap<String, Vec<&AnswerEntry>> =
            HashMap::with_capacity(entries.len());
        for e in &entries {
            any_entries.entry(normalize(&e.name)).or_default().push(e);
        }
        let mut any_map: HashMap<String, ResponseEntry> = HashMap::with_capacity(any_entries.len());
        for (owner, owner_entries) in any_entries {
            let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
            msg.set_message_type(MessageType::Response)
                .set_authoritative(true)
                .set_response_code(ResponseCode::NoError);
            let mut auth_names = Vec::new();
            for e in owner_entries {
                for r in &e.records {
                    let mut owned = r.clone();
                    owned.set_mdns_cache_flush(true);
                    msg.add_answer(owned);
                }
                attach_additionals(&mut msg, &e.records, e.qtype, &by_key);
                auth_names.extend(auth_names_for_entry(e, &srv_target_to_instances));
            }
            auth_names.sort_by_key(|name| normalize(name));
            auth_names.dedup_by(|a, b| normalize(a) == normalize(b));
            if let Ok(bytes) = msg.to_bytes() {
                any_map.insert(owner, ResponseEntry { bytes, auth_names });
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

        AnswerTable {
            map,
            any_map,
            srv_ports,
            conflict_claims,
        }
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
    any_map: HashMap<String, ResponseEntry>,
    srv_ports: Vec<u16>,
    conflict_claims: HashSet<ConflictClaim>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResponseEntry {
    pub(crate) bytes: Vec<u8>,
    pub(crate) auth_names: Vec<String>,
}

impl ResponseEntry {
    fn bytes_for_request_id(&self, request_id: u16) -> Vec<u8> {
        let mut bytes = self.bytes.clone();
        if let Some(header_id) = bytes.get_mut(..2) {
            header_id.copy_from_slice(&request_id.to_be_bytes());
        }
        bytes
    }
}

impl AnswerTable {
    pub(crate) fn iter_responses(&self) -> impl Iterator<Item = &[u8]> {
        self.map.values().map(|response| response.bytes.as_slice())
    }

    #[must_use]
    pub fn lookup(&self, name: &str, qtype: RecordType) -> Option<&[u8]> {
        self.lookup_response(name, qtype)
            .map(|response| response.bytes.as_slice())
    }

    #[must_use]
    pub(crate) fn lookup_response(&self, name: &str, qtype: RecordType) -> Option<&ResponseEntry> {
        if qtype == RecordType::ANY {
            return self.any_map.get(&normalize(name));
        }
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

    #[must_use]
    pub(crate) fn conflicts_with(&self, record: &Record) -> bool {
        let Some(claim) = conflict_claim_for_record(record) else {
            return false;
        };
        match &claim {
            ConflictClaim::Address { owner, qtype, data } => {
                let mut owns_name_type = false;
                for owned in &self.conflict_claims {
                    if let ConflictClaim::Address {
                        owner: owned_owner,
                        qtype: owned_qtype,
                        data: owned_data,
                    } = owned
                        && owned_owner == owner
                        && owned_qtype == qtype
                    {
                        owns_name_type = true;
                        if owned_data == data {
                            return false;
                        }
                    }
                }
                owns_name_type
            }
            ConflictClaim::Ptr { .. } | ConflictClaim::OwnerType { .. } => {
                self.conflict_claims.contains(&claim)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ConflictClaim {
    Ptr {
        owner: String,
        target: String,
    },
    OwnerType {
        owner: String,
        qtype: RecordType,
    },
    Address {
        owner: String,
        qtype: RecordType,
        data: String,
    },
}

fn conflict_claim_for_record(record: &Record) -> Option<ConflictClaim> {
    let owner = normalize(&record.name().to_string());
    match record.data() {
        Some(RData::PTR(ptr)) => Some(ConflictClaim::Ptr {
            owner,
            target: normalize(&ptr.0.to_string()),
        }),
        Some(RData::SRV(_) | RData::TXT(_)) => Some(ConflictClaim::OwnerType {
            owner,
            qtype: record.record_type(),
        }),
        Some(RData::A(addr)) => Some(ConflictClaim::Address {
            owner,
            qtype: record.record_type(),
            data: addr.0.to_string(),
        }),
        Some(RData::AAAA(addr)) => Some(ConflictClaim::Address {
            owner,
            qtype: record.record_type(),
            data: addr.0.to_string(),
        }),
        _ => None,
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
    reply_mode: ReplyMode,
    reannounce_interval: Option<Duration>,
    cancel: CancellationToken,
    event_callback: Option<Arc<dyn Fn(ResponderEvent) + Send + Sync>>,
}

#[derive(Debug, Clone)]
pub enum ResponderEvent {
    QueryAnswered {
        name: String,
        qtype: RecordType,
        src: std::net::SocketAddr,
    },
    Conflict {
        name: String,
        qtype: RecordType,
        src: std::net::SocketAddr,
    },
}

pub struct Monitor {
    transport: Arc<Transport>,
    auth: Authorization,
    table: Arc<AnswerTable>,
    cancel: CancellationToken,
    event_callback: Option<Arc<dyn Fn(MonitorEvent) + Send + Sync>>,
}

#[derive(Debug, Clone)]
pub enum MonitorEvent {
    WouldAnswer {
        name: String,
        qtype: RecordType,
        src: std::net::SocketAddr,
    },
    Blocked {
        name: String,
        qtype: RecordType,
        src: std::net::SocketAddr,
        reason: MonitorBlockReason,
    },
    Conflict {
        name: String,
        qtype: RecordType,
        src: std::net::SocketAddr,
    },
    SharedPtr {
        name: String,
        target: String,
        src: std::net::SocketAddr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorBlockReason {
    SourceAddress,
    Instance,
}

impl Monitor {
    pub fn new(mode: Mode, auth: Authorization, table: AnswerTable) -> Result<Self> {
        if !mode.binds_port() {
            return Err(Error::InvalidServiceType(format!(
                "Monitor requires Listen, Authoritative, or Custom mode, got {mode:?}"
            )));
        }
        let transport = Arc::new(Transport::build(mode)?);
        Ok(Self {
            transport,
            auth,
            table: Arc::new(table),
            cancel: CancellationToken::new(),
            event_callback: None,
        })
    }

    #[must_use]
    pub fn with_event_callback(
        mut self,
        callback: impl Fn(MonitorEvent) + Send + Sync + 'static,
    ) -> Self {
        self.event_callback = Some(Arc::new(callback));
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
                            let payload = buf.get(..n).unwrap_or(&[]);
                            self.handle_packet(payload, src);
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!(error = %e, "spoof monitor rx error, continuing"),
                    }
                }
            }
        }
    }

    fn handle_packet(&self, payload: &[u8], src: std::net::SocketAddr) {
        let Ok(msg) = Message::from_bytes(payload) else {
            return;
        };
        match msg.message_type() {
            MessageType::Query => self.handle_query(&msg, src),
            MessageType::Response => self.handle_response(&msg, src),
        }
    }

    fn handle_query(&self, msg: &Message, src: std::net::SocketAddr) {
        for q in msg.queries() {
            let name = q.name().to_string();
            let qtype = q.query_type();
            let Some(response) = self.table.lookup_response(&name, qtype) else {
                continue;
            };
            if !self.auth.permits_addr(src.ip()) {
                self.emit_event(MonitorEvent::Blocked {
                    name,
                    qtype,
                    src,
                    reason: MonitorBlockReason::SourceAddress,
                });
                continue;
            }
            if !response
                .auth_names
                .iter()
                .any(|candidate| self.auth.permits_instance(candidate))
            {
                self.emit_event(MonitorEvent::Blocked {
                    name,
                    qtype,
                    src,
                    reason: MonitorBlockReason::Instance,
                });
                continue;
            }
            self.emit_event(MonitorEvent::WouldAnswer { name, qtype, src });
        }
    }

    fn handle_response(&self, msg: &Message, src: std::net::SocketAddr) {
        if src.port() != self.transport.mode.port()
            || self.transport.is_local_addr(src.ip())
            || msg.answers().is_empty()
        {
            return;
        }
        for r in msg.answers() {
            let name = r.name().to_string();
            let qtype = r.record_type();
            if self.table.conflicts_with(r) {
                self.emit_event(MonitorEvent::Conflict { name, qtype, src });
            } else if let Some(RData::PTR(ptr)) = r.data()
                && self.table.lookup_response(&name, RecordType::PTR).is_some()
            {
                self.emit_event(MonitorEvent::SharedPtr {
                    name,
                    target: ptr.0.to_string(),
                    src,
                });
            }
        }
    }

    fn emit_event(&self, event: MonitorEvent) {
        if let Some(callback) = &self.event_callback {
            callback(event);
        }
    }

    #[cfg(test)]
    fn test(auth: Authorization, table: AnswerTable) -> Self {
        Self {
            transport: Arc::new(Transport::test()),
            auth,
            table: Arc::new(table),
            cancel: CancellationToken::new(),
            event_callback: None,
        }
    }
}

impl Responder {
    pub fn new(
        mode: Mode,
        auth: Authorization,
        table: AnswerTable,
        burst: u8,
        reply_mode: ReplyMode,
        reannounce_interval: Option<Duration>,
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
            reply_mode,
            reannounce_interval,
            cancel: CancellationToken::new(),
            event_callback: None,
        })
    }

    #[must_use]
    pub fn with_event_callback(
        mut self,
        callback: impl Fn(ResponderEvent) + Send + Sync + 'static,
    ) -> Self {
        self.event_callback = Some(Arc::new(callback));
        self
    }

    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub async fn run(self) -> Result<()> {
        let v4 = self.transport.v4();
        let v6 = self.transport.v6();

        let reannounce_handle = match self.reannounce_interval {
            Some(interval) if !interval.is_zero() => {
                let table = self.table.clone();
                let transport = self.transport.clone();
                let cancel = self.cancel.clone();
                Some(tokio::spawn(async move {
                    run_reannounce(transport, table, interval, cancel).await;
                }))
            }
            _ => None,
        };

        let mut buf = vec![0u8; 9000];
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => {
                    if let Some(h) = reannounce_handle {
                        h.abort();
                        let _joined = h.await;
                    }
                    return Ok(());
                }
                r = recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                    match r {
                        Ok(Some((n, src))) => {
                            let payload = buf.get(..n).unwrap_or(&[]);
                            self.handle_packet(payload, src).await;
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!(error = %e, "spoof rx error, continuing"),
                    }
                }
            }
        }
    }

    async fn handle_packet(&self, payload: &[u8], src: std::net::SocketAddr) {
        let Ok(msg) = Message::from_bytes(payload) else {
            return;
        };
        match msg.message_type() {
            MessageType::Query => self.handle_query(msg, src).await,
            MessageType::Response => self.handle_response(&msg, src),
        }
    }

    async fn handle_query(&self, msg: Message, src: std::net::SocketAddr) {
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
                let dest = response_destination(self.reply_mode, q, src);
                let bytes = match dest {
                    Destination::Unicast(_) => response.bytes_for_request_id(msg.id()),
                    Destination::Multicast => response.bytes.clone(),
                };
                for i in 0..self.burst {
                    if let Err(e) = self.transport.send_query(&bytes, dest).await {
                        tracing::debug!(error = %e, "send failed");
                    }
                    if i + 1 < self.burst {
                        tokio::time::sleep(Duration::from_micros(500)).await;
                    }
                }
                tracing::info!(
                    query = %name,
                    qtype = ?q.query_type(),
                    %src,
                    reply = ?self.reply_mode,
                    "spoofed"
                );
                self.emit_event(ResponderEvent::QueryAnswered {
                    name,
                    qtype: q.query_type(),
                    src,
                });
            }
        }
    }

    fn handle_response(&self, msg: &Message, src: std::net::SocketAddr) {
        if src.port() != self.transport.mode.port() || self.transport.is_local_addr(src.ip()) {
            return;
        }
        if msg.answers().is_empty() {
            return;
        }
        for r in msg.answers() {
            let name = r.name().to_string();
            let qtype = r.record_type();
            if self.table.conflicts_with(r) {
                tracing::warn!(
                    %src,
                    name = %name,
                    qtype = ?qtype,
                    "spoof conflict: another responder claims a name we own"
                );
                self.emit_event(ResponderEvent::Conflict { name, qtype, src });
            }
        }
    }

    fn emit_event(&self, event: ResponderEvent) {
        if let Some(callback) = &self.event_callback {
            callback(event);
        }
    }
}

fn response_destination(mode: ReplyMode, query: &Query, src: std::net::SocketAddr) -> Destination {
    match mode {
        ReplyMode::Unicast => Destination::Unicast(src),
        ReplyMode::Auto if query.mdns_unicast_response() => Destination::Unicast(src),
        ReplyMode::Multicast | ReplyMode::Auto => Destination::Multicast,
    }
}

async fn run_reannounce(
    transport: Arc<Transport>,
    table: Arc<AnswerTable>,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {
                let mut count = 0_usize;
                for bytes in table.iter_responses() {
                    if let Err(e) = transport.send_query(bytes, crate::transport::Destination::Multicast).await {
                        tracing::debug!(error = %e, "reannounce send failed");
                    } else {
                        count += 1;
                    }
                }
                tracing::debug!(announces = count, "reannounce tick");
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
    use std::sync::{Arc, Mutex};

    use std::net::Ipv4Addr;

    use hickory_proto::op::Query;
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
    fn answer_records_have_cache_flush_set() {
        use hickory_proto::rr::rdata::A as ARData;

        let table = AnswerTableBuilder::new()
            .answer(
                "x.local.",
                RecordType::A,
                RData::A(ARData(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        let bytes = table.lookup("x.local.", RecordType::A).expect("lookup");
        let msg = Message::from_bytes(bytes).expect("parse");
        let answer = msg.answers().first().expect("answer");
        assert!(
            answer.mdns_cache_flush,
            "answer record should have cache-flush bit set"
        );
        for additional in msg.additionals() {
            assert!(
                !additional.mdns_cache_flush,
                "additional record should not have cache-flush bit set"
            );
        }
    }

    #[test]
    fn iter_responses_yields_one_per_entry() {
        use hickory_proto::rr::rdata::A as ARData;

        let t = AnswerTableBuilder::new()
            .answer(
                "a.local.",
                RecordType::A,
                RData::A(ARData(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("a")
            .answer(
                "b.local.",
                RecordType::A,
                RData::A(ARData(Ipv4Addr::new(5, 6, 7, 8))),
            )
            .expect("b")
            .build();
        let responses: Vec<_> = t.iter_responses().collect();
        assert_eq!(responses.len(), 2);
        for r in responses {
            assert!(r.len() > 12);
        }
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

    #[test]
    fn lookup_response_detects_owned_name() {
        use hickory_proto::rr::rdata::A as ARData;
        let t = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(ARData(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        assert!(t.lookup_response("our.local.", RecordType::A).is_some());
        assert!(t.lookup_response("OUR.LOCAL", RecordType::A).is_some());
        assert!(
            t.lookup_response("not-ours.local.", RecordType::A)
                .is_none()
        );
    }

    #[test]
    fn any_lookup_returns_all_owned_name_records() {
        let instance = "Demo._ssh._tcp.local.";
        let table = AnswerTableBuilder::new()
            .answer(
                instance,
                RecordType::SRV,
                RData::SRV(hickory_proto::rr::rdata::SRV::new(
                    0,
                    0,
                    22,
                    Name::from_utf8("demo.local.").expect("host"),
                )),
            )
            .expect("srv")
            .answer(
                instance,
                RecordType::TXT,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                    "txtvers=1".to_string(),
                ])),
            )
            .expect("txt")
            .build();

        let bytes = table.lookup(instance, RecordType::ANY).expect("any lookup");
        let msg = Message::from_bytes(bytes).expect("parse any response");
        let answer_types: HashSet<_> = msg.answers().iter().map(Record::record_type).collect();

        assert!(answer_types.contains(&RecordType::SRV));
        assert!(answer_types.contains(&RecordType::TXT));
    }

    #[test]
    fn response_destination_auto_follows_query_unicast_bit() {
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));
        let mut query = Query::query(Name::from_utf8("our.local.").expect("name"), RecordType::A);

        assert_eq!(
            response_destination(ReplyMode::Auto, &query, src),
            Destination::Multicast
        );

        query.set_mdns_unicast_response(true);
        assert_eq!(
            response_destination(ReplyMode::Auto, &query, src),
            Destination::Unicast(src)
        );
    }

    #[test]
    fn explicit_response_destinations_ignore_query_unicast_bit() {
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));
        let mut query = Query::query(Name::from_utf8("our.local.").expect("name"), RecordType::A);
        query.set_mdns_unicast_response(true);

        assert_eq!(
            response_destination(ReplyMode::Multicast, &query, src),
            Destination::Multicast
        );
        assert_eq!(
            response_destination(ReplyMode::Unicast, &query, src),
            Destination::Unicast(src)
        );
    }

    #[test]
    fn unicast_response_bytes_copy_request_id() {
        let response = ResponseEntry {
            bytes: vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            auth_names: Vec::new(),
        };

        let bytes = response.bytes_for_request_id(0x1234);

        assert_eq!(bytes.get(0..2), Some(&[0x12, 0x34][..]));
    }

    #[tokio::test]
    async fn unicast_reply_reaches_querying_socket() {
        let table = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15356,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Unicast,
            None,
        )
        .expect("responder");
        let receiver =
            tokio::net::UdpSocket::bind(std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind receiver");
        let src = receiver.local_addr().expect("receiver addr");

        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_utf8("our.local.").expect("name"),
            RecordType::A,
        ));

        responder.handle_query(query, src).await;

        let mut buf = [0_u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for unicast reply")
            .expect("receive reply");
        let payload = buf.get(..n).expect("reply payload");
        let parsed = Message::from_bytes(payload).expect("parse reply");

        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.answers().len(), 1);
        let answer = parsed.answers().first().expect("answer");
        assert_eq!(answer.name().to_string(), "our.local.");
    }

    #[tokio::test]
    async fn query_answered_emits_event_callback() {
        let table = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        let events: Arc<Mutex<Vec<ResponderEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15355,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Multicast,
            None,
        )
        .expect("responder")
        .with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });

        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_utf8("our.local.").expect("name"),
            RecordType::A,
        ));

        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));
        responder.handle_query(msg, src).await;

        let query_answered = {
            let events = events.lock().expect("events lock");
            matches!(
                events.first(),
                Some(ResponderEvent::QueryAnswered { name, qtype, src: event_src })
                    if name == "our.local." && *qtype == RecordType::A && *event_src == src
            )
        };
        assert!(query_answered);
    }

    #[tokio::test]
    async fn response_conflict_emits_event_callback() {
        let table = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        let events: Arc<Mutex<Vec<ResponderEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15354,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Multicast,
            None,
        )
        .expect("responder")
        .with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });

        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("our.local.").expect("name"),
            60,
            RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
        ));

        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 15354));
        responder.handle_response(&msg, src);

        let conflict_emitted = {
            let events = events.lock().expect("events lock");
            matches!(
                events.first(),
                Some(ResponderEvent::Conflict { name, qtype, src: event_src })
                    if name == "our.local." && *qtype == RecordType::A && *event_src == src
            )
        };
        assert!(conflict_emitted);
    }

    #[tokio::test]
    async fn response_conflict_ignores_wrong_source_port() {
        let table = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        let events: Arc<Mutex<Vec<ResponderEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15354,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Multicast,
            None,
        )
        .expect("responder")
        .with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });

        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("our.local.").expect("name"),
            60,
            RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
        ));

        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));
        responder.handle_response(&msg, src);

        assert!(events.lock().expect("events lock").is_empty());
    }

    #[tokio::test]
    async fn shared_ptr_response_does_not_emit_conflict() {
        let table = AnswerTableBuilder::new()
            .answer(
                "_ssh._tcp.local.",
                RecordType::PTR,
                RData::PTR(hickory_proto::rr::rdata::PTR(
                    Name::from_utf8("our._ssh._tcp.local.").expect("our instance"),
                )),
            )
            .expect("answer")
            .build();
        let events: Arc<Mutex<Vec<ResponderEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15354,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Multicast,
            None,
        )
        .expect("responder")
        .with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });

        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("_ssh._tcp.local.").expect("service type"),
            60,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_utf8("other._ssh._tcp.local.").expect("other instance"),
            )),
        ));

        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 15354));
        responder.handle_response(&msg, src);

        assert!(
            events.lock().expect("events lock").is_empty(),
            "shared service-type PTR records should not be treated as conflicts"
        );
    }

    #[tokio::test]
    async fn matching_ptr_target_emits_conflict() {
        let table = AnswerTableBuilder::new()
            .answer(
                "_ssh._tcp.local.",
                RecordType::PTR,
                RData::PTR(hickory_proto::rr::rdata::PTR(
                    Name::from_utf8("our._ssh._tcp.local.").expect("our instance"),
                )),
            )
            .expect("answer")
            .build();
        let events: Arc<Mutex<Vec<ResponderEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15354,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Multicast,
            None,
        )
        .expect("responder")
        .with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });

        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("_ssh._tcp.local.").expect("service type"),
            60,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_utf8("our._ssh._tcp.local.").expect("our instance"),
            )),
        ));

        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 15354));
        responder.handle_response(&msg, src);

        let conflict_emitted = {
            let events = events.lock().expect("events lock");
            matches!(
                events.first(),
                Some(ResponderEvent::Conflict { name, qtype, src: event_src })
                    if name == "_ssh._tcp.local." && *qtype == RecordType::PTR && *event_src == src
            )
        };
        assert!(conflict_emitted);
    }

    #[tokio::test]
    async fn same_address_response_does_not_emit_conflict() {
        let table = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("answer")
            .build();
        let events: Arc<Mutex<Vec<ResponderEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let responder = Responder::new(
            Mode::Custom {
                group_v4: Ipv4Addr::new(239, 255, 99, 99),
                group_v6: std::net::Ipv6Addr::LOCALHOST,
                port: 15354,
            },
            Authorization::new(),
            table,
            1,
            ReplyMode::Multicast,
            None,
        )
        .expect("responder")
        .with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });

        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("our.local.").expect("name"),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));

        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 15354));
        responder.handle_response(&msg, src);

        assert!(
            events.lock().expect("events lock").is_empty(),
            "same-address duplicate A response should not be treated as a conflict"
        );
    }

    #[test]
    fn multi_address_owner_conflicts_only_on_unknown_address() {
        let table = AnswerTableBuilder::new()
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )
            .expect("first answer")
            .answer(
                "our.local.",
                RecordType::A,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 5))),
            )
            .expect("second answer")
            .build();

        let known = Record::from_rdata(
            Name::from_utf8("our.local.").expect("name"),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        let unknown = Record::from_rdata(
            Name::from_utf8("our.local.").expect("name"),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 6))),
        );

        assert!(!table.conflicts_with(&known));
        assert!(table.conflicts_with(&unknown));
    }

    fn ssh_ptr_table() -> AnswerTable {
        AnswerTableBuilder::new()
            .answer(
                "_ssh._tcp.local.",
                RecordType::PTR,
                RData::PTR(hickory_proto::rr::rdata::PTR(
                    Name::from_utf8("Demo._ssh._tcp.local.").expect("instance"),
                )),
            )
            .expect("answer")
            .build()
    }

    fn monitor_with_events(
        auth: Authorization,
        table: AnswerTable,
    ) -> (Monitor, Arc<Mutex<Vec<MonitorEvent>>>) {
        let events: Arc<Mutex<Vec<MonitorEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        let monitor = Monitor::test(auth, table).with_event_callback(move |event| {
            events_for_callback.lock().expect("events lock").push(event);
        });
        (monitor, events)
    }

    fn query_packet(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_utf8(name).expect("query name"),
            qtype,
        ));
        msg.to_bytes().expect("query bytes")
    }

    fn ptr_query_packet(name: &str) -> Vec<u8> {
        query_packet(name, RecordType::PTR)
    }

    fn first_monitor_event(events: &Arc<Mutex<Vec<MonitorEvent>>>) -> Option<MonitorEvent> {
        events.lock().expect("events lock").first().cloned()
    }

    #[test]
    fn monitor_query_emits_would_answer_without_sending() {
        let (monitor, events) = monitor_with_events(Authorization::new(), ssh_ptr_table());
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));

        monitor.handle_packet(&ptr_query_packet("_ssh._tcp.local."), src);

        assert!(matches!(
            first_monitor_event(&events),
            Some(MonitorEvent::WouldAnswer { name, qtype, src: event_src })
                if name == "_ssh._tcp.local." && qtype == RecordType::PTR && event_src == src
        ));
    }

    #[test]
    fn monitor_any_query_emits_would_answer() {
        let (monitor, events) = monitor_with_events(Authorization::new(), ssh_ptr_table());
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));

        monitor.handle_packet(&query_packet("_ssh._tcp.local.", RecordType::ANY), src);

        assert!(matches!(
            first_monitor_event(&events),
            Some(MonitorEvent::WouldAnswer { name, qtype, src: event_src })
                if name == "_ssh._tcp.local." && qtype == RecordType::ANY && event_src == src
        ));
    }

    #[test]
    fn monitor_query_emits_blocked_for_filtered_source() {
        let auth = Authorization::new().allow_subnet("192.0.2.0/24".parse().expect("subnet"));
        let (monitor, events) = monitor_with_events(auth, ssh_ptr_table());
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));

        monitor.handle_packet(&ptr_query_packet("_ssh._tcp.local."), src);

        assert!(matches!(
            first_monitor_event(&events),
            Some(MonitorEvent::Blocked {
                name,
                qtype,
                src: event_src,
                reason: MonitorBlockReason::SourceAddress,
            }) if name == "_ssh._tcp.local." && qtype == RecordType::PTR && event_src == src
        ));
    }

    #[test]
    fn monitor_query_emits_blocked_for_filtered_instance() {
        let auth = Authorization::new().allow_instance("Other");
        let (monitor, events) = monitor_with_events(auth, ssh_ptr_table());
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));

        monitor.handle_packet(&ptr_query_packet("_ssh._tcp.local."), src);

        assert!(matches!(
            first_monitor_event(&events),
            Some(MonitorEvent::Blocked {
                name,
                qtype,
                src: event_src,
                reason: MonitorBlockReason::Instance,
            }) if name == "_ssh._tcp.local." && qtype == RecordType::PTR && event_src == src
        ));
    }

    #[test]
    fn monitor_response_emits_shared_ptr_for_other_target() {
        let (monitor, events) = monitor_with_events(Authorization::new(), ssh_ptr_table());
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("_ssh._tcp.local.").expect("service type"),
            60,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_utf8("Other._ssh._tcp.local.").expect("other instance"),
            )),
        ));
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));

        monitor.handle_packet(&msg.to_bytes().expect("response bytes"), src);

        assert!(matches!(
            first_monitor_event(&events),
            Some(MonitorEvent::SharedPtr { name, target, src: event_src })
                if name == "_ssh._tcp.local."
                    && target == "other._ssh._tcp.local."
                    && event_src == src
        ));
    }

    #[test]
    fn monitor_response_emits_conflict_for_owned_ptr_target() {
        let (monitor, events) = monitor_with_events(Authorization::new(), ssh_ptr_table());
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("_ssh._tcp.local.").expect("service type"),
            60,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_utf8("Demo._ssh._tcp.local.").expect("our instance"),
            )),
        ));
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 5353));

        monitor.handle_packet(&msg.to_bytes().expect("response bytes"), src);

        assert!(matches!(
            first_monitor_event(&events),
            Some(MonitorEvent::Conflict { name, qtype, src: event_src })
                if name == "_ssh._tcp.local." && qtype == RecordType::PTR && event_src == src
        ));
    }

    #[test]
    fn monitor_response_ignores_wrong_source_port() {
        let (monitor, events) = monitor_with_events(Authorization::new(), ssh_ptr_table());
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        msg.add_answer(Record::from_rdata(
            Name::from_utf8("_ssh._tcp.local.").expect("service type"),
            60,
            RData::PTR(hickory_proto::rr::rdata::PTR(
                Name::from_utf8("Demo._ssh._tcp.local.").expect("our instance"),
            )),
        ));
        let src = std::net::SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 12345));

        monitor.handle_packet(&msg.to_bytes().expect("response bytes"), src);

        assert!(first_monitor_event(&events).is_none());
    }
}
