//! LLMNR (RFC 4795) wire layer.
//!
//! LLMNR is essentially DNS over UDP/5355 to a link-local multicast
//! group. We reuse hickory-proto for message encoding; the only
//! protocol-level difference for our purposes is the destination
//! group + port and the C bit handling on conflict-aware queries
//! (which we don't send).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::mode::Mode;

pub const LLMNR_PORT: u16 = 5355;
pub const LLMNR_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
pub const LLMNR_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3);

#[must_use]
pub const fn llmnr_mode() -> Mode {
    Mode::Custom {
        group_v4: LLMNR_GROUP_V4,
        group_v6: LLMNR_GROUP_V6,
        port: LLMNR_PORT,
    }
}

#[must_use]
pub fn is_llmnr_dest(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4 == LLMNR_GROUP_V4,
        IpAddr::V6(v6) => v6 == LLMNR_GROUP_V6,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmnrAnswer {
    pub name: String,
    pub addr: IpAddr,
    pub ttl: u32,
}

pub fn encode_query(name: &str, want_v6: bool) -> Result<Vec<u8>> {
    use crate::hickory_compat::MessageExt;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    let dotted = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let qname = Name::from_ascii(&dotted).map_err(|e| Error::NameRes {
        reason: e.to_string(),
    })?;
    let qtype = if want_v6 {
        RecordType::AAAA
    } else {
        RecordType::A
    };

    let mut msg = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    msg.set_recursion_desired(false);
    msg.add_query(Query::query(qname, qtype));

    msg.to_vec().map_err(|e| Error::NameRes {
        reason: e.to_string(),
    })
}

pub fn decode_message(bytes: &[u8]) -> Result<Vec<LlmnrAnswer>> {
    use crate::hickory_compat::{MessageExt, RecordExt};
    use hickory_proto::op::Message;
    use hickory_proto::rr::RData;

    let msg = Message::from_vec(bytes).map_err(|e| Error::NameRes {
        reason: e.to_string(),
    })?;
    let mut out = Vec::new();
    for record in msg.answers() {
        let addr = match record.data() {
            Some(RData::A(a)) => IpAddr::V4(a.0),
            Some(RData::AAAA(aaaa)) => IpAddr::V6(aaaa.0),
            _ => continue,
        };
        out.push(LlmnrAnswer {
            name: record.name().to_ascii(),
            addr,
            ttl: record.ttl(),
        });
    }
    Ok(out)
}

fn rand_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static SEED: AtomicU16 = AtomicU16::new(0x1000);
    SEED.fetch_add(1, Ordering::Relaxed)
}

use crate::auth::Authorization;
use crate::name_res::table::AnswerTable;
use crate::transport::{Destination, Transport};

pub struct Responder {
    transport: Transport,
    table: AnswerTable,
    auth: Authorization,
    wildcard: bool,
}

impl Responder {
    pub fn new(
        mode: crate::mode::Mode,
        table: AnswerTable,
        auth: Authorization,
        wildcard: bool,
    ) -> Result<Self> {
        let transport = Transport::build(mode)?;
        Ok(Self {
            transport,
            table,
            auth,
            wildcard,
        })
    }

    pub async fn run(self, cancel: tokio_util::sync::CancellationToken) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        loop {
            let v4 = self.transport.v4();
            let v6 = self.transport.v6();
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                r = crate::transport::recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                    match r {
                        Err(e) => {
                            tracing::debug!(error = %e, "llmnr responder recv error, continuing");
                        }
                        Ok(None) => return Ok(()),
                        Ok(Some((n, src))) => {
                            if let Some(slice) = buf.get(..n)
                                && let Err(e) = self.handle(slice, src).await
                            {
                                tracing::debug!(error = %e, "llmnr responder handle error, continuing");
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle(&self, bytes: &[u8], src: std::net::SocketAddr) -> Result<()> {
        use hickory_proto::op::{Message, MessageType, ResponseCode};
        use hickory_proto::rr::{RData, Record, RecordType, rdata};
        use hickory_proto::serialize::binary::BinEncodable;

        let q = Message::from_vec(bytes).map_err(|e| Error::NameRes {
            reason: e.to_string(),
        })?;
        if q.metadata.message_type != MessageType::Query {
            return Ok(());
        }
        let Some(query) = q.queries.first() else {
            return Ok(());
        };
        let qname_full = query.name().to_ascii();
        let qname = qname_full.trim_end_matches('.').to_string();

        if !self.wildcard && !self.auth.permits_name(&qname) {
            tracing::debug!(name = %qname, "llmnr query outside allow-list, dropping");
            return Ok(());
        }

        let Some(entry) = self.table.lookup(&qname) else {
            return Ok(());
        };

        let rdata = match (entry.answer, query.query_type()) {
            (std::net::IpAddr::V4(v4), RecordType::A) => RData::A(rdata::A(v4)),
            (std::net::IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA(rdata::AAAA(v6)),
            _ => return Ok(()),
        };

        let mut resp = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
        resp.metadata.response_code = ResponseCode::NoError;
        resp.metadata.authoritative = true;
        resp.queries.push(query.clone());
        resp.answers
            .push(Record::from_rdata(query.name().clone(), entry.ttl, rdata));

        let bytes = resp.to_bytes().map_err(|e| Error::NameRes {
            reason: e.to_string(),
        })?;

        // RFC 4795 §2.4: respond unicast to the query source.
        self.transport
            .send_query(&bytes, Destination::Unicast(src))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llmnr_mode_uses_canonical_group_and_port() {
        let Mode::Custom {
            group_v4,
            group_v6,
            port,
        } = llmnr_mode()
        else {
            unreachable!("llmnr_mode constructs Mode::Custom directly")
        };
        assert_eq!(group_v4, LLMNR_GROUP_V4);
        assert_eq!(group_v6, LLMNR_GROUP_V6);
        assert_eq!(port, LLMNR_PORT);
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use crate::hickory_compat::MessageExt;

    #[test]
    fn encode_query_round_trips_through_hickory() {
        let bytes = encode_query("wpad", false).expect("encode");
        let msg = hickory_proto::op::Message::from_vec(&bytes).expect("parse");
        assert_eq!(msg.queries().len(), 1);
        let q = msg.queries().first().expect("query");
        assert_eq!(q.name().to_ascii(), "wpad.");
        assert_eq!(q.query_type(), hickory_proto::rr::RecordType::A);
    }

    #[test]
    fn encode_query_v6_uses_aaaa() {
        let bytes = encode_query("wpad", true).expect("encode");
        let msg = hickory_proto::op::Message::from_vec(&bytes).expect("parse");
        let q = msg.queries().first().expect("query");
        assert_eq!(q.query_type(), hickory_proto::rr::RecordType::AAAA);
    }

    #[test]
    fn decode_response_extracts_a_records() {
        // Build a synthetic response: query for "wpad", answer 10.0.0.5 TTL 30.
        use crate::hickory_compat::MessageExt;
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};

        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("wpad.").expect("name");
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            30,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 5))),
        ));
        let bytes = msg.to_vec().expect("encode");

        let answers = decode_message(&bytes).expect("decode");
        assert_eq!(answers.len(), 1);
        let a = answers.first().expect("first");
        assert_eq!(a.name, "wpad.");
        assert_eq!(a.ttl, 30);
        assert_eq!(a.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    }
}
