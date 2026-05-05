//! Capture a live mDNS instance and emit a TOML answer table mimicking it.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::error::{Error, Result};
use crate::hickory_compat::{MessageExt, RecordExt, SrvExt, TxtExt};
use crate::mode::Mode;
use crate::transport::{Destination, Transport};

#[derive(Debug, Clone, Default)]
pub struct ClonedInstance {
    pub(crate) instance_fqdn: String,
    pub(crate) service_fqdn: String,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) txt: Vec<String>,
    pub(crate) addrs_v4: Vec<Ipv4Addr>,
    pub(crate) addrs_v6: Vec<Ipv6Addr>,
    pub(crate) ttl: u32,
}

impl ClonedInstance {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.host.is_none()
            && self.port.is_none()
            && self.txt.is_empty()
            && self.addrs_v4.is_empty()
            && self.addrs_v6.is_empty()
    }

    /// Format as a TOML answer table compatible with `whodis spoof <FILE>`.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut s = String::new();
        // Using _r to satisfy `unused` lint; writeln! into a String is infallible.
        let _r = writeln!(s, "# Cloned from {}", self.instance_fqdn);
        let _r = writeln!(s, "# Replay with: whodis spoof <this-file> --allow ...");
        let _r = writeln!(s);
        let _r = writeln!(s, "ttl = {}", if self.ttl == 0 { 4500 } else { self.ttl });
        let _r = writeln!(s);

        // PTR: service_type -> instance_fqdn
        let _r = writeln!(s, "[[answer]]");
        let _r = writeln!(s, "name = {}", toml_quote(&self.service_fqdn));
        let _r = writeln!(s, "qtype = \"PTR\"");
        let _r = writeln!(s, "data = {}", toml_quote(&self.instance_fqdn));
        let _r = writeln!(s);

        // SRV: instance_fqdn -> host:port
        if let (Some(host), Some(port)) = (self.host.as_deref(), self.port) {
            let _r = writeln!(s, "[[answer]]");
            let _r = writeln!(s, "name = {}", toml_quote(&self.instance_fqdn));
            let _r = writeln!(s, "qtype = \"SRV\"");
            let _r = writeln!(s, "port = {port}");
            let _r = writeln!(s, "target = {}", toml_quote(host));
            if self.priority != 0 {
                let _r = writeln!(s, "priority = {}", self.priority);
            }
            if self.weight != 0 {
                let _r = writeln!(s, "weight = {}", self.weight);
            }
            let _r = writeln!(s);
        }

        // TXT: instance_fqdn -> records
        if !self.txt.is_empty() {
            let _r = writeln!(s, "[[answer]]");
            let _r = writeln!(s, "name = {}", toml_quote(&self.instance_fqdn));
            let _r = writeln!(s, "qtype = \"TXT\"");
            let mut quoted_txt = Vec::with_capacity(self.txt.len());
            for t in &self.txt {
                quoted_txt.push(toml_quote(t));
            }
            let parts = quoted_txt.join(", ");
            let _r = writeln!(s, "txt = [{parts}]");
            let _r = writeln!(s);
        }

        // A / AAAA: host -> ips
        if let Some(host) = self.host.as_deref() {
            for ip in &self.addrs_v4 {
                let _r = writeln!(s, "[[answer]]");
                let _r = writeln!(s, "name = {}", toml_quote(host));
                let _r = writeln!(s, "qtype = \"A\"");
                let _r = writeln!(s, "data = \"{ip}\"");
                let _r = writeln!(s);
            }
            for ip in &self.addrs_v6 {
                let _r = writeln!(s, "[[answer]]");
                let _r = writeln!(s, "name = {}", toml_quote(host));
                let _r = writeln!(s, "qtype = \"AAAA\"");
                let _r = writeln!(s, "data = \"{ip}\"");
                let _r = writeln!(s);
            }
        }
        s
    }
}

fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _r = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub async fn clone_instance(instance_fqdn: &str, timeout: Duration) -> Result<ClonedInstance> {
    let parsed = parse_instance(instance_fqdn)?;
    // Listen mode binds 5353 with SO_REUSEPORT so we receive both multicast responses from the
    // mDNS group and unicast responses the target sends back to port 5353.
    let transport = Transport::build(Mode::Listen)?;

    // Phase 1: send PTR for service + SRV/TXT for the specific instance.
    let mut q1 = Message::new(0, MessageType::Query, OpCode::Query);
    q1.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    push_query(&mut q1, &parsed.service_fqdn, RecordType::PTR)?;
    push_query(&mut q1, instance_fqdn, RecordType::SRV)?;
    push_query(&mut q1, instance_fqdn, RecordType::TXT)?;

    let half = timeout / 2;
    let phase1 = collect_records(&transport, &q1, half).await?;

    // Build partial ClonedInstance from phase 1.
    let mut out = ClonedInstance {
        instance_fqdn: instance_fqdn.trim_end_matches('.').to_string() + ".",
        service_fqdn: parsed.service_fqdn.trim_end_matches('.').to_string() + ".",
        ..Default::default()
    };
    for r in &phase1 {
        absorb_record(&mut out, r, instance_fqdn);
    }

    // Phase 2: if we learned a host from SRV, query A/AAAA for it.
    if let Some(host) = out.host.clone() {
        let mut q2 = Message::new(0, MessageType::Query, OpCode::Query);
        q2.set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(false);
        push_query(&mut q2, &host, RecordType::A)?;
        push_query(&mut q2, &host, RecordType::AAAA)?;
        let phase2 = collect_records(&transport, &q2, half).await?;
        for r in phase2 {
            absorb_record(&mut out, &r, instance_fqdn);
        }
    }

    if out.is_empty() {
        return Err(Error::NoRecords {
            target: instance_fqdn.to_string(),
            timeout,
        });
    }
    Ok(out)
}

struct Parsed {
    service_fqdn: String,
}

fn parse_instance(fqdn: &str) -> Result<Parsed> {
    // For "Living Room AppleTV._airplay._tcp.local.", the instance label is the leftmost
    // label and the rest is the service fqdn.
    let trimmed = fqdn.trim_end_matches('.');
    let parts: Vec<&str> = trimmed.split('.').collect();
    let n = parts.len();
    if n < 4 {
        return Err(Error::InvalidServiceType(fqdn.to_string()));
    }
    // Validate _<svc>._<proto>.local using .get() to satisfy indexing_slicing.
    let tld = parts.get(n - 1).copied().unwrap_or("");
    let proto = parts.get(n - 2).copied().unwrap_or("");
    let svc = parts.get(n - 3).copied().unwrap_or("");
    if tld != "local" || !(proto == "_tcp" || proto == "_udp") || !svc.starts_with('_') {
        return Err(Error::InvalidServiceType(fqdn.to_string()));
    }
    let service_fqdn = format!("{svc}.{proto}.{tld}.");
    Ok(Parsed { service_fqdn })
}

fn push_query(msg: &mut Message, name: &str, qtype: RecordType) -> Result<()> {
    let n = crate::name_util::lax_from_str(name)?;
    let mut q = Query::query(n, qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    Ok(())
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
            Ok(Err(e)) => tracing::debug!(error = %e, "clone recv error, dropping packet"),
            Err(_) => break,
        }
    }
    Ok(records)
}

fn absorb_record(out: &mut ClonedInstance, r: &Record, instance_fqdn: &str) {
    let owner = r.name().to_string();
    let owner_norm = owner.trim_end_matches('.').to_ascii_lowercase();
    let instance_norm = instance_fqdn.trim_end_matches('.').to_ascii_lowercase();
    let host_match = out
        .host
        .as_deref()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase());

    match r.data() {
        Some(RData::SRV(srv)) if owner_norm == instance_norm => {
            out.host = Some(srv.target().to_string());
            out.port = Some(srv.port());
            out.priority = srv.priority();
            out.weight = srv.weight();
            if r.ttl() > 0 && (out.ttl == 0 || r.ttl() < out.ttl) {
                out.ttl = r.ttl();
            }
        }
        Some(RData::TXT(txt)) if owner_norm == instance_norm && out.txt.is_empty() => {
            for kv in txt.iter() {
                if let Ok(s) = std::str::from_utf8(kv) {
                    out.txt.push(s.to_string());
                } else {
                    tracing::warn!(
                        "skipping non-UTF-8 TXT entry on {instance_fqdn}; clone will not be byte-for-byte"
                    );
                }
            }
        }
        Some(RData::A(A(ip)))
            if host_match.as_deref() == Some(&owner_norm) && !out.addrs_v4.contains(ip) =>
        {
            out.addrs_v4.push(*ip);
        }
        Some(RData::AAAA(AAAA(ip)))
            if host_match.as_deref() == Some(&owner_norm) && !out.addrs_v6.contains(ip) =>
        {
            out.addrs_v6.push(*ip);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_instance_handles_multilabel_instance() {
        let p = parse_instance("Living Room ATV._airplay._tcp.local.").expect("parse");
        assert_eq!(p.service_fqdn, "_airplay._tcp.local.");
    }

    #[test]
    fn parse_instance_rejects_non_local() {
        assert!(parse_instance("foo._airplay._tcp.example.com.").is_err());
    }

    #[test]
    fn parse_instance_rejects_no_underscore_service() {
        assert!(parse_instance("foo.airplay._tcp.local.").is_err());
    }

    #[test]
    fn to_toml_emits_minimal_record_set() {
        let c = ClonedInstance {
            instance_fqdn: "Foo._airplay._tcp.local.".into(),
            service_fqdn: "_airplay._tcp.local.".into(),
            host: Some("Foo.local.".into()),
            port: Some(7000),
            txt: vec!["model=AppleTV11,1".into()],
            addrs_v4: vec![Ipv4Addr::new(10, 0, 0, 1)],
            ttl: 4500,
            ..Default::default()
        };
        let s = c.to_toml();
        assert!(s.contains("ttl = 4500"));
        assert!(s.contains(r#"qtype = "PTR""#));
        assert!(s.contains(r#"qtype = "SRV""#));
        assert!(s.contains("port = 7000"));
        assert!(s.contains(r#"qtype = "TXT""#));
        assert!(s.contains(r#"qtype = "A""#));
        assert!(s.contains("10.0.0.1"));
    }

    #[test]
    fn toml_quote_escapes_special_chars() {
        assert_eq!(toml_quote("plain"), r#""plain""#);
        assert_eq!(toml_quote("with\"quote"), r#""with\"quote""#);
        assert_eq!(toml_quote("back\\slash"), r#""back\\slash""#);
    }

    #[test]
    fn empty_when_no_records_absorbed() {
        let c = ClonedInstance {
            instance_fqdn: "X._airplay._tcp.local.".into(),
            service_fqdn: "_airplay._tcp.local.".into(),
            ..Default::default()
        };
        assert!(c.is_empty());
    }
}
