//! Loader for spoof answer tables (TOML format).
//!
//! Schema:
//!
//! ```toml
//! ttl = 120  # optional, default 120
//!
//! [[answer]]
//! name = "spoofed.local."
//! qtype = "A"
//! data = "192.168.1.42"
//!
//! [[answer]]
//! name = "_airplay._tcp.local."
//! qtype = "PTR"
//! data = "Spoofed-AppleTV._airplay._tcp.local."
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, anyhow};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::Deserialize;

use crate::spoof::{AnswerTable, AnswerTableBuilder};

#[derive(Debug, Deserialize)]
struct Raw {
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default, rename = "answer")]
    answers: Vec<RawAnswer>,
}

#[derive(Debug, Deserialize)]
struct RawAnswer {
    name: String,
    qtype: String,
    data: String,
}

fn default_ttl() -> u32 {
    120
}

pub(crate) fn load(toml_src: &str) -> anyhow::Result<AnswerTable> {
    let raw: Raw = toml::from_str(toml_src).context("parsing spoof table TOML")?;
    let mut b = AnswerTableBuilder::new().ttl(raw.ttl);
    for entry in raw.answers {
        let qtype = parse_qtype(&entry.qtype)?;
        let rdata = parse_rdata(qtype, &entry.data)?;
        b = b.answer(entry.name, qtype, rdata)?;
    }
    Ok(b.build())
}

fn parse_qtype(s: &str) -> anyhow::Result<RecordType> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "PTR" => Ok(RecordType::PTR),
        other => Err(anyhow!("unsupported qtype: {other}")),
    }
}

fn parse_rdata(qtype: RecordType, data: &str) -> anyhow::Result<RData> {
    match qtype {
        RecordType::A => Ok(RData::A(A(data.parse::<Ipv4Addr>().context("ipv4")?))),
        RecordType::AAAA => Ok(RData::AAAA(AAAA(data.parse::<Ipv6Addr>().context("ipv6")?))),
        RecordType::PTR => Ok(RData::PTR(PTR(Name::from_utf8(data).context("ptr name")?))),
        other => Err(anyhow!("unsupported qtype: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_a_record_table() {
        let src = r#"
            ttl = 60
            [[answer]]
            name = "spoofed.local."
            qtype = "A"
            data = "192.168.1.42"
        "#;
        let t = load(src).expect("load");
        assert!(t.lookup("spoofed.local.", RecordType::A).is_some());
    }

    #[test]
    fn rejects_unknown_qtype() {
        let src = r#"
            [[answer]]
            name = "x.local."
            qtype = "WHAT"
            data = "y"
        "#;
        assert!(load(src).is_err());
    }
}
