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
//!
//! [[answer]]
//! name = "Spoofed-AppleTV._airplay._tcp.local."
//! qtype = "SRV"
//! port = 7000
//! target = "Spoofed-AppleTV.local."
//! # priority and weight default to 0
//!
//! [[answer]]
//! name = "Spoofed-AppleTV._airplay._tcp.local."
//! qtype = "TXT"
//! txt = ["model=AppleTV11,1", "deviceid=AA:BB:CC:DD:EE:FF"]
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, anyhow};
use hickory_proto::rr::rdata::{A, AAAA, PTR, SRV, TXT};
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
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    txt: Option<Vec<String>>,
}

fn default_ttl() -> u32 {
    120
}

pub(crate) fn load(toml_src: &str) -> anyhow::Result<AnswerTable> {
    let raw: Raw = toml::from_str(toml_src).context("parsing spoof table TOML")?;
    let mut b = AnswerTableBuilder::new().ttl(raw.ttl);
    for entry in raw.answers {
        let qtype = parse_qtype(&entry.qtype)?;
        let rdata = parse_rdata(qtype, &entry)?;
        b = b.answer(entry.name, qtype, rdata)?;
    }
    Ok(b.build())
}

fn parse_qtype(s: &str) -> anyhow::Result<RecordType> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "PTR" => Ok(RecordType::PTR),
        "SRV" => Ok(RecordType::SRV),
        "TXT" => Ok(RecordType::TXT),
        other => Err(anyhow!("unsupported qtype: {other}")),
    }
}

fn parse_rdata(qtype: RecordType, entry: &RawAnswer) -> anyhow::Result<RData> {
    match qtype {
        RecordType::A => {
            let data = entry.data.as_deref().context("`data` required for A")?;
            Ok(RData::A(A(data.parse::<Ipv4Addr>().context("ipv4")?)))
        }
        RecordType::AAAA => {
            let data = entry.data.as_deref().context("`data` required for AAAA")?;
            Ok(RData::AAAA(AAAA(data.parse::<Ipv6Addr>().context("ipv6")?)))
        }
        RecordType::PTR => {
            let data = entry.data.as_deref().context("`data` required for PTR")?;
            Ok(RData::PTR(PTR(Name::from_utf8(data).context("ptr name")?)))
        }
        RecordType::SRV => {
            let port = entry.port.context("`port` required for SRV")?;
            let target_str = entry.target.as_deref().context("`target` required for SRV")?;
            let target = Name::from_utf8(target_str).context("srv target")?;
            let priority = entry.priority.unwrap_or(0);
            let weight = entry.weight.unwrap_or(0);
            Ok(RData::SRV(SRV::new(priority, weight, port, target)))
        }
        RecordType::TXT => {
            let txt = entry.txt.clone().context("`txt` required for TXT")?;
            Ok(RData::TXT(TXT::new(txt)))
        }
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
    fn loads_srv_and_txt() {
        let src = r#"
            [[answer]]
            name = "Spoofed._airplay._tcp.local."
            qtype = "SRV"
            port = 7000
            target = "Spoofed.local."

            [[answer]]
            name = "Spoofed._airplay._tcp.local."
            qtype = "TXT"
            txt = ["model=AppleTV11,1"]
        "#;
        let t = load(src).expect("load");
        assert!(t.lookup("Spoofed._airplay._tcp.local.", RecordType::SRV).is_some());
        assert!(t.lookup("Spoofed._airplay._tcp.local.", RecordType::TXT).is_some());
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
