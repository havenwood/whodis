//! Built-in spoof presets.
//!
//! v1 ships only WPAD. Future plans add SMB and proxy presets.

use std::net::IpAddr;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::name_res::table::{AnswerTable, NameEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Wpad,
}

impl FromStr for Preset {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "wpad" => Ok(Self::Wpad),
            other => Err(Error::Cli {
                reason: format!("unknown preset: {other}"),
            }),
        }
    }
}

#[must_use]
pub fn build(preset: Preset, attacker_ip: IpAddr, engagement_domain: Option<&str>) -> AnswerTable {
    match preset {
        Preset::Wpad => wpad_table(attacker_ip, engagement_domain),
    }
}

fn wpad_table(attacker_ip: IpAddr, engagement_domain: Option<&str>) -> AnswerTable {
    let mut entries = vec![
        NameEntry {
            r#match: "wpad".into(),
            answer: attacker_ip,
            ttl: 30,
            nbns_suffix: None,
        },
        NameEntry {
            r#match: "wpadproxy".into(),
            answer: attacker_ip,
            ttl: 30,
            nbns_suffix: None,
        },
        NameEntry {
            r#match: "wpad.local".into(),
            answer: attacker_ip,
            ttl: 30,
            nbns_suffix: None,
        },
    ];
    if let Some(domain) = engagement_domain {
        entries.push(NameEntry {
            r#match: format!("wpad.{domain}"),
            answer: attacker_ip,
            ttl: 30,
            nbns_suffix: None,
        });
    }
    AnswerTable { names: entries }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_from_str_accepts_wpad_case_insensitive() {
        assert_eq!("wpad".parse::<Preset>().expect("ok"), Preset::Wpad);
        assert_eq!("WPAD".parse::<Preset>().expect("ok"), Preset::Wpad);
        assert!("nope".parse::<Preset>().is_err());
    }

    #[test]
    fn wpad_preset_includes_canonical_names_with_attacker_ip() {
        let ip: IpAddr = "10.0.0.5".parse().expect("ip");
        let t = build(Preset::Wpad, ip, None);
        let has = |s: &str| t.names.iter().any(|e| e.r#match == s);
        assert!(has("wpad"));
        assert!(has("wpadproxy"));
        assert!(has("wpad.local"));
        for e in &t.names {
            assert_eq!(e.answer, ip);
        }
    }

    #[test]
    fn wpad_preset_with_domain_adds_qualified_entry() {
        let ip: IpAddr = "10.0.0.5".parse().expect("ip");
        let t = build(Preset::Wpad, ip, Some("corp.example"));
        assert!(t.names.iter().any(|e| e.r#match == "wpad.corp.example"));
    }

    #[test]
    fn wpad_preset_with_no_domain_does_not_emit_placeholder() {
        let ip: IpAddr = "10.0.0.5".parse().expect("ip");
        let t = build(Preset::Wpad, ip, None);
        for e in &t.names {
            assert!(
                !e.r#match.contains('<'),
                "placeholder leaked: {}",
                e.r#match
            );
            assert!(
                !e.r#match.contains('>'),
                "placeholder leaked: {}",
                e.r#match
            );
        }
    }
}
