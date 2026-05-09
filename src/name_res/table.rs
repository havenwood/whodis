//! Shared answer-table format for the name-resolution responders.

use std::net::IpAddr;

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnswerTable {
    #[serde(default, rename = "name")]
    pub names: Vec<NameEntry>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NameEntry {
    pub r#match: String,
    pub answer: IpAddr,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub nbns_suffix: Option<u8>,
}

const fn default_ttl() -> u32 {
    30
}

impl AnswerTable {
    pub fn from_toml(s: &str) -> Result<Self> {
        toml::from_str::<Self>(s).map_err(|e| Error::NameRes {
            reason: e.to_string(),
        })
    }

    /// Look up the first entry whose `match` matches `query` (case-insensitive
    /// exact, or a single trailing-`*` glob). Returns `None` if no match.
    #[must_use]
    pub fn lookup(&self, query: &str) -> Option<&NameEntry> {
        let q = query.trim_end_matches('.').to_ascii_lowercase();
        self.names.iter().find(|entry| matches(&entry.r#match, &q))
    }
}

fn matches(pattern: &str, query: &str) -> bool {
    let pat = pattern.to_ascii_lowercase();
    if let Some(prefix) = pat.strip_suffix('*') {
        return query.starts_with(prefix);
    }
    query == pat
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_table() {
        let toml = r#"
            [[name]]
            match  = "wpad"
            answer = "10.0.0.5"
        "#;
        let t = AnswerTable::from_toml(toml).expect("parse");
        assert_eq!(t.names.len(), 1);
        let entry = t.names.first().expect("entry");
        assert_eq!(entry.r#match, "wpad");
        assert_eq!(entry.ttl, 30);
        assert_eq!(entry.answer.to_string(), "10.0.0.5");
        assert!(entry.nbns_suffix.is_none());
    }

    #[test]
    fn rejects_unknown_keys() {
        let toml = r#"
            [[name]]
            match  = "wpad"
            answer = "10.0.0.5"
            wat    = true
        "#;
        let r = AnswerTable::from_toml(toml);
        assert!(r.is_err());
    }

    #[test]
    fn lookup_exact_case_insensitive() {
        let t = AnswerTable::from_toml(
            r#"[[name]]
               match  = "WPAD"
               answer = "1.2.3.4"
            "#,
        )
        .expect("parse");
        assert!(t.lookup("wpad").is_some());
        assert!(t.lookup("Wpad.").is_some());
        assert!(t.lookup("wpadx").is_none());
    }

    #[test]
    fn lookup_glob_only_trailing_star() {
        let t = AnswerTable::from_toml(
            r#"[[name]]
               match  = "proxy*"
               answer = "1.2.3.4"
            "#,
        )
        .expect("parse");
        assert!(t.lookup("proxy").is_some());
        assert!(t.lookup("proxy.example").is_some());
        assert!(t.lookup("notproxy").is_none());
    }

    #[test]
    fn ttl_default_is_thirty() {
        let t = AnswerTable::from_toml(
            r#"[[name]]
               match  = "x"
               answer = "1.1.1.1"
            "#,
        )
        .expect("parse");
        assert_eq!(t.names.first().expect("entry").ttl, 30);
    }
}
