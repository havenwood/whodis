//! Engagement scope file loader.
//!
//! A TOML file declaring engagement-wide allow-lists (subnets and instance names)
//! plus optional output paths. Auto-applied to every subcommand. CLI flags still
//! work and stack on top.
//!
//! Schema:
//!
//! ```toml
//! allow_subnet   = ["10.0.5.0/24"]
//! allow_instance = ["LivingRoomTV"]
//! log_dir        = "./engagement-logs"
//! ```

use std::path::{Path, PathBuf};

use anyhow::Context;
use ipnet::IpNet;
use serde::Deserialize;

use crate::auth::Authorization;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub allow_subnet: Vec<IpNet>,
    #[serde(default)]
    pub allow_instance: Vec<String>,
    #[serde(default)]
    pub log_dir: Option<PathBuf>,
    #[serde(default)]
    pub apple_services: Vec<String>,
    #[serde(default)]
    pub allow_llmnr_names: Vec<String>,
    #[serde(default)]
    pub engagement_domain: Option<String>,
}

impl Scope {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading scope file {}", path.display()))?;
        let scope: Self = toml::from_str(&raw).context("parsing scope file")?;
        Ok(scope)
    }

    /// Build an `Authorization` from this scope, then layer additional CLI-passed
    /// subnets and instances on top.
    #[must_use]
    pub fn into_auth(
        self,
        extra_subnets: Vec<IpNet>,
        extra_instances: Vec<String>,
    ) -> Authorization {
        let mut auth = Authorization::new();
        for net in self.allow_subnet {
            auth = auth.allow_subnet(net);
        }
        for name in self.allow_instance {
            auth = auth.allow_instance(name);
        }
        for name in self.allow_llmnr_names {
            auth = auth.allow_name(name);
        }
        for net in extra_subnets {
            auth = auth.allow_subnet(net);
        }
        for name in extra_instances {
            auth = auth.allow_instance(name);
        }
        auth
    }

    #[must_use]
    pub fn log_dir(&self) -> Option<&Path> {
        self.log_dir.as_deref()
    }

    pub fn apple_services(&self) -> &[String] {
        &self.apple_services
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_basic_scope() {
        let toml = r#"
            allow_subnet = ["10.0.5.0/24"]
            allow_instance = ["Foo"]
        "#;
        let s: Scope = toml::from_str(toml).expect("parse");
        assert_eq!(s.allow_subnet.len(), 1);
        assert_eq!(s.allow_instance, vec!["Foo".to_string()]);
        assert!(s.log_dir.is_none());
    }

    #[test]
    fn loads_log_dir_only_scope() {
        let dir = tempdir_or_skip();
        let path = dir.join("scope.toml");
        std::fs::write(&path, "log_dir = \"./out\"\n").expect("write");
        let scope = Scope::load(&path).expect("load");
        assert_eq!(scope.log_dir(), Some(std::path::Path::new("./out")));
        assert!(scope.allow_subnet.is_empty());
        assert!(scope.allow_instance.is_empty());
    }

    #[test]
    fn into_auth_layers_extras() {
        let s = Scope {
            allow_subnet: vec!["10.0.0.0/8".parse().expect("net")],
            allow_instance: vec!["Foo".into()],
            log_dir: None,
            apple_services: Vec::new(),
            allow_llmnr_names: Vec::new(),
            engagement_domain: None,
        };
        let auth = s.into_auth(
            vec!["192.168.1.0/24".parse().expect("net")],
            vec!["Bar".into()],
        );
        assert!(auth.permits_addr("10.0.0.5".parse().expect("addr")));
        assert!(auth.permits_addr("192.168.1.5".parse().expect("addr")));
        assert!(auth.permits_instance("Foo"));
        assert!(auth.permits_instance("Bar"));
    }

    #[test]
    fn parses_apple_services_from_toml() {
        let toml = r#"
            apple_services = ["_apple-foo", "_apple-bar"]
        "#;
        let s: Scope = toml::from_str(toml).expect("parse");
        assert_eq!(
            s.apple_services,
            vec!["_apple-foo".to_string(), "_apple-bar".to_string()]
        );
    }

    fn tempdir_or_skip() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("whodis-scope-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create temp");
        p
    }

    #[test]
    fn malformed_toml_returns_error() {
        let bad = "allow_subnet = [[[not valid toml";
        let result: Result<Scope, _> = toml::from_str(bad);
        assert!(result.is_err());
    }

    #[test]
    fn scope_load_missing_file_returns_error() {
        let result = Scope::load(std::path::Path::new("/nonexistent/path/scope.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn parses_ipv6_in_allow_subnet() {
        let toml = r#"allow_subnet = ["fd00::/8", "10.0.0.0/8"]"#;
        let s: Scope = toml::from_str(toml).expect("parse");
        assert_eq!(s.allow_subnet.len(), 2);
        let v6 = s.allow_subnet.first().expect("first").to_string();
        assert!(v6.contains(':'), "expected IPv6, got {v6}");
    }

    #[test]
    fn empty_arrays_explicit_parse_as_empty() {
        let toml = r"
            allow_subnet = []
            allow_instance = []
            apple_services = []
        ";
        let s: Scope = toml::from_str(toml).expect("parse");
        assert!(s.allow_subnet.is_empty());
        assert!(s.allow_instance.is_empty());
        assert!(s.apple_services.is_empty());
    }

    #[test]
    fn all_four_fields_parse_correctly() {
        let toml = r#"
            allow_subnet   = ["192.168.0.0/16"]
            allow_instance = ["LivingRoomTV"]
            log_dir        = "/tmp/engagement"
            apple_services = ["_apple-custom"]
        "#;
        let s: Scope = toml::from_str(toml).expect("parse");
        assert_eq!(s.allow_subnet.len(), 1);
        assert_eq!(s.allow_instance, vec!["LivingRoomTV".to_string()]);
        assert_eq!(s.log_dir(), Some(std::path::Path::new("/tmp/engagement")));
        assert_eq!(s.apple_services(), &["_apple-custom".to_string()]);
    }

    #[test]
    fn into_auth_with_empty_extras_still_applies_scope() {
        let s = Scope {
            allow_subnet: vec!["172.16.0.0/12".parse().expect("net")],
            allow_instance: vec!["Office".into()],
            log_dir: None,
            apple_services: Vec::new(),
            allow_llmnr_names: Vec::new(),
            engagement_domain: None,
        };
        let auth = s.into_auth(vec![], vec![]);
        assert!(auth.permits_addr("172.16.5.1".parse().expect("addr")));
        assert!(auth.permits_instance("Office"));
        assert!(!auth.permits_instance("Unknown"));
    }

    #[test]
    fn loads_allow_llmnr_names_and_engagement_domain() {
        let toml = r#"
            allow_llmnr_names = ["wpad", "proxy*"]
            engagement_domain = "corp.example"
        "#;
        let s: Scope = toml::from_str(toml).expect("parse");
        assert_eq!(s.allow_llmnr_names, vec!["wpad", "proxy*"]);
        assert_eq!(s.engagement_domain.as_deref(), Some("corp.example"));
    }
}
