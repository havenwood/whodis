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
pub(crate) struct Scope {
    #[serde(default)]
    pub(crate) allow_subnet: Vec<IpNet>,
    #[serde(default)]
    pub(crate) allow_instance: Vec<String>,
    #[serde(default)]
    pub(crate) log_dir: Option<PathBuf>,
    #[serde(default)]
    pub(crate) apple_services: Vec<String>,
}

impl Scope {
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading scope file {}", path.display()))?;
        let scope: Self = toml::from_str(&raw).context("parsing scope file")?;
        Ok(scope)
    }

    /// Build an `Authorization` from this scope, then layer additional CLI-passed
    /// subnets and instances on top.
    #[must_use]
    pub(crate) fn into_auth(
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
        for net in extra_subnets {
            auth = auth.allow_subnet(net);
        }
        for name in extra_instances {
            auth = auth.allow_instance(name);
        }
        auth
    }

    #[must_use]
    pub(crate) fn log_dir(&self) -> Option<&Path> {
        self.log_dir.as_deref()
    }

    pub(crate) fn apple_services(&self) -> &[String] {
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
}
