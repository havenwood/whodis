//! Soft authorization gate. v1 logs a warning when aggressive ops run with an empty allow-list,
//! but never refuses. The shape exists so the gate can be tightened later without API churn.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ipnet::IpNet;

#[derive(Debug, Clone, Default)]
pub struct Authorization {
    allow_subnets: Vec<IpNet>,
    allow_instances: Vec<String>,
    allow_names: Vec<String>,
    warned: Arc<AtomicBool>,
}

impl Authorization {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn allow_subnet(mut self, net: IpNet) -> Self {
        self.allow_subnets.push(net);
        self
    }

    #[must_use]
    pub fn allow_instance(mut self, name: impl Into<String>) -> Self {
        self.allow_instances
            .push(normalize_instance_id(&name.into()));
        self
    }

    #[must_use]
    pub fn permits_addr(&self, addr: IpAddr) -> bool {
        self.allow_subnets.is_empty() || self.allow_subnets.iter().any(|n| n.contains(&addr))
    }

    #[must_use]
    pub fn permits_instance(&self, name: &str) -> bool {
        if self.allow_instances.is_empty() {
            return true;
        }
        let candidates = instance_candidates(name);
        self.allow_instances
            .iter()
            .any(|allowed| candidates.iter().any(|candidate| candidate == allowed))
    }

    #[must_use]
    pub fn allow_name(mut self, name: impl Into<String>) -> Self {
        self.allow_names.push(name.into().to_ascii_lowercase());
        self
    }

    #[must_use]
    pub fn permits_name(&self, name: &str) -> bool {
        if self.allow_names.is_empty() {
            return true;
        }
        let q = name.trim_end_matches('.').to_ascii_lowercase();
        self.allow_names.iter().any(|pat| name_matches(pat, &q))
    }

    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.allow_subnets.is_empty()
            && self.allow_instances.is_empty()
            && self.allow_names.is_empty()
    }

    /// Emit the "no allow-list" warning at most once per Authorization instance,
    /// from any aggressive op that wants to log it.
    pub fn warn_once_if_permissive(&self, op: &'static str) {
        if !self.is_permissive() {
            return;
        }
        if self.warned.swap(true, Ordering::SeqCst) {
            return;
        }
        tracing::warn!(
            op,
            "no allow-list configured; {op} will fire against any responder it can reach. \
             pass --allow CIDR or --allow-instance NAME to scope it."
        );
    }
}

fn normalize_instance_id(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn instance_candidates(name: &str) -> Vec<String> {
    let full = normalize_instance_id(name);
    let mut candidates = Vec::with_capacity(2);
    candidates.push(full.clone());
    if let Some(leftmost) = full.split('.').next()
        && !leftmost.is_empty()
        && leftmost != full
    {
        candidates.push(leftmost.to_string());
    }
    candidates
}

fn name_matches(pattern: &str, query: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return query.starts_with(prefix);
    }
    query == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_authorization_is_permissive() {
        let a = Authorization::new();
        assert!(a.is_permissive());
        assert!(a.permits_addr("10.0.0.1".parse().expect("addr")));
        assert!(a.permits_instance("anything"));
    }

    #[test]
    fn subnet_allow_blocks_outside_addrs() {
        let a = Authorization::new().allow_subnet("192.168.1.0/24".parse().expect("net"));
        assert!(!a.is_permissive());
        assert!(a.permits_addr("192.168.1.50".parse().expect("addr")));
        assert!(!a.permits_addr("10.0.0.1".parse().expect("addr")));
    }

    #[test]
    fn instance_allow_only_matches_listed() {
        let a = Authorization::new().allow_instance("LivingRoom AppleTV");
        assert!(a.permits_instance("LivingRoom AppleTV"));
        assert!(a.permits_instance("LivingRoom AppleTV._airplay._tcp.local."));
        assert!(a.permits_instance("livingroom appletv._airplay._tcp.local."));
        assert!(!a.permits_instance("Bedroom AppleTV"));
    }

    #[test]
    fn full_fqdn_allow_matches_full_fqdn_only() {
        let a = Authorization::new().allow_instance("Living._airplay._tcp.local.");
        assert!(a.permits_instance("Living._airplay._tcp.local."));
        assert!(!a.permits_instance("Living._raop._tcp.local."));
    }

    #[test]
    fn empty_authorization_permits_any_name() {
        let a = Authorization::new();
        assert!(a.permits_name("wpad"));
        assert!(a.permits_name("anything"));
    }

    #[test]
    fn name_allow_list_blocks_outside_names() {
        let a = Authorization::new().allow_name("wpad");
        assert!(a.permits_name("wpad"));
        assert!(a.permits_name("WPAD"));
        assert!(a.permits_name("wpad."));
        assert!(!a.permits_name("printserver"));
    }

    #[test]
    fn name_glob_matches_trailing_star() {
        let a = Authorization::new().allow_name("proxy*");
        assert!(a.permits_name("proxy"));
        assert!(a.permits_name("proxyserver"));
        assert!(!a.permits_name("notproxy"));
    }
}
