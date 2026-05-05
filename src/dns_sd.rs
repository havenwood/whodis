//! Query the macOS Bonjour daemon (mDNSResponder) directly via `dns_sd.h`
//! through the astro-dnssd crate. Used as a fallback when wire-level mDNS
//! probing misses Apple services that announce only over AWDL.

use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;

use crate::types::{Instance, Protocol, ServiceType};

/// Known-Apple service name prefixes (the part before `._tcp` / `._udp`).
/// When wire-level probing returns empty for one of these, we fall back to
/// querying mDNSResponder directly.
pub(crate) const APPLE_SERVICES: &[&str] = &[
    "_airplay",
    "_raop",
    "_airdrop",
    "_hap",
    "_companion-link",
    "_rdlink",
    "_apple-mobdev2",
    "_afpovertcp",
    "_device-info",
    "_sleep-proxy",
    "_meshcop",
];

/// Normalize a service type input to just the `_name` portion (no protocol,
/// no `.local.` suffix). Returns `None` if the input cannot be parsed.
fn extract_service_name(service: &str) -> Option<&str> {
    // Strip trailing dot and `.local` suffix
    let s = service.trim_end_matches('.');
    let s = s.strip_suffix(".local").unwrap_or(s);
    // Strip `._tcp` or `._udp` suffix
    let s = s
        .strip_suffix("._tcp")
        .or_else(|| s.strip_suffix("._udp"))
        .unwrap_or(s);
    if s.starts_with('_') { Some(s) } else { None }
}

/// Return `true` if the service type belongs to the known-Apple list.
/// Accepts both `_airplay._tcp.local.` and `_airplay._tcp` forms.
pub(crate) fn is_apple_service_type(service: &str) -> bool {
    let Some(name) = extract_service_name(service) else {
        return false;
    };
    APPLE_SERVICES
        .iter()
        .any(|&known| known.eq_ignore_ascii_case(name))
}

/// Normalize a service type string for passing to the dns-sd API.
/// Returns `_name._tcp` or `_name._udp`, whichever was present, falling back
/// to `_name._tcp` when no protocol suffix is found.
fn normalize_regtype(service: &str) -> String {
    let s = service.trim_end_matches('.');
    let s = s.strip_suffix(".local").unwrap_or(s);
    // Already has protocol
    if s.ends_with("._tcp") || s.ends_with("._udp") {
        return s.to_string();
    }
    // No protocol: default to _tcp
    format!("{s}._tcp")
}

/// Parse a `regtype` string like `_airplay._tcp.` into a `ServiceType`.
fn parse_service_type(regtype: &str) -> Option<ServiceType> {
    let s = regtype.trim_end_matches('.');
    let s = s.strip_suffix(".local").unwrap_or(s);
    let (name, proto_str) = s.rsplit_once('.')?;
    let proto = match proto_str {
        "_tcp" => Protocol::Tcp,
        "_udp" => Protocol::Udp,
        _ => return None,
    };
    Some(ServiceType::new(name, proto))
}

/// Browse the given service type via mDNSResponder for `timeout`, then
/// resolve each observed instance's host:port and TXT records. Returns
/// one Instance per unique observed instance.
///
/// `service` accepts both `_airplay._tcp` and `_airplay._tcp.local.`.
pub(crate) async fn browse_service(
    service: &str,
    timeout: Duration,
) -> anyhow::Result<Vec<Instance>> {
    let regtype = normalize_regtype(service);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Instance>(64);

    let regtype_clone = regtype.clone();
    // Spawn the dns-sd browse on a blocking thread (the crate's API is sync).
    // We discard the JoinHandle: the task self-exits when `tx` is dropped
    // (which happens when this async function returns), so there's no leak.
    let _handle = tokio::task::spawn_blocking(move || {
        let browser = match astro_dnssd::ServiceBrowserBuilder::new(&regtype_clone).browse() {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, "dns_sd browser failed to start");
                return;
            }
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let poll = remaining.min(Duration::from_millis(200));
            match browser.recv_timeout(poll) {
                Ok(svc) => {
                    if svc.event_type != astro_dnssd::ServiceEventType::Added {
                        continue;
                    }
                    let Some(service_type) = parse_service_type(&svc.regtype) else {
                        continue;
                    };
                    let host = if svc.hostname.ends_with('.') {
                        svc.hostname.clone()
                    } else {
                        format!("{}.", svc.hostname)
                    };
                    let mut txt: BTreeMap<String, Bytes> = BTreeMap::new();
                    if let Some(map) = svc.txt_record {
                        // astro-dnssd surfaces TXT as `HashMap<String, String>`, which means
                        // any non-UTF8 TXT value has already been dropped by the crate before
                        // we see it. Acceptable for engagement use - binary TXT is rare and the
                        // wire-level path captures it faithfully when it works.
                        for (k, v) in map {
                            txt.insert(k, Bytes::from(v.into_bytes()));
                        }
                    }
                    let instance = Instance {
                        service_type,
                        instance_name: svc.name,
                        host,
                        port: svc.port,
                        addrs: Vec::new(),
                        txt,
                    };
                    if tx.blocking_send(instance).is_err() {
                        break;
                    }
                }
                Err(astro_dnssd::BrowseError::Timeout) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "dns_sd recv error");
                }
            }
        }
    });

    let mut instances: Vec<Instance> = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(inst)) => instances.push(inst),
            Ok(None) | Err(_) => break,
        }
    }

    // Deduplicate by instance_name + service_type
    instances.sort_by(|a, b| {
        (&a.service_type.name, &a.instance_name).cmp(&(&b.service_type.name, &b.instance_name))
    });
    instances
        .dedup_by(|a, b| a.service_type == b.service_type && a.instance_name == b.instance_name);

    Ok(instances)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_apple_service_type_recognizes_airplay_fqdn() {
        assert!(is_apple_service_type("_airplay._tcp.local."));
    }

    #[test]
    fn is_apple_service_type_recognizes_raop_no_local() {
        assert!(is_apple_service_type("_raop._tcp"));
    }

    #[test]
    fn is_apple_service_type_recognizes_airdrop() {
        assert!(is_apple_service_type("_airdrop._tcp.local."));
    }

    #[test]
    fn is_apple_service_type_recognizes_hap() {
        assert!(is_apple_service_type("_hap._tcp"));
    }

    #[test]
    fn is_apple_service_type_recognizes_companion_link() {
        assert!(is_apple_service_type("_companion-link._tcp.local."));
    }

    #[test]
    fn is_apple_service_type_recognizes_meshcop() {
        assert!(is_apple_service_type("_meshcop._udp.local."));
    }

    #[test]
    fn is_apple_service_type_rejects_googlecast() {
        assert!(!is_apple_service_type("_googlecast._tcp.local."));
    }

    #[test]
    fn is_apple_service_type_rejects_ipp() {
        assert!(!is_apple_service_type("_ipp._tcp.local."));
    }

    #[test]
    fn normalize_regtype_strips_local_and_dot() {
        assert_eq!(normalize_regtype("_airplay._tcp.local."), "_airplay._tcp");
    }

    #[test]
    fn normalize_regtype_keeps_tcp_suffix() {
        assert_eq!(normalize_regtype("_airplay._tcp"), "_airplay._tcp");
    }

    #[test]
    fn normalize_regtype_keeps_udp_suffix() {
        assert_eq!(normalize_regtype("_meshcop._udp"), "_meshcop._udp");
    }

    #[test]
    fn normalize_regtype_adds_tcp_when_no_proto() {
        assert_eq!(normalize_regtype("_airplay"), "_airplay._tcp");
    }

    #[test]
    fn input_normalization_both_forms_same_name() {
        let a = extract_service_name("_airplay._tcp.local.");
        let b = extract_service_name("_airplay._tcp");
        assert_eq!(a, b);
        assert_eq!(a, Some("_airplay"));
    }

    #[test]
    fn parse_service_type_tcp() {
        let st = parse_service_type("_airplay._tcp.").expect("parse");
        assert_eq!(st.name, "_airplay");
        assert_eq!(st.protocol, Protocol::Tcp);
    }

    #[test]
    fn parse_service_type_udp() {
        let st = parse_service_type("_meshcop._udp").expect("parse");
        assert_eq!(st.name, "_meshcop");
        assert_eq!(st.protocol, Protocol::Udp);
    }
}
