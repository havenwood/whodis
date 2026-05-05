//! Markdown engagement report generator.
//!
//! Produces a self-contained `.md` file summarising the LAN's mDNS surface at one
//! moment in time. Pairs naturally with `whodis capture --pcap` for raw evidence.

use std::fmt::Write as _;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_stream::StreamExt;

use crate::browse::{Browser, Event};
use crate::error::Result;
use crate::fingerprint;
use crate::mode::Mode;
use crate::probe::{self, ProbeOptions, ServiceTypeSummary};
use crate::types::{Fingerprint, Instance};

const DEFAULT_WINDOW_SECS: u64 = 10;

pub(crate) async fn write(out_path: &Path, window_secs: u64) -> Result<usize> {
    let secs = if window_secs == 0 {
        DEFAULT_WINDOW_SECS
    } else {
        window_secs
    };
    let started = SystemTime::now();

    // Phase 1: discover service types (count by type).
    let opts = ProbeOptions {
        timeout: Duration::from_secs(secs / 2 + 1),
    };
    let (service_types, service_type_error) = match probe::discover_service_types(&opts).await {
        Ok(service_types) => (service_types, None),
        Err(e) => {
            tracing::warn!(error = %e, "report: service-type discovery failed");
            (Vec::new(), Some(e.to_string()))
        }
    };

    // Phase 2: snapshot instances.
    let instances = collect_instances(secs).await;

    // Phase 3: compose the Markdown.
    let bytes = build_markdown(
        started,
        secs,
        &service_types,
        &instances,
        service_type_error.as_deref(),
    );

    // Phase 4: write atomically (or as close as we can).
    let file = std::fs::File::create(out_path)?;
    let mut w = BufWriter::new(file);
    w.write_all(bytes.as_bytes())?;
    w.flush()?;

    Ok(instances.len())
}

async fn collect_instances(window_secs: u64) -> Vec<Instance> {
    let browser = match Browser::new(Mode::Listen) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "report: browser failed to start; section will be empty");
            return Vec::new();
        }
    };
    let cancel = browser.cancel_token();
    let stream = browser.run();
    tokio::pin!(stream);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(window_secs);
    let mut seen: std::collections::BTreeMap<String, Instance> = std::collections::BTreeMap::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Event::InstanceFound { instance } | Event::InstanceUpdated { instance })) => {
                seen.insert(instance.fqdn(), instance);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    cancel.cancel();
    seen.into_values().collect()
}

fn build_markdown(
    started: SystemTime,
    window_secs: u64,
    service_types: &[ServiceTypeSummary],
    instances: &[Instance],
    service_type_error: Option<&str>,
) -> String {
    let mut s = String::new();
    let when = format_iso8601(started);
    let _r = writeln!(s, "# whodis engagement report\n");
    let _r = writeln!(s, "- **Generated:** {when}");
    let _r = writeln!(s, "- **Inventory window:** {window_secs}s");
    let _r = writeln!(s, "- **Tool:** `whodis {}`\n", env!("CARGO_PKG_VERSION"));

    // Service-type table
    let _r = writeln!(s, "## Service types\n");
    if service_types.is_empty() {
        let _r = writeln!(s, "_No service types observed._\n");
    } else {
        let _r = writeln!(s, "| Service type | Instance count |");
        let _r = writeln!(s, "|---|---:|");
        for st in service_types {
            let _r = writeln!(s, "| `{}` | {} |", st.fqdn, st.instance_count);
        }
        let _r = writeln!(s);
    }

    // Instance inventory
    let _r = writeln!(s, "## Instance inventory\n");
    if instances.is_empty() {
        let _r = writeln!(s, "_No instances observed in the {window_secs}s window._\n");
    } else {
        let _r = writeln!(
            s,
            "| Instance | Service type | Host:Port | Vendor / Product | TXT highlights |"
        );
        let _r = writeln!(s, "|---|---|---|---|---|");
        for inst in instances {
            let fp = fingerprint::identify(inst);
            let fp_str = fp.as_ref().map_or_else(String::new, format_fp);
            let txt_str = format_txt_highlights(inst);
            let host = format_host_port(inst);
            let _r = writeln!(
                s,
                "| `{}` | `{}` | `{}` | {} | {} |",
                escape_md(&inst.instance_name),
                inst.service_type.fqdn(),
                host,
                fp_str,
                txt_str,
            );
        }
        let _r = writeln!(s);
    }

    let _r = writeln!(s, "## Notes\n");
    if let Some(error) = service_type_error {
        let _r = writeln!(s, "- Service-type discovery failed: `{}`", escape_md(error));
    }
    let _r = writeln!(
        s,
        "Generated by `whodis report`. Pair with `whodis capture --pcap` for full packet evidence.\n"
    );

    s
}

fn format_host_port(inst: &Instance) -> String {
    if inst.addrs.is_empty() {
        return format!("{}:{}", inst.host, inst.port);
    }
    let addrs = inst
        .addrs
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} ({addrs}):{}", inst.host, inst.port)
}

fn format_iso8601(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let when = time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(0))
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        when.year(),
        u8::from(when.month()),
        when.day(),
        when.hour(),
        when.minute(),
        when.second()
    )
}

fn format_fp(fp: &Fingerprint) -> String {
    fp.os_hint.as_ref().map_or_else(
        || format!("{} {}", fp.vendor, fp.product),
        |os| format!("{} {} ({os})", fp.vendor, fp.product),
    )
}

fn format_txt_highlights(inst: &Instance) -> String {
    // Show up to 3 most useful TXT keys: model, deviceid/id, ty/product, fn, am, md.
    const KEYS_OF_INTEREST: &[&str] =
        &["model", "deviceid", "id", "ty", "product", "fn", "am", "md"];
    let mut parts: Vec<String> = Vec::with_capacity(3);
    for key in KEYS_OF_INTEREST {
        if parts.len() >= 3 {
            break;
        }
        if let Some(v) = inst.txt.get(*key) {
            let value =
                std::str::from_utf8(v).map_or_else(|_| format!("0x{}", hex_short(v)), String::from);
            parts.push(format!("`{key}={}`", escape_md(&value)));
        }
    }
    parts.join(" ")
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b.iter().take(8) {
        let _r = write!(s, "{byte:02x}");
    }
    if b.len() > 8 {
        s.push_str("...");
    }
    s
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_renders_placeholders() {
        let now = SystemTime::now();
        let s = build_markdown(now, 5, &[], &[], None);
        assert!(s.contains("# whodis engagement report"));
        assert!(s.contains("No service types observed"));
        assert!(s.contains("No instances observed"));
    }

    #[test]
    fn renders_service_types_and_instances() {
        let now = SystemTime::now();
        let st = ServiceTypeSummary {
            fqdn: "_airplay._tcp.local.".into(),
            instance_count: 2,
        };
        let inst = Instance {
            service_type: crate::types::ServiceType::new("_airplay", crate::types::Protocol::Tcp),
            instance_name: "Foo".into(),
            host: "Foo.local.".into(),
            port: 7000,
            addrs: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))],
            txt: std::iter::once((
                "model".to_string(),
                bytes::Bytes::from_static(b"AppleTV11,1"),
            ))
            .collect(),
        };
        let s = build_markdown(now, 5, &[st], &[inst], None);
        assert!(s.contains("`_airplay._tcp.local.`"));
        assert!(s.contains("`Foo`"));
        assert!(s.contains("Apple AppleTV"));
        assert!(s.contains("10.0.0.1"));
    }

    #[test]
    fn pipe_in_field_is_escaped() {
        assert_eq!(escape_md("a|b"), "a\\|b");
    }

    #[test]
    fn report_includes_service_type_discovery_error_note() {
        let now = SystemTime::now();
        let s = build_markdown(now, 5, &[], &[], Some("bind failed"));
        assert!(s.contains("Service-type discovery failed"));
        assert!(s.contains("bind failed"));
    }

    #[test]
    fn format_iso8601_uses_utc_with_z_suffix() {
        let t = UNIX_EPOCH;
        assert_eq!(format_iso8601(t), "1970-01-01T00:00:00Z");
    }
}
