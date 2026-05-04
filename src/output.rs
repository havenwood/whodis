//! CLI output sink. The only place in the crate allowed to write to stdout.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};

use serde::Serialize;

use crate::browse::Event;
use crate::probe::{HostEnumeration, HostSummary, ServiceTypeSummary};
use crate::types::HostAnswer;
use crate::types::{Device, Fingerprint, Instance, NeighborEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    #[must_use]
    pub(crate) fn enabled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                if std::env::var_os("NO_COLOR").is_some() {
                    return false;
                }
                io::stdout().is_terminal()
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Renderer {
    Jsonl,
    Pretty(ColorMode),
}

/// Write a raw string to stdout. Used by subcommands that produce non-JSONL output (e.g. clone).
#[allow(
    clippy::print_stdout,
    reason = "output.rs is the designated CLI stdout sink"
)]
pub(crate) fn emit_raw(s: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(s.as_bytes())?;
    out.flush()
}

pub(crate) fn emit_jsonl<T: Serialize>(value: &T) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()
}

pub(crate) fn emit_browse_event(
    renderer: Renderer,
    event: &Event,
    fp: Option<&Fingerprint>,
) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => emit_jsonl(&BrowseRecord {
            event,
            fingerprint: fp,
        }),
        Renderer::Pretty(c) => emit_browse_pretty(c, event, fp),
    }
}

#[derive(Serialize)]
struct BrowseRecord<'a> {
    #[serde(flatten)]
    event: &'a Event,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<&'a Fingerprint>,
}

pub(crate) fn emit_service_type_summaries(
    renderer: Renderer,
    summaries: &[ServiceTypeSummary],
) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => {
            for s in summaries {
                emit_jsonl(s)?;
            }
            Ok(())
        }
        Renderer::Pretty(_) => {
            let mut out = io::stdout().lock();
            let width = summaries.iter().map(|s| s.fqdn.len()).max().unwrap_or(0);
            for s in summaries {
                let plural = if s.instance_count == 1 {
                    "instance"
                } else {
                    "instances"
                };
                writeln!(
                    out,
                    "  {:<width$}   {} {}",
                    s.fqdn, s.instance_count, plural
                )?;
            }
            Ok(())
        }
    }
}

pub(crate) fn emit_host_summaries(renderer: Renderer, summaries: &[HostSummary]) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => {
            for s in summaries {
                emit_jsonl(s)?;
            }
            Ok(())
        }
        Renderer::Pretty(_) => {
            let mut out = io::stdout().lock();
            let width = summaries.iter().map(|s| s.host.len()).max().unwrap_or(0);
            for s in summaries {
                let plural = if s.service_count == 1 {
                    "service"
                } else {
                    "services"
                };
                writeln!(out, "  {:<width$}   {} {}", s.host, s.service_count, plural)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn emit_instance(
    renderer: Renderer,
    instance: &Instance,
    fp: Option<&Fingerprint>,
) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => emit_jsonl(&Device {
            instance: instance.clone(),
            addrs: instance.addrs.clone(),
            fingerprint: fp.cloned(),
        }),
        Renderer::Pretty(c) => emit_instance_pretty(c, instance, fp),
    }
}

pub(crate) fn emit_host_answers(renderer: Renderer, answers: &[HostAnswer]) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => {
            for a in answers {
                emit_jsonl(a)?;
            }
            Ok(())
        }
        Renderer::Pretty(_) => {
            let mut out = io::stdout().lock();
            for a in answers {
                let mut rendered_addrs = Vec::with_capacity(a.addrs.len());
                for addr in &a.addrs {
                    rendered_addrs.push(addr.to_string());
                }
                let addrs = rendered_addrs.join(", ");
                writeln!(out, "{}  {}", a.host, addrs)?;
            }
            Ok(())
        }
    }
}

fn emit_browse_pretty(color: ColorMode, event: &Event, fp: Option<&Fingerprint>) -> io::Result<()> {
    let on = color.enabled();
    let mut out = io::stdout().lock();
    let now = now_hms();
    let tag = fp_tag(on, fp);
    match event {
        Event::ServiceTypeFound { service_type } => writeln!(
            out,
            "  {}  {}  service-type {}",
            paint(on, " *", BLUE),
            now,
            service_type.fqdn()
        ),
        Event::InstanceFound { instance } => writeln!(
            out,
            "  {}  {}  {:<28}  {:<16}  {}:{}{}",
            paint(on, " +", GREEN),
            now,
            truncate(&instance.instance_name, 28),
            truncate(&instance.service_type.fqdn(), 16),
            instance.host,
            instance.port,
            tag,
        ),
        Event::InstanceUpdated { instance } => writeln!(
            out,
            "  {}  {}  {:<28}  {:<16}  txt update{}",
            paint(on, " ~", YELLOW),
            now,
            truncate(&instance.instance_name, 28),
            truncate(&instance.service_type.fqdn(), 16),
            tag,
        ),
        Event::InstanceGoodbye { fqdn } => writeln!(
            out,
            "  {}  {}  {:<28}  {:<16}  goodbye",
            paint(on, " -", RED),
            now,
            truncate(fqdn, 28),
            "",
        ),
    }
}

fn fp_tag(on: bool, fp: Option<&Fingerprint>) -> String {
    fp.map_or_else(String::new, |fp| {
        let summary = fp.os_hint.as_ref().map_or_else(
            || format!("{} {}", fp.vendor, fp.product),
            |os| format!("{} {} ({os})", fp.vendor, fp.product),
        );
        format!("  {}", paint(on, &summary, BOLD))
    })
}

fn emit_instance_pretty(
    color: ColorMode,
    instance: &Instance,
    fp: Option<&Fingerprint>,
) -> io::Result<()> {
    let on = color.enabled();
    let mut out = io::stdout().lock();
    writeln!(out, "{}", paint(on, &instance.fqdn(), BOLD))?;
    writeln!(out, "    host        {}", instance.host)?;
    if !instance.addrs.is_empty() {
        let addrs = instance
            .addrs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "    addrs       {addrs}")?;
    }
    writeln!(out, "    port        {}", instance.port)?;
    let mut rendered_txt = Vec::with_capacity(instance.txt.len());
    for (k, v) in &instance.txt {
        let value =
            std::str::from_utf8(v).map_or_else(|_| format!("0x{}", hex_lower(v)), String::from);
        rendered_txt.push(format!("{k}={value}"));
    }
    let txt = rendered_txt.join("  ");
    writeln!(out, "    txt         {txt}")?;
    if let Some(fp) = fp {
        let summary = fp.os_hint.as_ref().map_or_else(
            || format!("{} {}", fp.vendor, fp.product),
            |os| format!("{} {} ({os})", fp.vendor, fp.product),
        );
        writeln!(out, "    fingerprint {}", paint(on, &summary, BOLD))?;
    }
    writeln!(out)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let cut = max.saturating_sub(3);
        let mut t = s.chars().take(cut).collect::<String>();
        t.push_str("...");
        t
    }
}

fn now_hms() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format!("{:02}:{:02}:{:02}", now.hour(), now.minute(), now.second())
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _r = write!(s, "{byte:02x}");
    }
    s
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";

fn paint(enabled: bool, body: &str, color: &str) -> String {
    if enabled {
        format!("{color}{body}{RESET}")
    } else {
        body.to_string()
    }
}

pub(crate) fn emit_host_enumeration(
    renderer: Renderer,
    enumeration: &HostEnumeration,
) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => emit_jsonl(enumeration),
        Renderer::Pretty(c) => emit_host_enumeration_pretty(c, enumeration),
    }
}

fn emit_host_enumeration_pretty(color: ColorMode, e: &HostEnumeration) -> io::Result<()> {
    let on = color.enabled();
    let mut out = io::stdout().lock();
    writeln!(out, "{}", paint(on, &e.host, BOLD))?;
    if !e.addrs.is_empty() {
        let addrs = e
            .addrs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "  addrs    {addrs}")?;
    }
    if e.services.is_empty() {
        writeln!(out, "  no services found")?;
    } else {
        for svc in &e.services {
            writeln!(
                out,
                "  {} on port {}",
                paint(on, &svc.service_type, BOLD),
                svc.port
            )?;
            if !svc.instance_name.is_empty() {
                writeln!(out, "    instance  {}", svc.instance_name)?;
            }
            if !svc.txt.is_empty() {
                let txt = svc
                    .txt
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("  ");
                writeln!(out, "    txt       {txt}")?;
            }
        }
    }
    Ok(())
}

pub(crate) fn emit_neighbor_entries(
    renderer: Renderer,
    entries: &[NeighborEntry],
) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => {
            for e in entries {
                emit_jsonl(e)?;
            }
            Ok(())
        }
        Renderer::Pretty(c) => emit_neighbors_pretty(c, entries),
    }
}

#[allow(
    clippy::print_stdout,
    reason = "output.rs is the designated CLI stdout sink"
)]
fn emit_neighbors_pretty(color: ColorMode, entries: &[NeighborEntry]) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let on = color.enabled();
    let mut out = io::stdout().lock();

    // Column widths
    let iface_w = entries.iter().map(|e| e.interface.len()).max().unwrap_or(5);
    let ip_w = entries
        .iter()
        .map(|e| e.ip.to_string().len())
        .max()
        .unwrap_or(15);
    let mac_w = 17; // xx:xx:xx:xx:xx:xx is always 17 chars

    for e in entries {
        let [o0, o1, o2, o3, o4, o5] = e.mac;
        let mac_str = format!("{o0:02x}:{o1:02x}:{o2:02x}:{o3:02x}:{o4:02x}:{o5:02x}");
        let vendor = e.vendor.as_deref().unwrap_or("-");
        writeln!(
            out,
            "  {:<iface_w$}  {:<ip_w$}  {}  {}",
            paint(on, &e.interface, BOLD),
            e.ip,
            mac_str,
            vendor,
            iface_w = iface_w,
            ip_w = ip_w,
        )?;
        let _ = mac_w;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_preserves_short_strings() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_clips_long_strings_with_ellipsis() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
    }

    #[test]
    fn paint_off_returns_plain_text() {
        assert_eq!(paint(false, "hi", RED), "hi");
    }

    #[test]
    fn paint_on_wraps_with_ansi() {
        let s = paint(true, "hi", RED);
        assert!(s.starts_with("\x1b[31m"));
        assert!(s.ends_with("\x1b[0m"));
    }
}
