//! CLI output sink. The only place in the crate allowed to write to stdout.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};

use serde::Serialize;

use crate::browse::Event;
use crate::types::{Device, Fingerprint, Instance};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    #[must_use]
    pub(crate) fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "always" => Self::Always,
            "never" => Self::Never,
            _ => Self::Auto,
        }
    }

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

impl Renderer {
    #[must_use]
    pub(crate) fn auto(pretty: bool, color: ColorMode) -> Self {
        if pretty {
            Self::Pretty(color)
        } else {
            Self::Jsonl
        }
    }
}

pub(crate) fn emit_jsonl<T: Serialize>(value: &T) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()
}

pub(crate) fn emit_browse_event(renderer: Renderer, event: &Event) -> io::Result<()> {
    match renderer {
        Renderer::Jsonl => emit_jsonl(event),
        Renderer::Pretty(c) => emit_browse_pretty(c, event),
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
            addrs: Vec::new(),
            fingerprint: fp.cloned(),
        }),
        Renderer::Pretty(c) => emit_instance_pretty(c, instance, fp),
    }
}

fn emit_browse_pretty(color: ColorMode, event: &Event) -> io::Result<()> {
    let on = color.enabled();
    let mut out = io::stdout().lock();
    let now = now_hms();
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
            "  {}  {}  {:<28}  {:<16}  {}:{}",
            paint(on, " +", GREEN),
            now,
            truncate(&instance.instance_name, 28),
            truncate(&instance.service_type.fqdn(), 16),
            instance.host,
            instance.port,
        ),
        Event::InstanceUpdated { instance } => writeln!(
            out,
            "  {}  {}  {:<28}  {:<16}  txt update",
            paint(on, " ~", YELLOW),
            now,
            truncate(&instance.instance_name, 28),
            truncate(&instance.service_type.fqdn(), 16),
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

fn emit_instance_pretty(
    color: ColorMode,
    instance: &Instance,
    fp: Option<&Fingerprint>,
) -> io::Result<()> {
    let on = color.enabled();
    let mut out = io::stdout().lock();
    writeln!(out, "{}", paint(on, &instance.fqdn(), BOLD))?;
    writeln!(out, "    host        {}", instance.host)?;
    writeln!(out, "    port        {}", instance.port)?;
    let txt = instance
        .txt
        .iter()
        .map(|(k, v)| {
            let value = std::str::from_utf8(v)
                .map_or_else(|_| format!("0x{}", hex_lower(v)), String::from);
            format!("{k}={value}")
        })
        .collect::<Vec<_>>()
        .join("  ");
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

    #[test]
    fn color_mode_from_str_handles_known_values() {
        assert_eq!(ColorMode::from_str_lossy("always"), ColorMode::Always);
        assert_eq!(ColorMode::from_str_lossy("never"), ColorMode::Never);
        assert_eq!(ColorMode::from_str_lossy("garbage"), ColorMode::Auto);
    }
}
