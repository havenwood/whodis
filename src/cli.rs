//! CLI argument parsing and subcommand dispatch.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::{CommandFactory, Parser, Subcommand};
use ipnet::IpNet;
use serde::Serialize;
use tokio_stream::StreamExt;

use crate::auth::Authorization;
use crate::browse::{Browser, Event};
use crate::error::Result as WhResult;
use crate::flood::{self, FloodOptions};
use crate::mode::Mode;
use crate::output::{
    ColorMode, Renderer, emit_browse_event, emit_host_answers, emit_host_enumeration,
    emit_instance, emit_neighbor_entries, emit_sweep_results,
};
use crate::probe::{self, ProbeOptions};
use crate::spoof::{MonitorBlockReason, MonitorEvent, ReplyMode};
use crate::spoof_template::{self, Template};
use crate::types::{Protocol, ServiceType};

#[derive(Parser, Debug)]
#[command(
    name = "whodis",
    version,
    about = "mDNS / Bonjour recon and spoof",
    long_about = "whodis: ask the LAN \"who is this\" and (sometimes) lie about the answer.\n\
                  See `whodis <command> --help` for details on each command."
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "flags map 1:1 to CLI bool options; a state machine would obscure intent"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,

    /// Path to a TOML scope file (also via `WHODIS_SCOPE` env). Pre-populates
    /// allow-list for spoof and flood.
    #[arg(global = true, long, value_name = "FILE", env = "WHODIS_SCOPE")]
    pub scope: Option<std::path::PathBuf>,

    #[arg(global = true, long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,

    #[arg(global = true, long, conflicts_with = "no_pretty")]
    pub pretty: bool,

    #[arg(global = true, long = "no-pretty")]
    pub no_pretty: bool,

    #[arg(global = true, short = 'q', long)]
    pub quiet: bool,

    #[arg(global = true, short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Restrict operations to a single network interface (e.g. en0). Repeatable.
    /// Default: all non-loopback interfaces.
    #[arg(global = true, short = 'i', long = "interface", value_name = "NAME")]
    pub interface: Vec<String>,

    /// Disable the mDNSResponder (`dns_sd`) fallback for known Apple service types.
    /// When set, probe only uses wire-level mDNS even if no results are found.
    #[arg(global = true, long = "no-dns-sd")]
    pub no_dns_sd: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl From<ColorChoice> for ColorMode {
    fn from(value: ColorChoice) -> Self {
        match value {
            ColorChoice::Auto => Self::Auto,
            ColorChoice::Always => Self::Always,
            ColorChoice::Never => Self::Never,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Watch the LAN for mDNS or SSDP announcements.
    Browse {
        #[arg(short = 't', long, default_value_t = 0)]
        timeout: u64,

        /// Tag each instance with a vendor/product guess. mDNS-only.
        #[arg(short = 'f', long, conflicts_with = "ssdp")]
        fingerprint: bool,

        /// Run for a 5-second window then exit. -t overrides the window.
        #[arg(long = "once", short = '1')]
        once: bool,

        /// Filter events to a specific service-type fqdn (e.g. `_airplay._tcp.local.`). mDNS-only.
        #[arg(
            short = 'T',
            long = "type",
            value_name = "FQDN",
            conflicts_with = "ssdp"
        )]
        service_type: Option<String>,

        /// Browse `SSDP` / `UPnP` (multicast 239.255.255.250:1900) instead of `mDNS`.
        #[arg(long)]
        ssdp: bool,
    },

    /// Send a directed mDNS or SSDP query. Without args, lists mDNS service types on the LAN.
    Probe {
        /// mDNS service-type fqdn (e.g. `_airplay._tcp.local.`) or SSDP ST URN
        /// (e.g. `urn:schemas-upnp-org:device:MediaRenderer:1`) when `--ssdp` is set.
        /// Omit for mDNS service-type discovery.
        service: Option<String>,

        #[arg(long, conflicts_with = "ssdp")]
        instance: Option<String>,

        #[arg(long, conflicts_with = "ssdp")]
        host: Option<String>,

        /// Timeout in seconds. Default: 3s for targeted queries, 8s for discovery (no positional arg).
        #[arg(short = 't', long)]
        timeout: Option<u64>,

        /// Probe `SSDP` / `UPnP` instead of `mDNS`. The positional argument is the ST URN.
        #[arg(long)]
        ssdp: bool,

        /// SSDP M-SEARCH MX wait value (seconds). Only meaningful with --ssdp.
        #[arg(long, default_value_t = 3, requires = "ssdp")]
        mx: u32,
    },

    /// Enumerate every service a single host advertises. Without args, lists hosts on the LAN.
    Enum {
        /// Hostname to enumerate, e.g. `BedroomTV.local.`. Omit to discover hosts.
        host: Option<String>,

        /// Timeout in seconds. Default: 5s for targeted queries, 8s for discovery (no positional arg).
        #[arg(short = 't', long)]
        timeout: Option<u64>,
    },

    /// Read the kernel ARP/NDP caches and show neighbors with OUI vendor lookup.
    Arp {
        /// Show only IPv4 neighbors.
        #[arg(long)]
        v4: bool,

        /// Show only IPv6 neighbors.
        #[arg(long)]
        v6: bool,

        /// Case-insensitive substring match on vendor name.
        #[arg(long, value_name = "VENDOR")]
        vendor: Option<String>,

        /// Skip OUI vendor lookup.
        #[arg(long)]
        no_oui: bool,
    },

    /// Sweep a CIDR block with ICMP echo to discover live IPv4 hosts. No root required.
    Sweep {
        /// CIDR block to sweep (IPv4 only), e.g. `192.168.1.0/24`. Defaults to the /24 of the
        /// primary non-loopback IPv4 interface (or the one named via `-i`).
        cidr: Option<ipnet::Ipv4Net>,

        /// Per-probe timeout in milliseconds.
        #[arg(short = 't', long, default_value_t = 500)]
        timeout: u64,

        /// Maximum concurrent probes. 0 means unbounded (advanced; watch fd limits).
        #[arg(long, default_value_t = 256)]
        max: usize,

        /// Skip MAC / vendor enrichment from ARP cache.
        #[arg(long)]
        no_arp: bool,

        /// Keep MAC enrichment but skip OUI vendor lookup.
        #[arg(long)]
        no_oui: bool,

        /// Also emit records for unreachable (dead) hosts.
        #[arg(long)]
        show_dead: bool,
    },

    /// Watch the LAN for mDNS spoofing signatures. Listen-only.
    Watch {
        /// Watch window in seconds. 0 = until Ctrl-C.
        #[arg(short = 't', long, default_value_t = 0)]
        timeout: u64,

        /// Also observe traffic from local interface IPs. Off by default so
        /// legitimate local mDNS announces don't drown the output. Turn on to
        /// dogfood `watch` against your own `flood`/`spoof` running on the same host.
        #[arg(long = "include-local")]
        include_local: bool,
    },

    /// Capture mDNS traffic to a pcap file.
    Capture {
        /// Output pcap file path. Defaults to `mdns-{timestamp}.pcap` in the current
        /// directory, or in `scope.log_dir` if set.
        #[arg(long, value_name = "FILE")]
        pcap: Option<std::path::PathBuf>,

        /// Capture window in seconds. 0 = until Ctrl-C.
        #[arg(short = 't', long, default_value_t = 0)]
        timeout: u64,
    },

    /// Run an authoritative mDNS or SSDP responder against the given TOML answer table.
    Spoof {
        /// Path to a TOML answer table. Optional when --template is given.
        #[arg(value_name = "TABLE", required_unless_present = "template")]
        table: Option<std::path::PathBuf>,

        /// Built-in service template. Requires --name and --ip. mDNS-only.
        #[arg(long, value_enum, requires = "name", requires_all = ["name", "ip"], conflicts_with = "ssdp")]
        template: Option<Template>,

        /// Instance name for the template (e.g. "Conf Room"). mDNS-only.
        #[arg(long, requires = "template")]
        name: Option<String>,

        /// IPv4 address for the template A record. mDNS-only.
        #[arg(long, requires = "template")]
        ip: Option<Ipv4Addr>,

        #[arg(long, default_value_t = 3, conflicts_with = "ssdp")]
        burst: u8,

        #[arg(long = "allow", value_name = "CIDR")]
        allow: Vec<IpNet>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        /// Bridge inbound TCP on spoofed ports to HOST:PORT (full MITM). mDNS-only.
        #[arg(long, value_name = "HOST:PORT", conflicts_with = "ssdp")]
        relay: Option<SocketAddr>,

        /// Where spoof answers are sent. mDNS-only.
        #[arg(long, value_enum, default_value_t = ReplyMode::Multicast, conflicts_with = "ssdp")]
        reply: ReplyMode,

        /// Periodically push our spoofed records into client caches.
        /// 0 means only reply to incoming queries (default).
        #[arg(long, value_name = "SECS", default_value_t = 0)]
        reannounce_interval: u64,

        /// Passive dry-run: report matching queries and conflicts without answering. mDNS-only.
        #[arg(long, conflicts_with = "ssdp")]
        monitor: bool,

        /// Window in seconds. 0 = until Ctrl-C.
        #[arg(short = 't', long, default_value_t = 0)]
        timeout: u64,

        /// Run as an `SSDP` / `UPnP` responder instead of `mDNS`. Interprets `TABLE`
        /// as an SSDP TOML schema (see docs).
        #[arg(long)]
        ssdp: bool,

        /// LOCATION URL host (advertised IPv4) for SSDP responses. Defaults to the
        /// first non-loopback interface IP. SSDP-only.
        #[arg(long, value_name = "IP", requires = "ssdp")]
        http_host: Option<Ipv4Addr>,
    },

    /// Capture a real LAN device and emit a TOML answer table mimicking it.
    Clone {
        /// mDNS instance fqdn (e.g. `LivingRoomTV._airplay._tcp.local.`) or, with
        /// `--ssdp`, an `SSDP` USN (e.g. `uuid:abc::urn:schemas-upnp-org:device:MediaRenderer:1`).
        instance: String,

        /// Listen window in seconds. Exits non-zero if no records arrive in time.
        #[arg(short = 't', long, default_value_t = 5)]
        timeout: u64,

        /// Clone an `SSDP` / `UPnP` device. The positional argument is the USN.
        /// Fetches the device's LOCATION URL and embeds the description XML
        /// in the emitted TOML.
        #[arg(long)]
        ssdp: bool,
    },

    /// Send goodbye or conflict-rename floods. Disruptive.
    Flood {
        #[command(subcommand)]
        kind: FloodCmd,
    },

    /// Generate a Markdown engagement report.
    Report {
        /// Output Markdown file path. If --scope sets `log_dir`, path is relative to it.
        #[arg(long, value_name = "FILE", default_value = "engagement.md")]
        out: std::path::PathBuf,

        /// Inventory window in seconds (default 10).
        #[arg(short = 't', long, default_value_t = 10)]
        timeout: u64,
    },

    /// Print shell completions for the given shell to stdout.
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand, Debug)]
pub enum FloodCmd {
    Goodbye {
        #[arg(value_name = "INSTANCE")]
        targets: Vec<String>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50, value_parser = parse_positive_u32)]
        rate: u32,

        #[arg(long, default_value_t = 1, conflicts_with = "forever", value_parser = parse_positive_usize)]
        count: usize,

        #[arg(long)]
        forever: bool,

        #[arg(long)]
        dry_run: bool,
    },
    Conflict {
        #[arg(value_name = "INSTANCE")]
        targets: Vec<String>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50, value_parser = parse_positive_u32)]
        rate: u32,

        #[arg(long, default_value_t = 1, conflicts_with = "forever", value_parser = parse_positive_usize)]
        count: usize,

        #[arg(long)]
        forever: bool,

        #[arg(long)]
        dry_run: bool,
    },
    /// Discover all instances of a service type then flood TTL=0 goodbyes for each,
    /// clearing the type from clients' Bonjour pickers. Disruptive.
    GoodbyeType {
        /// Service type fqdn, e.g. `_googlecast._tcp.local.`.
        #[arg(value_name = "SERVICE")]
        service: String,

        /// Seconds to listen for instances of the service type before flooding.
        #[arg(long, default_value_t = 3, value_parser = parse_positive_u64)]
        discovery_window: u64,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50, value_parser = parse_positive_u32)]
        rate: u32,

        #[arg(long, default_value_t = 1, conflicts_with = "forever", value_parser = parse_positive_usize)]
        count: usize,

        #[arg(long)]
        forever: bool,

        #[arg(long)]
        dry_run: bool,
    },
    /// Flood A records claiming a `.local` hostname, poisoning client caches so the host
    /// resolves to a sinkhole IP. Optionally also poisons AAAA via --ip6. Disruptive.
    ConflictHost {
        #[arg(value_name = "HOST")]
        targets: Vec<String>,

        /// Sinkhole IPv4 address that targeted hosts will resolve to.
        #[arg(long, value_name = "IP")]
        ip: Ipv4Addr,

        /// Optional sinkhole IPv6 address. When given, an AAAA record with the
        /// cache-flush bit is added to the same response packet alongside the A.
        #[arg(long, value_name = "IP6")]
        ip6: Option<Ipv6Addr>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50, value_parser = parse_positive_u32)]
        rate: u32,

        #[arg(long, default_value_t = 1, conflicts_with = "forever", value_parser = parse_positive_usize)]
        count: usize,

        #[arg(long)]
        forever: bool,

        #[arg(long)]
        dry_run: bool,
    },
    /// Send SSDP `NOTIFY ssdp:byebye` messages, telling `UPnP` controllers a device
    /// is gone. Disruptive.
    Byebye {
        /// Full SSDP USN, e.g. `uuid:abc123::urn:schemas-upnp-org:service:WANIPConnection:1`.
        #[arg(long)]
        usn: String,

        /// SSDP NT (notification target). For an IGD: `urn:schemas-upnp-org:service:WANIPConnection:1`.
        #[arg(long)]
        nt: String,

        #[arg(long = "allow-instance", value_name = "UUID")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50, value_parser = parse_positive_u32)]
        rate: u32,

        #[arg(long, default_value_t = 1, conflicts_with = "forever", value_parser = parse_positive_usize)]
        count: usize,

        #[arg(long)]
        forever: bool,

        #[arg(long)]
        dry_run: bool,
    },
}

fn parse_positive_u32(s: &str) -> std::result::Result<u32, String> {
    let value = s
        .parse::<u32>()
        .map_err(|e| format!("expected positive integer: {e}"))?;
    if value == 0 {
        return Err("must be at least 1".to_string());
    }
    Ok(value)
}

fn parse_positive_usize(s: &str) -> std::result::Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|e| format!("expected positive integer: {e}"))?;
    if value == 0 {
        return Err("must be at least 1".to_string());
    }
    Ok(value)
}

fn parse_positive_u64(s: &str) -> std::result::Result<u64, String> {
    let value = s
        .parse::<u64>()
        .map_err(|e| format!("expected positive integer: {e}"))?;
    if value == 0 {
        return Err("must be at least 1".to_string());
    }
    Ok(value)
}

fn default_capture_filename() -> PathBuf {
    let now = SystemTime::now();
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let when = time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(0))
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let filename = format!(
        "mdns-{:04}-{:02}-{:02}T{:02}-{:02}-{:02}Z.pcap",
        when.year(),
        u8::from(when.month()),
        when.day(),
        when.hour(),
        when.minute(),
        when.second()
    );
    PathBuf::from(filename)
}

fn resolve_capture_path(pcap: Option<PathBuf>, scope: Option<&crate::scope::Scope>) -> PathBuf {
    let path = pcap.unwrap_or_else(default_capture_filename);
    if path.is_absolute() {
        return path;
    }
    let Some(dir) = scope.and_then(crate::scope::Scope::log_dir) else {
        return path;
    };
    std::fs::create_dir_all(dir).ok();
    dir.join(path)
}

#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "run is a dispatch table over Cmd variants; splitting adds noise"
)]
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    init_tracing(cli.quiet, cli.verbose);
    if !cli.interface.is_empty() {
        crate::transport::set_interface_filter(cli.interface.clone());
    }
    let renderer = pick_renderer(&cli);
    let scope = match cli.scope.as_deref() {
        Some(p) => Some(crate::scope::Scope::load(p)?),
        None => None,
    };
    match cli.command {
        Cmd::Browse {
            timeout,
            fingerprint,
            once,
            service_type,
            ssdp,
        } => {
            if ssdp {
                run_ssdp_browse(renderer, timeout, once).await?;
            } else {
                run_browse(renderer, timeout, fingerprint, once, service_type).await?;
            }
        }
        Cmd::Probe {
            service,
            instance,
            host,
            timeout,
            ssdp,
            mx,
        } => {
            if ssdp {
                let st = service.context("--ssdp probe requires an ST URN positional argument")?;
                run_ssdp_probe(renderer, &st, timeout.unwrap_or(3), mx).await?;
            } else {
                let extras: Vec<String> = scope
                    .as_ref()
                    .map(|s| s.apple_services().to_vec())
                    .unwrap_or_default();
                run_probe(
                    renderer,
                    service,
                    instance,
                    host,
                    timeout,
                    cli.no_dns_sd,
                    extras,
                )
                .await?;
            }
        }
        Cmd::Spoof {
            table,
            template,
            name,
            ip,
            burst,
            allow,
            allow_instance,
            relay,
            reply,
            reannounce_interval,
            monitor,
            timeout,
            ssdp,
            http_host,
        } => {
            if ssdp {
                let table_path =
                    table.context("--ssdp spoof requires a TABLE positional argument")?;
                run_ssdp_spoof(
                    renderer,
                    &table_path,
                    http_host,
                    if reannounce_interval == 0 {
                        None
                    } else {
                        Some(Duration::from_secs(reannounce_interval))
                    },
                    timeout,
                    allow,
                    allow_instance,
                    scope,
                )
                .await?;
            } else {
                run_spoof(
                    renderer,
                    table,
                    template,
                    name,
                    ip,
                    burst,
                    allow,
                    allow_instance,
                    relay,
                    reply,
                    reannounce_interval,
                    monitor,
                    timeout,
                    scope,
                )
                .await?;
            }
        }
        Cmd::Enum { host, timeout } => {
            // If no positional arg and no explicit timeout, use 8s for discovery; otherwise use defaults.
            let effective_timeout = if host.is_none() {
                timeout.unwrap_or(8)
            } else {
                timeout.unwrap_or(5)
            };
            let opts = ProbeOptions {
                timeout: Duration::from_secs(effective_timeout),
            };
            if let Some(host) = host {
                let result = probe::enum_host(&host, &opts).await?;
                emit_host_enumeration(renderer, &result)?;
            } else {
                let summaries = probe::discover_hosts(&opts).await?;
                crate::output::emit_host_summaries(renderer, &summaries)?;
            }
        }
        Cmd::Clone {
            instance,
            timeout,
            ssdp,
        } => {
            let dur = std::time::Duration::from_secs(timeout);
            if ssdp {
                let cloned = crate::ssdp::clone_device(&instance, dur).await?;
                crate::output::emit_raw(&cloned.to_toml())?;
            } else {
                let cloned = crate::clone::clone_instance(&instance, dur).await?;
                crate::output::emit_raw(&cloned.to_toml())?;
            }
        }
        Cmd::Flood { kind } => run_flood(kind, scope).await?,
        Cmd::Watch {
            timeout,
            include_local,
        } => run_watch(renderer, timeout, include_local).await?,
        Cmd::Capture { pcap, timeout } => {
            let pcap = resolve_capture_path(pcap, scope.as_ref());
            let count = crate::capture::run(&pcap, timeout).await?;
            tracing::info!(packets = count, file = %pcap.display(), "capture complete");
        }
        Cmd::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            let mut out: Vec<u8> = Vec::new();
            clap_complete::generate(shell, &mut cmd, bin, &mut out);
            let s = std::str::from_utf8(&out)
                .map_err(|e| anyhow::anyhow!("completions not utf-8: {e}"))?;
            crate::output::emit_raw(s)?;
        }
        Cmd::Report { out, timeout } => {
            // If scope.log_dir is set and `out` is relative, resolve it inside log_dir.
            let out = if out.is_relative() {
                scope.as_ref().map_or_else(
                    || out.clone(),
                    |scope_ref| {
                        scope_ref.log_dir().map_or_else(
                            || out.clone(),
                            |dir| {
                                std::fs::create_dir_all(dir).ok();
                                dir.join(&out)
                            },
                        )
                    },
                )
            } else {
                out.clone()
            };
            let count = crate::report::write(&out, timeout).await?;
            tracing::info!(instances = count, file = %out.display(), "report written");
        }
        Cmd::Arp {
            v4,
            v6,
            vendor,
            no_oui,
        } => run_arp(renderer, scope, v4, v6, vendor, no_oui).await?,
        Cmd::Sweep {
            cidr,
            timeout,
            max,
            no_arp,
            no_oui,
            show_dead,
        } => {
            let final_cidr = if let Some(c) = cidr {
                c
            } else {
                let derived = derive_local_v4_subnet(&cli.interface).context(
                    "no CIDR given and no local IPv4 interface found; pass a CIDR explicitly",
                )?;
                tracing::info!(cidr = %derived, "no CIDR given, sweeping local /24");
                derived
            };
            run_sweep(
                renderer, scope, final_cidr, timeout, max, no_arp, no_oui, show_dead,
            )
            .await?;
        }
    }
    Ok(())
}

fn pick_renderer(cli: &Cli) -> Renderer {
    let color: ColorMode = cli.color.into();
    if cli.pretty {
        return Renderer::Pretty(color);
    }
    if cli.no_pretty {
        return Renderer::Jsonl;
    }
    if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        Renderer::Pretty(color)
    } else {
        Renderer::Jsonl
    }
}

fn init_tracing(quiet: bool, verbose: u8) {
    use tracing_subscriber::{EnvFilter, fmt};

    let level = if quiet {
        "error"
    } else {
        match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .ok();
}

fn event_matches_filter(event: &Event, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter = filter.trim_end_matches('.').to_ascii_lowercase();
    match event {
        Event::ServiceTypeFound { service_type } => {
            service_type
                .fqdn()
                .trim_end_matches('.')
                .to_ascii_lowercase()
                == filter
        }
        Event::InstanceFound { instance } | Event::InstanceUpdated { instance } => {
            instance
                .service_type
                .fqdn()
                .trim_end_matches('.')
                .to_ascii_lowercase()
                == filter
        }
        Event::InstanceGoodbye { fqdn } => fqdn.to_ascii_lowercase().contains(&filter),
    }
}

async fn run_browse(
    renderer: Renderer,
    timeout: u64,
    fingerprint: bool,
    once: bool,
    service_type_filter: Option<String>,
) -> anyhow::Result<()> {
    let effective_timeout = if timeout > 0 {
        timeout
    } else if once {
        5
    } else {
        0
    };

    let browser = Browser::new(Mode::Listen).context("starting browser")?;
    let cancel = browser.cancel_token();
    let stream = browser.run();

    let task = tokio::spawn(async move {
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            if !event_matches_filter(&event, service_type_filter.as_deref()) {
                continue;
            }
            let fp = if fingerprint {
                match &event {
                    Event::InstanceFound { instance } | Event::InstanceUpdated { instance } => {
                        crate::fingerprint::identify(instance)
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let Err(e) = emit_browse_event(renderer, &event, fp.as_ref()) {
                tracing::error!(error = %e, "emit failed");
                break;
            }
        }
    });

    if effective_timeout > 0 {
        tokio::time::sleep(Duration::from_secs(effective_timeout)).await;
    } else {
        tokio::signal::ctrl_c().await.ok();
    }
    cancel.cancel();
    if let Err(e) = task.await {
        tracing::debug!(error = %e, "browse task ended");
    }
    Ok(())
}

async fn run_ssdp_browse(renderer: Renderer, timeout: u64, once: bool) -> anyhow::Result<()> {
    let effective = if timeout > 0 {
        timeout
    } else if once {
        5
    } else {
        0
    };
    let stream = crate::ssdp::browse(Duration::from_secs(effective))?;
    tokio::pin!(stream);
    let deadline = if effective > 0 {
        Some(tokio::time::Instant::now() + Duration::from_secs(effective))
    } else {
        None
    };
    loop {
        tokio::select! {
            event = stream.next() => {
                match event {
                    Some(e) => {
                        if let Err(err) = emit_ssdp_event(renderer, &e) {
                            tracing::error!(error = %err, "emit failed");
                            break;
                        }
                    }
                    None => break,
                }
            }
            () = sleep_until_or_pending(deadline) => break,
            r = tokio::signal::ctrl_c() => {
                drop(r);
                break;
            }
        }
    }
    Ok(())
}

async fn sleep_until_or_pending(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

async fn run_ssdp_probe(renderer: Renderer, st: &str, timeout: u64, mx: u32) -> anyhow::Result<()> {
    let opts = crate::ssdp::SsdpProbeOptions {
        timeout: Duration::from_secs(timeout),
        mx,
        target_override: None,
    };
    let devices = crate::ssdp::probe(st, &opts).await?;
    for d in devices {
        emit_ssdp_device(renderer, &d)?;
    }
    Ok(())
}

fn emit_ssdp_event(renderer: Renderer, event: &crate::ssdp::SsdpEvent) -> std::io::Result<()> {
    match renderer {
        Renderer::Jsonl => crate::output::emit_jsonl(event),
        Renderer::Pretty(color) => emit_ssdp_event_pretty(color, event),
    }
}

fn emit_ssdp_device(renderer: Renderer, device: &crate::ssdp::SsdpDevice) -> std::io::Result<()> {
    match renderer {
        Renderer::Jsonl => crate::output::emit_jsonl(device),
        Renderer::Pretty(color) => emit_ssdp_device_pretty(color, device),
    }
}

fn emit_ssdp_event_pretty(color: ColorMode, event: &crate::ssdp::SsdpEvent) -> std::io::Result<()> {
    let on = color.enabled();
    let line = match event {
        crate::ssdp::SsdpEvent::Alive { device, src } => {
            format!(
                "{}  {}  {}  src={}\n",
                paint_ssdp(on, "ssdp alive  ", "\x1b[32m"),
                device.usn,
                device.st,
                src
            )
        }
        crate::ssdp::SsdpEvent::Byebye { usn, nt, src } => {
            format!(
                "{}  {}  {}  src={}\n",
                paint_ssdp(on, "ssdp byebye ", "\x1b[33m"),
                usn,
                nt,
                src
            )
        }
        crate::ssdp::SsdpEvent::Reply { device, src } => {
            format!(
                "{}  {}  {}  src={}\n",
                paint_ssdp(on, "ssdp reply  ", "\x1b[36m"),
                device.usn,
                device.st,
                src
            )
        }
    };
    crate::output::emit_raw(&line)
}

fn emit_ssdp_device_pretty(
    color: ColorMode,
    device: &crate::ssdp::SsdpDevice,
) -> std::io::Result<()> {
    let on = color.enabled();
    let loc = device.location.as_deref().unwrap_or("-");
    crate::output::emit_raw(&format!(
        "{}  {}  {}  loc={}\n",
        paint_ssdp(on, "ssdp device", "\x1b[36m"),
        device.usn,
        device.st,
        loc,
    ))
}

fn paint_ssdp(enabled: bool, body: &str, color: &str) -> String {
    if enabled {
        format!("{color}{body}\x1b[0m")
    } else {
        body.to_string()
    }
}

#[allow(
    clippy::cognitive_complexity,
    reason = "probe dispatch branches across host/service/instance paths"
)]
async fn run_probe(
    renderer: Renderer,
    service: Option<String>,
    instance: Option<String>,
    host: Option<String>,
    timeout: Option<u64>,
    no_dns_sd: bool,
    extra_apple_services: Vec<String>,
) -> anyhow::Result<()> {
    // If no positional arg and no explicit timeout, use 8s for discovery; otherwise use defaults.
    let effective_timeout = if service.is_none() && host.is_none() {
        timeout.unwrap_or(8)
    } else {
        timeout.unwrap_or(3)
    };
    let opts = ProbeOptions {
        timeout: Duration::from_secs(effective_timeout),
    };
    if let Some(h) = host {
        let answers = probe::probe_host(&h, &opts).await?;
        emit_host_answers(renderer, &answers)?;
        return Ok(());
    }
    let Some(service) = service else {
        let summaries = probe::discover_service_types(&opts).await?;
        crate::output::emit_service_type_summaries(renderer, &summaries)?;
        return Ok(());
    };
    let svc = parse_service(&service)?;
    let instances = if let Some(name) = instance {
        probe::probe_instance(&name, &svc, &opts).await?
    } else {
        probe::probe_service(&svc, &opts, no_dns_sd, &extra_apple_services).await?
    };
    for inst in instances {
        let fp = crate::fingerprint::identify(&inst);
        emit_instance(renderer, &inst, fp.as_ref())?;
    }
    Ok(())
}

#[allow(
    clippy::similar_names,
    reason = "names match CLI flag spelling: allow vs allow_instance"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "all args map 1:1 to CLI flags; splitting into a struct would obscure the relationship"
)]
async fn run_spoof(
    renderer: Renderer,
    mut table_path: Option<std::path::PathBuf>,
    template: Option<Template>,
    name: Option<String>,
    ip: Option<Ipv4Addr>,
    burst: u8,
    allow: Vec<IpNet>,
    allow_instance: Vec<String>,
    relay: Option<SocketAddr>,
    reply: ReplyMode,
    reannounce_interval: u64,
    mut monitor: bool,
    timeout: u64,
    scope: Option<crate::scope::Scope>,
) -> anyhow::Result<()> {
    if template.is_none()
        && table_path
            .as_deref()
            .is_some_and(|path| path == std::path::Path::new("verify"))
    {
        return crate::spoof_verify::run(renderer).await;
    }
    if table_path
        .as_deref()
        .is_some_and(|path| path == std::path::Path::new("monitor"))
    {
        monitor = true;
        table_path = None;
    }

    let table = if let Some(tmpl) = template {
        if table_path.is_some() {
            tracing::warn!("--template and TABLE both given; --template takes precedence");
        }
        let tmpl_name = name.as_deref().context("--name required with --template")?;
        let tmpl_ip = ip.context("--ip required with --template")?;
        spoof_template::build(tmpl, tmpl_name, tmpl_ip)?
    } else {
        let path = table_path.context("TABLE required when --template is not given")?;
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        crate::spoof_table::load(&raw)?
    };
    let auth = if let Some(s) = scope {
        s.into_auth(allow, allow_instance)
    } else {
        let mut a = Authorization::new();
        for cidr in allow {
            a = a.allow_subnet(cidr);
        }
        for inst_name in allow_instance {
            a = a.allow_instance(inst_name);
        }
        a
    };
    if monitor {
        return run_spoof_monitor(renderer, table, auth, timeout).await;
    }
    let ports = table.srv_ports().to_vec();
    let interval = if reannounce_interval == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(reannounce_interval))
    };
    let resp =
        crate::spoof::Responder::new(Mode::Authoritative, auth, table, burst, reply, interval)?;
    let cancel = resp.cancel_token();
    if let Some(target) = relay {
        crate::relay::run(&ports, target, cancel.clone()).await?;
    }
    let task = tokio::spawn(async move { resp.run().await });
    tokio::signal::ctrl_c().await.ok();
    cancel.cancel();
    if let Err(e) = task.await {
        tracing::debug!(error = %e, "spoof task ended");
    }
    Ok(())
}

async fn run_watch(renderer: Renderer, timeout: u64, include_local: bool) -> anyhow::Result<()> {
    let detector = crate::detect::Detector::new(Mode::Listen)?
        .with_include_local(include_local)
        .with_event_callback(move |a| {
            if let Err(e) = emit_anomaly(renderer, &a) {
                tracing::error!(error = %e, "emit failed");
            }
        });
    let cancel = detector.cancel_token();
    let task = tokio::spawn(async move { detector.run().await });
    if timeout > 0 {
        tokio::time::sleep(Duration::from_secs(timeout)).await;
    } else {
        tokio::signal::ctrl_c().await.ok();
    }
    cancel.cancel();
    task.await
        .map_err(|e| anyhow::anyhow!("watch task failed: {e}"))??;
    Ok(())
}

#[derive(Debug, Serialize)]
struct AnomalyRecord<'a> {
    kind: &'static str,
    severity: &'static str,
    #[serde(flatten)]
    body: &'a crate::detect::Anomaly,
}

fn emit_anomaly(renderer: Renderer, anomaly: &crate::detect::Anomaly) -> std::io::Result<()> {
    let record = AnomalyRecord {
        kind: "anomaly",
        severity: anomaly.severity(),
        body: anomaly,
    };
    match renderer {
        Renderer::Jsonl => crate::output::emit_jsonl(&record),
        Renderer::Pretty(color) => emit_anomaly_pretty(color, &record),
    }
}

fn emit_anomaly_pretty(color: ColorMode, record: &AnomalyRecord<'_>) -> std::io::Result<()> {
    let on = color.enabled();
    let chip = match record.severity {
        "high" => paint_anomaly(on, "anomaly high  ", "\x1b[31m"),
        "medium" => paint_anomaly(on, "anomaly medium", "\x1b[33m"),
        _ => paint_anomaly(on, "anomaly       ", "\x1b[36m"),
    };
    let detail = match record.body {
        crate::detect::Anomaly::MultiSourceUniqueRr {
            name,
            qtype,
            sources,
        } => {
            let parts: Vec<String> = sources
                .iter()
                .map(|s| format!("{}={}", s.src, s.rdata))
                .collect();
            format!(
                "multi_source_unique_rr {qtype:<5} {name}  [{}]",
                parts.join(", ")
            )
        }
        crate::detect::Anomaly::WhodisConflictSignature { name, qtype, src } => {
            format!("whodis_conflict_signature {qtype:<5} {name}  src={src}")
        }
        crate::detect::Anomaly::CacheFlushRateExceeded {
            name,
            qtype,
            src,
            per_sec,
        } => {
            format!("cache_flush_rate_exceeded {qtype:<5} {name}  src={src} ({per_sec}/s)")
        }
        crate::detect::Anomaly::GoodbyeStorm { name, src, count } => {
            format!("goodbye_storm       -     {name}  src={src} ({count} in window)")
        }
        crate::detect::Anomaly::GoodbyeThenTakeover {
            name,
            qtype,
            src_goodbye,
            src_takeover,
        } => {
            format!(
                "goodbye_then_takeover {qtype:<5} {name}  goodbye={src_goodbye} -> takeover={src_takeover}"
            )
        }
        crate::detect::Anomaly::ServiceTypeGoodbyeBurst {
            service_type,
            src,
            instance_count,
        } => {
            format!(
                "service_type_goodbye_burst PTR   {service_type}  src={src} ({instance_count} instances)"
            )
        }
        crate::detect::Anomaly::SourceIpMismatch {
            name,
            qtype,
            src,
            advertised,
        } => {
            format!("source_ip_mismatch  {qtype:<5} {name}  src={src} -> advertised={advertised}")
        }
        crate::detect::Anomaly::UnsolicitedAdditional { name, qtype, src } => {
            format!("unsolicited_additional {qtype:<5} {name}  src={src}")
        }
        crate::detect::Anomaly::LlmnrPoisonResponder { name, src } => {
            format!("llmnr_poison_responder  -     {name}  src={src}")
        }
    };
    crate::output::emit_raw(&format!("{chip}  {detail}\n"))
}

fn paint_anomaly(enabled: bool, body: &str, color: &str) -> String {
    if enabled {
        format!("{color}{body}\x1b[0m")
    } else {
        body.to_string()
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "all args map 1:1 to CLI flags; splitting into a struct would obscure the relationship"
)]
async fn run_ssdp_spoof(
    _renderer: Renderer,
    table_path: &std::path::Path,
    http_host: Option<Ipv4Addr>,
    reannounce: Option<Duration>,
    timeout: u64,
    allow: Vec<IpNet>,
    allow_instance: Vec<String>,
    scope: Option<crate::scope::Scope>,
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(table_path)
        .with_context(|| format!("reading {}", table_path.display()))?;
    let table = crate::ssdp_table::load(&raw)?;
    let host = match http_host {
        Some(h) => h,
        None => derive_local_v4_ip().context(
            "no --http-host given and no non-loopback IPv4 interface found; pass --http-host explicitly",
        )?,
    };
    let auth = if let Some(s) = scope {
        s.into_auth(allow, allow_instance)
    } else {
        let mut a = Authorization::new();
        for cidr in allow {
            a = a.allow_subnet(cidr);
        }
        for inst_name in allow_instance {
            a = a.allow_instance(inst_name);
        }
        a
    };
    let responder = crate::ssdp::SsdpResponder::new(auth, table, host, reannounce)?;
    let cancel = responder.cancel_token();
    let mut task = tokio::spawn(async move { responder.run().await });

    // Race the task against the timeout / Ctrl-C so an early-exit (e.g. HTTP
    // bind failure on macOS port 5000) surfaces as an error instead of being
    // hidden by the wait window.
    let outcome = tokio::select! {
        biased;
        r = &mut task => Some(r),
        () = wait_for_window(timeout) => None,
    };
    cancel.cancel();
    match outcome {
        Some(Ok(Ok(()))) => Ok(()),
        Some(Ok(Err(e))) => Err(e.into()),
        Some(Err(e)) => Err(anyhow::anyhow!("ssdp responder task panicked: {e}")),
        None => {
            // Timer fired first; let the task finish cleanly.
            match task.await {
                Ok(Ok(())) | Err(_) => Ok(()),
                Ok(Err(e)) => Err(e.into()),
            }
        }
    }
}

async fn wait_for_window(timeout: u64) {
    if timeout > 0 {
        tokio::time::sleep(Duration::from_secs(timeout)).await;
    } else {
        tokio::signal::ctrl_c().await.ok();
    }
}

fn derive_local_v4_ip() -> anyhow::Result<Ipv4Addr> {
    for iface in get_if_addrs::get_if_addrs().context("listing interfaces")? {
        if iface.is_loopback() {
            continue;
        }
        if let std::net::IpAddr::V4(v4) = iface.ip() {
            return Ok(v4);
        }
    }
    anyhow::bail!("no non-loopback IPv4 interface found")
}

async fn run_spoof_monitor(
    renderer: Renderer,
    table: crate::spoof::AnswerTable,
    auth: Authorization,
    timeout: u64,
) -> anyhow::Result<()> {
    let monitor =
        crate::spoof::Monitor::new(Mode::Listen, auth, table)?.with_event_callback(move |event| {
            if let Err(e) = emit_monitor_event(renderer, &event) {
                tracing::error!(error = %e, "emit failed");
            }
        });
    let cancel = monitor.cancel_token();
    let task = tokio::spawn(async move { monitor.run().await });
    if timeout > 0 {
        tokio::time::sleep(Duration::from_secs(timeout)).await;
    } else {
        tokio::signal::ctrl_c().await.ok();
    }
    cancel.cancel();
    task.await
        .map_err(|e| anyhow::anyhow!("spoof monitor task failed: {e}"))??;
    Ok(())
}

fn emit_monitor_event(renderer: Renderer, event: &MonitorEvent) -> std::io::Result<()> {
    let record = MonitorRecord::from(event);
    match renderer {
        Renderer::Jsonl => crate::output::emit_jsonl(&record),
        Renderer::Pretty(color) => emit_monitor_pretty(color, &record),
    }
}

#[derive(Debug, Serialize)]
struct MonitorRecord {
    kind: &'static str,
    src: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    qtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl From<&MonitorEvent> for MonitorRecord {
    fn from(event: &MonitorEvent) -> Self {
        match event {
            MonitorEvent::WouldAnswer { name, qtype, src } => Self {
                kind: "would_answer",
                src: src.to_string(),
                name: name.clone(),
                qtype: Some(format!("{qtype:?}")),
                target: None,
                reason: None,
            },
            MonitorEvent::Blocked {
                name,
                qtype,
                src,
                reason,
            } => Self {
                kind: "blocked",
                src: src.to_string(),
                name: name.clone(),
                qtype: Some(format!("{qtype:?}")),
                target: None,
                reason: Some(match reason {
                    MonitorBlockReason::SourceAddress => "source_address",
                    MonitorBlockReason::Instance => "instance",
                }),
            },
            MonitorEvent::Conflict { name, qtype, src } => Self {
                kind: "conflict",
                src: src.to_string(),
                name: name.clone(),
                qtype: Some(format!("{qtype:?}")),
                target: None,
                reason: None,
            },
            MonitorEvent::SharedPtr { name, target, src } => Self {
                kind: "shared_ptr",
                src: src.to_string(),
                name: name.clone(),
                qtype: Some("PTR".to_string()),
                target: Some(target.clone()),
                reason: None,
            },
        }
    }
}

fn emit_monitor_pretty(color: ColorMode, record: &MonitorRecord) -> std::io::Result<()> {
    let on = color.enabled();
    let kind = match record.kind {
        "would_answer" => paint_monitor(on, "would answer", "\x1b[32m"),
        "blocked" => paint_monitor(on, "blocked", "\x1b[33m"),
        "conflict" => paint_monitor(on, "conflict", "\x1b[31m"),
        "shared_ptr" => paint_monitor(on, "shared ptr", "\x1b[34m"),
        other => other.to_string(),
    };
    let qtype = record.qtype.as_deref().unwrap_or("-");
    let detail = record.target.as_ref().map_or_else(
        || {
            record
                .reason
                .map_or_else(String::new, |reason| format!(" ({reason})"))
        },
        |target| format!(" -> {target}"),
    );
    crate::output::emit_raw(&format!(
        "{kind:<16} {:<5} {}  src={}{}\n",
        qtype, record.name, record.src, detail
    ))
}

fn paint_monitor(enabled: bool, body: &str, color: &str) -> String {
    if enabled {
        format!("{color}{body}\x1b[0m")
    } else {
        body.to_string()
    }
}

#[allow(
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    reason = "FloodCmd must be owned to destructure in match arms; one arm per variant is unavoidable"
)]
async fn run_flood(kind: FloodCmd, scope: Option<crate::scope::Scope>) -> anyhow::Result<()> {
    use std::num::NonZeroU32;

    let sent = match kind {
        FloodCmd::Goodbye {
            targets,
            allow_instance,
            rate,
            count,
            forever,
            dry_run,
        } => {
            let auth = build_auth(allow_instance, scope);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
                count: if forever { 0 } else { count },
                dry_run,
            };
            flood::goodbye(Mode::Authoritative, &targets, &auth, opts).await?
        }
        FloodCmd::Conflict {
            targets,
            allow_instance,
            rate,
            count,
            forever,
            dry_run,
        } => {
            let auth = build_auth(allow_instance, scope);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
                count: if forever { 0 } else { count },
                dry_run,
            };
            flood::conflict_rename(Mode::Authoritative, &targets, &auth, opts).await?
        }
        FloodCmd::ConflictHost {
            targets,
            ip,
            ip6,
            allow_instance,
            rate,
            count,
            forever,
            dry_run,
        } => {
            let auth = build_auth(allow_instance, scope);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
                count: if forever { 0 } else { count },
                dry_run,
            };
            flood::conflict_host(Mode::Authoritative, &targets, ip, ip6, &auth, opts).await?
        }
        FloodCmd::GoodbyeType {
            service,
            discovery_window,
            allow_instance,
            rate,
            count,
            forever,
            dry_run,
        } => {
            let auth = build_auth(allow_instance, scope);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
                count: if forever { 0 } else { count },
                dry_run,
            };
            let sent = flood::goodbye_type(
                Mode::Authoritative,
                &service,
                Duration::from_secs(discovery_window),
                &auth,
                opts,
            )
            .await?;
            if sent == 0 {
                tracing::warn!(service = %service, "goodbye-type: no instances on the LAN to goodbye");
            } else {
                tracing::info!(sent, "flood complete");
            }
            return Ok(());
        }
        FloodCmd::Byebye {
            usn,
            nt,
            allow_instance,
            rate,
            count,
            forever,
            dry_run,
        } => {
            let auth = build_auth(allow_instance, scope);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
                count: if forever { 0 } else { count },
                dry_run,
            };
            crate::ssdp::flood_byebye(&usn, &nt, &auth, opts).await?
        }
    };
    if sent == 0 {
        anyhow::bail!("no packets sent (allow-list filtered every target)");
    }
    tracing::info!(sent, "flood complete");
    Ok(())
}

fn build_auth(allow_instance: Vec<String>, scope: Option<crate::scope::Scope>) -> Authorization {
    if let Some(s) = scope {
        s.into_auth(Vec::new(), allow_instance)
    } else {
        let mut auth = Authorization::new();
        for name in allow_instance {
            auth = auth.allow_instance(name);
        }
        auth
    }
}

async fn run_arp(
    renderer: Renderer,
    scope: Option<crate::scope::Scope>,
    v4: bool,
    v6: bool,
    vendor_filter: Option<String>,
    no_oui: bool,
) -> anyhow::Result<()> {
    use std::net::IpAddr;

    let auth = scope.map(|s| s.into_auth(Vec::new(), Vec::new()));

    let mut entries = crate::arp::read_neighbors().await?;

    // Family filter: if neither flag is set, show both
    let filter_v4 = v4 && !v6;
    let filter_v6 = v6 && !v4;
    if filter_v4 {
        entries.retain(|e| matches!(e.ip, IpAddr::V4(_)));
    } else if filter_v6 {
        entries.retain(|e| matches!(e.ip, IpAddr::V6(_)));
    }

    // Scope / authorization filter
    if let Some(ref a) = auth {
        entries.retain(|e| a.permits_addr(e.ip));
    }

    // Interface filter (already applied globally; this is belt-and-suspenders for completeness)

    // OUI vendor lookup
    if !no_oui {
        for e in &mut entries {
            e.vendor = crate::oui::lookup(e.mac).map(str::to_owned);
        }
    }

    // Vendor name substring filter
    if let Some(ref pattern) = vendor_filter {
        let pat = pattern.to_ascii_lowercase();
        entries.retain(|e| {
            e.vendor
                .as_deref()
                .is_some_and(|v| v.to_ascii_lowercase().contains(&pat))
        });
    }

    // Sort by interface then IP
    entries.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then_with(|| a.ip.to_string().cmp(&b.ip.to_string()))
    });

    emit_neighbor_entries(renderer, &entries)?;
    Ok(())
}

fn derive_local_v4_subnet(iface_filter: &[String]) -> anyhow::Result<ipnet::Ipv4Net> {
    let ifaces = get_if_addrs::get_if_addrs().context("listing interfaces")?;
    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        if !iface_filter.is_empty() && !iface_filter.iter().any(|n| n == &iface.name) {
            continue;
        }
        if let std::net::IpAddr::V4(addr) = iface.ip() {
            let octets = addr.octets();
            let net = ipnet::Ipv4Net::new(
                std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0),
                24,
            )
            .context("building /24")?;
            return Ok(net);
        }
    }
    anyhow::bail!("no non-loopback IPv4 interface found")
}

#[allow(
    clippy::too_many_arguments,
    reason = "all args map 1:1 to CLI flags; splitting into a struct would obscure the relationship"
)]
async fn run_sweep(
    renderer: Renderer,
    scope: Option<crate::scope::Scope>,
    cidr: ipnet::Ipv4Net,
    timeout_ms: u64,
    max: usize,
    no_arp: bool,
    no_oui: bool,
    show_dead: bool,
) -> anyhow::Result<()> {
    use std::collections::HashMap;
    use std::net::IpAddr;

    let auth = scope.map(|s| s.into_auth(Vec::new(), Vec::new()));

    // Warn if no scope is set (sweep is an active operation).
    let permissive = auth.as_ref().is_none_or(Authorization::is_permissive);
    if permissive {
        tracing::warn!(
            "sweeping without an engagement scope - confirm authorization. \
             pass --scope FILE or set WHODIS_SCOPE to declare targets."
        );
    }

    let opts = crate::sweep::SweepOptions {
        timeout: Duration::from_millis(timeout_ms),
        max_concurrent: max,
    };

    let probes = crate::sweep::sweep(cidr, opts).await?;

    // ARP enrichment: read neighbors once, build a lookup map.
    let neighbor_map: HashMap<IpAddr, crate::types::NeighborEntry> = if no_arp {
        HashMap::new()
    } else {
        let mut entries = crate::arp::read_neighbors().await?;
        if !no_oui {
            for e in &mut entries {
                e.vendor = crate::oui::lookup(e.mac).map(str::to_owned);
            }
        }
        entries.into_iter().map(|e| (e.ip, e)).collect()
    };

    // Build SweepResult records.
    let mut results: Vec<crate::types::SweepResult> = probes
        .into_iter()
        .filter_map(|probe| {
            let ip = IpAddr::V4(probe.ip);

            // Apply scope filter.
            if let Some(ref a) = auth
                && !a.permits_addr(ip)
            {
                return None;
            }

            if !probe.alive && !show_dead {
                return None;
            }

            let neighbor = neighbor_map.get(&ip);
            let (mac, vendor, interface) = if probe.alive {
                neighbor.map_or((None, None, None), |n| {
                    (Some(n.mac), n.vendor.clone(), Some(n.interface.clone()))
                })
            } else {
                (None, None, None)
            };

            Some(crate::types::SweepResult {
                ip,
                alive: probe.alive,
                rtt_ms: probe.rtt,
                mac,
                vendor,
                interface,
            })
        })
        .collect();

    // Sort by IP numerically.
    results.sort_by_key(|r| match r.ip {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(_) => 0,
    });

    emit_sweep_results(renderer, &results)?;
    Ok(())
}

fn parse_service(s: &str) -> WhResult<ServiceType> {
    let trimmed = s.trim_end_matches('.').trim_end_matches(".local");
    let parts: Vec<&str> = trimmed.split('.').collect();
    let n = parts.len();
    if n < 2 {
        return Err(crate::Error::InvalidServiceType(s.to_string()));
    }
    let proto = match parts.get(n - 1).copied() {
        Some("_tcp") => Protocol::Tcp,
        Some("_udp") => Protocol::Udp,
        _ => return Err(crate::Error::InvalidServiceType(s.to_string())),
    };
    let svc = (*parts
        .get(n - 2)
        .ok_or_else(|| crate::Error::InvalidServiceType(s.to_string()))?)
    .to_string();
    if !svc.starts_with('_') {
        return Err(crate::Error::InvalidServiceType(s.to_string()));
    }
    Ok(ServiceType::new(svc, proto))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_browse_subcommand() {
        let c = Cli::try_parse_from(["whodis", "browse"]).expect("parse");
        match c.command {
            Cmd::Browse { timeout, ssdp, .. } => {
                assert_eq!(timeout, 0);
                assert!(!ssdp);
            }
            other => panic!("expected Browse, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_browse_with_ssdp() {
        let c = Cli::try_parse_from(["whodis", "browse", "--ssdp"]).expect("parse");
        match c.command {
            Cmd::Browse { ssdp, .. } => assert!(ssdp),
            other => panic!("expected Browse, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_browse_ssdp_with_fingerprint() {
        let err = Cli::try_parse_from(["whodis", "browse", "--ssdp", "-f"]);
        assert!(err.is_err(), "--ssdp should conflict with --fingerprint");
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_probe_ssdp_with_urn() {
        let c = Cli::try_parse_from([
            "whodis",
            "probe",
            "urn:schemas-upnp-org:device:MediaRenderer:1",
            "--ssdp",
        ])
        .expect("parse");
        match c.command {
            Cmd::Probe {
                service, ssdp, mx, ..
            } => {
                assert_eq!(
                    service.as_deref(),
                    Some("urn:schemas-upnp-org:device:MediaRenderer:1")
                );
                assert!(ssdp);
                assert_eq!(mx, 3);
            }
            other => panic!("expected Probe, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_probe_mx_without_ssdp() {
        let err = Cli::try_parse_from(["whodis", "probe", "_airplay._tcp.local.", "--mx", "5"]);
        assert!(err.is_err(), "--mx should require --ssdp");
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_flood_byebye() {
        let c = Cli::try_parse_from([
            "whodis",
            "flood",
            "byebye",
            "--usn",
            "uuid:abc::urn:schemas-upnp-org:service:WANIPConnection:1",
            "--nt",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        ])
        .expect("parse");
        match c.command {
            Cmd::Flood {
                kind: FloodCmd::Byebye { usn, nt, .. },
            } => {
                assert!(usn.starts_with("uuid:abc::"));
                assert_eq!(nt, "urn:schemas-upnp-org:service:WANIPConnection:1");
            }
            other => panic!("expected Flood::Byebye, got {other:?}"),
        }
    }

    #[test]
    fn cli_requires_byebye_usn_and_nt() {
        let err = Cli::try_parse_from(["whodis", "flood", "byebye"]);
        assert!(err.is_err(), "byebye requires --usn and --nt");
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_probe_with_service() {
        let c = Cli::try_parse_from(["whodis", "probe", "_airplay._tcp.local."]).expect("parse");
        match c.command {
            Cmd::Probe { service, .. } => {
                assert_eq!(service.as_deref(), Some("_airplay._tcp.local."));
            }
            other => panic!("expected Probe, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_probe_without_service() {
        let c = Cli::try_parse_from(["whodis", "probe"]).expect("parse");
        match c.command {
            Cmd::Probe {
                service, timeout, ..
            } => {
                assert!(service.is_none());
                assert!(timeout.is_none());
            }
            other => panic!("expected Probe, got {other:?}"),
        }
    }

    #[test]
    fn cli_validates_color_choice() {
        let c = Cli::try_parse_from(["whodis", "--color", "always", "browse"]).expect("parse");
        assert!(matches!(c.color, ColorChoice::Always));
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_enum_subcommand() {
        let c = Cli::try_parse_from(["whodis", "enum", "BedroomTV.local."]).expect("parse");
        match c.command {
            Cmd::Enum { host, timeout } => {
                assert_eq!(host.as_deref(), Some("BedroomTV.local."));
                assert!(timeout.is_none());
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_enum_without_host() {
        let c = Cli::try_parse_from(["whodis", "enum"]).expect("parse");
        match c.command {
            Cmd::Enum { host, timeout } => {
                assert!(host.is_none());
                assert!(timeout.is_none());
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_enum_with_custom_timeout() {
        let c = Cli::try_parse_from(["whodis", "enum", "192-168-50-179.local.", "-t", "8"])
            .expect("parse");
        match c.command {
            Cmd::Enum { host, timeout } => {
                assert_eq!(host.as_deref(), Some("192-168-50-179.local."));
                assert_eq!(timeout, Some(8));
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_watch_with_include_local() {
        let c =
            Cli::try_parse_from(["whodis", "watch", "--include-local", "-t", "5"]).expect("parse");
        match c.command {
            Cmd::Watch {
                timeout,
                include_local,
            } => {
                assert_eq!(timeout, 5);
                assert!(include_local);
            }
            other => panic!("expected Watch, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_watch_default_excludes_local() {
        let c = Cli::try_parse_from(["whodis", "watch"]).expect("parse");
        match c.command {
            Cmd::Watch {
                timeout,
                include_local,
            } => {
                assert_eq!(timeout, 0);
                assert!(!include_local);
            }
            other => panic!("expected Watch, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_capture_without_pcap() {
        let c = Cli::try_parse_from(["whodis", "capture"]).expect("parse");
        match c.command {
            Cmd::Capture { pcap, timeout } => {
                assert!(pcap.is_none());
                assert_eq!(timeout, 0);
            }
            other => panic!("expected Capture, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_capture_with_pcap() {
        let c = Cli::try_parse_from(["whodis", "capture", "--pcap", "snap.pcap"]).expect("parse");
        match c.command {
            Cmd::Capture { pcap, timeout } => {
                assert_eq!(
                    pcap.as_deref().map(|p| p.to_string_lossy().into_owned()),
                    Some("snap.pcap".to_string())
                );
                assert_eq!(timeout, 0);
            }
            other => panic!("expected Capture, got {other:?}"),
        }
    }

    #[test]
    fn default_capture_filename_has_correct_format() {
        let filename = default_capture_filename();
        let name_str = filename
            .file_name()
            .expect("filename has a name")
            .to_string_lossy();
        assert!(name_str.starts_with("mdns-"));
        assert!(name_str.ends_with(".pcap"));
        assert!(name_str.contains('T'));
        assert!(name_str.contains('Z'));
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_spoof_with_ssdp() {
        let c = Cli::try_parse_from(["whodis", "spoof", "answers.toml", "--ssdp"]).expect("parse");
        match c.command {
            Cmd::Spoof {
                ssdp, http_host, ..
            } => {
                assert!(ssdp);
                assert!(http_host.is_none());
            }
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_spoof_ssdp_with_http_host() {
        let c = Cli::try_parse_from([
            "whodis",
            "spoof",
            "answers.toml",
            "--ssdp",
            "--http-host",
            "127.0.0.1",
        ])
        .expect("parse");
        match c.command {
            Cmd::Spoof {
                ssdp, http_host, ..
            } => {
                assert!(ssdp);
                assert_eq!(http_host, Some(Ipv4Addr::LOCALHOST));
            }
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_http_host_without_ssdp() {
        let err = Cli::try_parse_from([
            "whodis",
            "spoof",
            "answers.toml",
            "--http-host",
            "127.0.0.1",
        ]);
        assert!(err.is_err(), "--http-host should require --ssdp");
    }

    #[test]
    fn cli_rejects_spoof_template_with_ssdp() {
        let err = Cli::try_parse_from([
            "whodis",
            "spoof",
            "answers.toml",
            "--ssdp",
            "--template",
            "ssh",
            "--name",
            "x",
            "--ip",
            "1.2.3.4",
        ]);
        assert!(err.is_err(), "--template should conflict with --ssdp");
    }

    #[test]
    fn cli_rejects_spoof_relay_with_ssdp() {
        let err = Cli::try_parse_from([
            "whodis",
            "spoof",
            "answers.toml",
            "--ssdp",
            "--relay",
            "10.0.0.1:5000",
        ]);
        assert!(err.is_err(), "--relay should conflict with --ssdp");
    }

    #[test]
    fn cli_rejects_spoof_monitor_with_ssdp() {
        let err = Cli::try_parse_from(["whodis", "spoof", "answers.toml", "--ssdp", "--monitor"]);
        assert!(err.is_err(), "--monitor should conflict with --ssdp");
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_spoof_reply_mode() {
        let c = Cli::try_parse_from(["whodis", "spoof", "answers.toml", "--reply", "unicast"])
            .expect("parse");
        match c.command {
            Cmd::Spoof { reply, .. } => assert_eq!(reply, ReplyMode::Unicast),
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_spoof_verify_marker() {
        let c = Cli::try_parse_from(["whodis", "spoof", "verify"]).expect("parse");
        match c.command {
            Cmd::Spoof {
                table, template, ..
            } => {
                assert_eq!(table.as_deref(), Some(std::path::Path::new("verify")));
                assert!(template.is_none());
            }
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_spoof_monitor_marker_with_template() {
        let c = Cli::try_parse_from([
            "whodis",
            "spoof",
            "monitor",
            "--template",
            "ssh",
            "--name",
            "Demo",
            "--ip",
            "127.0.0.1",
            "--timeout",
            "5",
        ])
        .expect("parse");
        match c.command {
            Cmd::Spoof {
                table,
                template,
                monitor,
                timeout,
                ..
            } => {
                assert_eq!(table.as_deref(), Some(std::path::Path::new("monitor")));
                assert_eq!(template, Some(Template::Ssh));
                assert!(!monitor);
                assert_eq!(timeout, 5);
            }
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_spoof_monitor_flag_with_table() {
        let c =
            Cli::try_parse_from(["whodis", "spoof", "--monitor", "answers.toml"]).expect("parse");
        match c.command {
            Cmd::Spoof { table, monitor, .. } => {
                assert_eq!(table.as_deref(), Some(std::path::Path::new("answers.toml")));
                assert!(monitor);
            }
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_zero_flood_rate() {
        let err = Cli::try_parse_from([
            "whodis",
            "flood",
            "goodbye",
            "Foo._airplay._tcp.local.",
            "--rate",
            "0",
        ]);

        assert!(err.is_err());
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_flood_conflict_host() {
        let c = Cli::try_parse_from([
            "whodis",
            "flood",
            "conflict-host",
            "Camera.local.",
            "--ip",
            "0.0.0.0",
        ])
        .expect("parse");
        match c.command {
            Cmd::Flood {
                kind:
                    FloodCmd::ConflictHost {
                        ref targets, ip, ..
                    },
            } => {
                assert_eq!(targets, &vec!["Camera.local.".to_string()]);
                assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
            }
            other => panic!("expected Flood::ConflictHost, got {other:?}"),
        }
    }

    #[test]
    fn cli_requires_ip_for_flood_conflict_host() {
        let err = Cli::try_parse_from(["whodis", "flood", "conflict-host", "Camera.local."]);
        assert!(err.is_err(), "--ip should be required");
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_flood_goodbye_type() {
        let c = Cli::try_parse_from([
            "whodis",
            "flood",
            "goodbye-type",
            "_googlecast._tcp.local.",
            "--discovery-window",
            "5",
        ])
        .expect("parse");
        match c.command {
            Cmd::Flood {
                kind:
                    FloodCmd::GoodbyeType {
                        ref service,
                        discovery_window,
                        ..
                    },
            } => {
                assert_eq!(service, "_googlecast._tcp.local.");
                assert_eq!(discovery_window, 5);
            }
            other => panic!("expected Flood::GoodbyeType, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_zero_discovery_window() {
        let err = Cli::try_parse_from([
            "whodis",
            "flood",
            "goodbye-type",
            "_googlecast._tcp.local.",
            "--discovery-window",
            "0",
        ]);
        assert!(err.is_err());
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_flood_conflict_host_with_ip6() {
        let c = Cli::try_parse_from([
            "whodis",
            "flood",
            "conflict-host",
            "Camera.local.",
            "--ip",
            "0.0.0.0",
            "--ip6",
            "::",
        ])
        .expect("parse");
        match c.command {
            Cmd::Flood {
                kind: FloodCmd::ConflictHost { ip, ip6, .. },
            } => {
                assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
                assert_eq!(ip6, Some(Ipv6Addr::UNSPECIFIED));
            }
            other => panic!("expected Flood::ConflictHost, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_zero_flood_count() {
        let err = Cli::try_parse_from([
            "whodis",
            "flood",
            "conflict",
            "Foo._airplay._tcp.local.",
            "--count",
            "0",
        ]);

        assert!(err.is_err());
    }

    #[test]
    fn debug_assert_clap_command_renders() {
        Cli::command().debug_assert();
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_clone_with_ssdp() {
        let c = Cli::try_parse_from([
            "whodis",
            "clone",
            "uuid:abc::urn:schemas-upnp-org:device:MediaRenderer:1",
            "--ssdp",
        ])
        .expect("parse");
        match c.command {
            Cmd::Clone { instance, ssdp, .. } => {
                assert!(instance.starts_with("uuid:abc::"));
                assert!(ssdp);
            }
            other => panic!("expected Clone, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_clone_default_is_mdns() {
        let c =
            Cli::try_parse_from(["whodis", "clone", "Foo._airplay._tcp.local."]).expect("parse");
        match c.command {
            Cmd::Clone { ssdp, .. } => assert!(!ssdp),
            other => panic!("expected Clone, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_arp_subcommand() {
        let c = Cli::try_parse_from(["whodis", "arp"]).expect("parse");
        match c.command {
            Cmd::Arp {
                v4,
                v6,
                vendor,
                no_oui,
            } => {
                assert!(!v4);
                assert!(!v6);
                assert!(vendor.is_none());
                assert!(!no_oui);
            }
            other => panic!("expected Arp, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_arp_with_vendor_filter() {
        let c = Cli::try_parse_from(["whodis", "arp", "--vendor", "Apple", "--v4"]).expect("parse");
        match c.command {
            Cmd::Arp { v4, vendor, .. } => {
                assert!(v4);
                assert_eq!(vendor.as_deref(), Some("Apple"));
            }
            other => panic!("expected Arp, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_sweep_subcommand() {
        let c = Cli::try_parse_from(["whodis", "sweep", "192.168.1.0/24"]).expect("parse");
        match c.command {
            Cmd::Sweep {
                cidr,
                timeout,
                max,
                no_arp,
                no_oui,
                show_dead,
            } => {
                assert_eq!(
                    cidr.map(|c| c.to_string()),
                    Some("192.168.1.0/24".to_string())
                );
                assert_eq!(timeout, 500);
                assert_eq!(max, 256);
                assert!(!no_arp);
                assert!(!no_oui);
                assert!(!show_dead);
            }
            other => panic!("expected Sweep, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_sweep_without_cidr() {
        let c = Cli::try_parse_from(["whodis", "sweep"]).expect("parse");
        match c.command {
            Cmd::Sweep { cidr, .. } => assert!(cidr.is_none()),
            other => panic!("expected Sweep, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_sweep_with_max_zero_for_unbounded() {
        let c =
            Cli::try_parse_from(["whodis", "sweep", "10.0.0.0/24", "--max", "0"]).expect("parse");
        match c.command {
            Cmd::Sweep { max, .. } => assert_eq!(max, 0),
            other => panic!("expected Sweep, got {other:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn cli_parses_sweep_with_show_dead() {
        let c =
            Cli::try_parse_from(["whodis", "sweep", "10.0.0.0/30", "--show-dead"]).expect("parse");
        match c.command {
            Cmd::Sweep { show_dead, .. } => assert!(show_dead),
            other => panic!("expected Sweep, got {other:?}"),
        }
    }

    #[test]
    fn filter_matches_instance_found_with_same_service_type() {
        let inst = crate::types::Instance {
            service_type: crate::types::ServiceType::new("_airplay", crate::types::Protocol::Tcp),
            instance_name: "Foo".into(),
            host: "Foo.local.".into(),
            port: 7000,
            addrs: Vec::new(),
            txt: std::collections::BTreeMap::new(),
        };
        let event = crate::browse::Event::InstanceFound { instance: inst };
        assert!(event_matches_filter(&event, Some("_airplay._tcp.local.")));
        assert!(event_matches_filter(&event, Some("_AIRPLAY._tcp.local")));
        assert!(!event_matches_filter(&event, Some("_ipp._tcp.local.")));
    }

    #[test]
    fn filter_passes_everything_when_none() {
        let event = crate::browse::Event::InstanceGoodbye {
            fqdn: "X._airplay._tcp.local.".into(),
        };
        assert!(event_matches_filter(&event, None));
    }

    #[test]
    fn cli_parses_no_dns_sd_global_flag() {
        let c = Cli::try_parse_from(["whodis", "--no-dns-sd", "probe", "_airplay._tcp.local."])
            .expect("parse");
        assert!(c.no_dns_sd);
    }
}
