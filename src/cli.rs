//! CLI argument parsing and subcommand dispatch.

use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tokio_stream::StreamExt;

use crate::auth::Authorization;
use crate::browse::{Browser, Event};
use crate::error::Result as WhResult;
use crate::flood::{self, FloodOptions};
use crate::mode::Mode;
use crate::output::{ColorMode, Renderer, emit_browse_event, emit_instance};
use crate::probe::{self, ProbeOptions};
use crate::types::{Protocol, ServiceType};

#[derive(Parser, Debug)]
#[command(
    name = "whodis",
    version,
    about = "mDNS / Bonjour recon and spoof",
    long_about = "whodis: ask the LAN \"who is this\" and (sometimes) lie about the answer.\n\
                  See `whodis <command> --help` for details on each command."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,

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
    /// Watch the LAN for mDNS announcements.
    Browse {
        #[arg(short = 't', long, default_value_t = 0)]
        timeout: u64,

        /// Tag each instance with a vendor/product guess.
        #[arg(short = 'f', long)]
        fingerprint: bool,
    },

    /// Send a directed mDNS query. Without args, lists service types on the LAN.
    Probe {
        /// Service type fqdn, e.g. `_airplay._tcp.local.`. Omit to discover.
        service: Option<String>,

        #[arg(long)]
        instance: Option<String>,

        #[arg(long)]
        host: Option<String>,

        #[arg(short = 't', long, default_value_t = 3)]
        timeout: u64,
    },

    /// Run an authoritative responder.
    Spoof {
        #[arg(long, value_name = "FILE")]
        table: std::path::PathBuf,

        #[arg(long, default_value_t = 3)]
        burst: u8,

        #[arg(long = "allow", value_name = "CIDR")]
        allow: Vec<IpNet>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,
    },

    /// Send goodbye or conflict-rename floods. Disruptive.
    Flood {
        #[command(subcommand)]
        kind: FloodCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum FloodCmd {
    Goodbye {
        #[arg(value_name = "INSTANCE")]
        targets: Vec<String>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50)]
        rate: u32,
    },
    Conflict {
        #[arg(value_name = "INSTANCE")]
        targets: Vec<String>,

        #[arg(long = "allow-instance", value_name = "NAME")]
        allow_instance: Vec<String>,

        #[arg(long, default_value_t = 50)]
        rate: u32,
    },
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    init_tracing(cli.quiet, cli.verbose);
    let renderer = pick_renderer(&cli);
    match cli.command {
        Cmd::Browse {
            timeout,
            fingerprint,
        } => run_browse(renderer, timeout, fingerprint).await?,
        Cmd::Probe {
            service,
            instance,
            host,
            timeout,
        } => {
            run_probe(renderer, service, instance, host, timeout).await?;
        }
        Cmd::Spoof {
            table,
            burst,
            allow,
            allow_instance,
        } => {
            run_spoof(renderer, table, burst, allow, allow_instance).await?;
        }
        Cmd::Flood { kind } => run_flood(kind).await?,
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

async fn run_browse(renderer: Renderer, timeout: u64, fingerprint: bool) -> anyhow::Result<()> {
    let browser = Browser::new(Mode::Listen).context("starting browser")?;
    let cancel = browser.cancel_token();
    let stream = browser.run();

    let task = tokio::spawn(async move {
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
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

    if timeout > 0 {
        tokio::time::sleep(Duration::from_secs(timeout)).await;
    } else {
        tokio::signal::ctrl_c().await.ok();
    }
    cancel.cancel();
    if let Err(e) = task.await {
        tracing::debug!(error = %e, "browse task ended");
    }
    Ok(())
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
    timeout: u64,
) -> anyhow::Result<()> {
    let opts = ProbeOptions {
        timeout: Duration::from_secs(timeout),
    };
    if let Some(h) = host {
        let answers = probe::probe_host(&h, &opts).await?;
        for a in answers {
            crate::output::emit_jsonl(&a)?;
        }
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
        probe::probe_service(&svc, &opts).await?
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
async fn run_spoof(
    _renderer: Renderer,
    table_path: std::path::PathBuf,
    burst: u8,
    allow: Vec<IpNet>,
    allow_instance: Vec<String>,
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(&table_path)
        .with_context(|| format!("reading {}", table_path.display()))?;
    let table = crate::spoof_table::load(&raw)?;
    let mut auth = Authorization::new();
    for n in allow {
        auth = auth.allow_subnet(n);
    }
    for name in allow_instance {
        auth = auth.allow_instance(name);
    }
    let resp = crate::spoof::Responder::new(Mode::Authoritative, auth, table, burst)?;
    let cancel = resp.cancel_token();
    let task = tokio::spawn(async move { resp.run().await });
    tokio::signal::ctrl_c().await.ok();
    cancel.cancel();
    if let Err(e) = task.await {
        tracing::debug!(error = %e, "spoof task ended");
    }
    Ok(())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "FloodCmd must be owned to destructure in match arms"
)]
async fn run_flood(kind: FloodCmd) -> anyhow::Result<()> {
    use std::num::NonZeroU32;

    match kind {
        FloodCmd::Goodbye {
            targets,
            allow_instance,
            rate,
        } => {
            let auth = build_auth(allow_instance);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
            };
            flood::goodbye(Mode::Authoritative, &targets, &auth, opts).await?;
        }
        FloodCmd::Conflict {
            targets,
            allow_instance,
            rate,
        } => {
            let auth = build_auth(allow_instance);
            let opts = FloodOptions {
                rate_pps: NonZeroU32::new(rate).unwrap_or(NonZeroU32::MIN),
            };
            flood::conflict_rename(Mode::Authoritative, &targets, &auth, opts).await?;
        }
    }
    Ok(())
}

fn build_auth(allow_instance: Vec<String>) -> Authorization {
    let mut auth = Authorization::new();
    for name in allow_instance {
        auth = auth.allow_instance(name);
    }
    auth
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
            Cmd::Browse { timeout, .. } => assert_eq!(timeout, 0),
            other => panic!("expected Browse, got {other:?}"),
        }
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
            Cmd::Probe { service, .. } => assert!(service.is_none()),
            other => panic!("expected Probe, got {other:?}"),
        }
    }

    #[test]
    fn cli_validates_color_choice() {
        let c = Cli::try_parse_from(["whodis", "--color", "always", "browse"]).expect("parse");
        assert!(matches!(c.color, ColorChoice::Always));
    }

    #[test]
    fn debug_assert_clap_command_renders() {
        Cli::command().debug_assert();
    }
}
