//! Non-disruptive spoof responder smoke test.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
use hickory_proto::rr::{RData, RecordType};
use serde::Serialize;

use crate::auth::Authorization;
use crate::error::{Error, Result};
use crate::mode::Mode;
use crate::output::{ColorMode, Renderer};
use crate::probe::{ProbeOptions, probe_service_with_mode};
use crate::spoof::{AnswerTable, AnswerTableBuilder, ReplyMode, Responder};
use crate::types::{Protocol, ServiceType};

const VERIFY_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 99, 99);
const VERIFY_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0, 0xabcd);
const VERIFY_PORT: u16 = 15353;
const VERIFY_SERVICE: &str = "_whodis-verify._tcp.local.";
const VERIFY_INSTANCE: &str = "WhodisVerify";
const VERIFY_HOST: &str = "WhodisVerify.local.";
const VERIFY_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
const VERIFY_SRV_PORT: u16 = 9;
const VERIFY_TXT_KEY: &str = "purpose";
const VERIFY_TXT_VALUE: &str = "spoof-verify";

/// Timing controls for the non-disruptive spoof responder smoke test.
#[derive(Debug, Clone)]
pub struct SpoofVerifyOptions {
    pub timeout: Duration,
    pub startup_delay: Duration,
}

impl Default for SpoofVerifyOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            startup_delay: Duration::from_millis(100),
        }
    }
}

/// Successful observation from the spoof responder smoke test.
#[derive(Debug, Clone, Serialize)]
pub struct SpoofVerifyResult {
    pub service: String,
    pub instance: String,
    pub host: String,
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Serialize)]
struct VerifyRecord {
    kind: &'static str,
    ok: bool,
    service: String,
    instance: String,
    host: String,
    addr: IpAddr,
    port: u16,
}

pub(crate) async fn run(renderer: Renderer) -> anyhow::Result<()> {
    match spoof_verify(SpoofVerifyOptions::default()).await {
        Ok(result) => {
            emit_result(renderer, true, &result)?;
            Ok(())
        }
        Err(e) => {
            let expected = expected_result();
            emit_result(renderer, false, &expected)?;
            Err(e.into())
        }
    }
}

/// Verifies that the spoof responder can answer a private synthetic service.
///
/// This uses a whodis-only multicast group and port instead of normal mDNS, so callers can run it
/// as a non-disruptive smoke test before enabling spoofing against real LAN service names.
pub async fn spoof_verify(options: SpoofVerifyOptions) -> Result<SpoofVerifyResult> {
    let mode = verify_mode();
    let table = build_table()?;
    let auth = Authorization::new().allow_instance(VERIFY_INSTANCE);
    let responder = Responder::new(mode, auth, table, 1, ReplyMode::Multicast, None)?;
    let cancel = responder.cancel_token();
    let task = tokio::spawn(async move { responder.run().await });

    tokio::time::sleep(options.startup_delay).await;

    let service = ServiceType::new("_whodis-verify", Protocol::Tcp);
    let opts = ProbeOptions {
        timeout: options.timeout,
    };
    let instances = probe_service_with_mode(&service, &opts, mode).await;

    cancel.cancel();
    task.await
        .map_err(|e| std::io::Error::other(format!("spoof verify responder task failed: {e}")))??;

    let instances = instances?;
    let Some(instance) = instances
        .into_iter()
        .find(|instance| instance.instance_name == VERIFY_INSTANCE)
    else {
        return Err(Error::NoRecords {
            target: VERIFY_SERVICE.to_string(),
            timeout: options.timeout,
        });
    };

    let txt_ok = instance
        .txt
        .get(VERIFY_TXT_KEY)
        .and_then(|value| std::str::from_utf8(value).ok())
        == Some(VERIFY_TXT_VALUE);
    if instance.host == VERIFY_HOST
        && instance.port == VERIFY_SRV_PORT
        && instance.addrs.contains(&std::net::IpAddr::V4(VERIFY_ADDR))
        && txt_ok
    {
        Ok(expected_result())
    } else {
        Err(Error::SpoofVerify {
            reason: format!(
                "observed {} with host={}, port={}, addrs={:?}, txt={:?}",
                instance.fqdn(),
                instance.host,
                instance.port,
                instance.addrs,
                instance.txt
            ),
        })
    }
}

fn expected_result() -> SpoofVerifyResult {
    SpoofVerifyResult {
        service: VERIFY_SERVICE.to_string(),
        instance: format!("{VERIFY_INSTANCE}.{VERIFY_SERVICE}"),
        host: VERIFY_HOST.to_string(),
        addr: IpAddr::V4(VERIFY_ADDR),
        port: VERIFY_SRV_PORT,
    }
}

pub(crate) fn build_table() -> Result<AnswerTable> {
    let inst = format!("{VERIFY_INSTANCE}.{VERIFY_SERVICE}");
    Ok(AnswerTableBuilder::new()
        .ttl(30)
        .answer(
            VERIFY_SERVICE,
            RecordType::PTR,
            RData::PTR(PTR(crate::name_util::lax_from_str(&inst)?)),
        )?
        .answer(
            &inst,
            RecordType::SRV,
            RData::SRV(SRV::new(
                0,
                0,
                VERIFY_SRV_PORT,
                crate::name_util::lax_from_str(VERIFY_HOST)?,
            )),
        )?
        .answer(
            &inst,
            RecordType::TXT,
            RData::TXT(TXT::new(vec![format!(
                "{VERIFY_TXT_KEY}={VERIFY_TXT_VALUE}"
            )])),
        )?
        .answer(VERIFY_HOST, RecordType::A, RData::A(A(VERIFY_ADDR)))?
        .build())
}

fn verify_mode() -> Mode {
    Mode::Custom {
        group_v4: VERIFY_GROUP_V4,
        group_v6: VERIFY_GROUP_V6,
        port: VERIFY_PORT,
    }
}

fn emit_result(renderer: Renderer, ok: bool, result: &SpoofVerifyResult) -> std::io::Result<()> {
    let record = VerifyRecord {
        kind: "spoof_verify",
        ok,
        service: result.service.clone(),
        instance: result.instance.clone(),
        host: result.host.clone(),
        addr: result.addr,
        port: result.port,
    };
    match renderer {
        Renderer::Jsonl => crate::output::emit_jsonl(&record),
        Renderer::Pretty(color) => emit_pretty(color, &record),
    }
}

fn emit_pretty(color: ColorMode, record: &VerifyRecord) -> std::io::Result<()> {
    let status = if record.ok { "ok" } else { "failed" };
    let line = if color.enabled() && record.ok {
        format!(
            "\x1b[32mspoof verify {status}\x1b[0m  {}  {}:{}\n",
            record.instance, record.host, record.port
        )
    } else if color.enabled() {
        format!(
            "\x1b[31mspoof verify {status}\x1b[0m  {}  {}:{}\n",
            record.instance, record.host, record.port
        )
    } else {
        format!(
            "spoof verify {status}  {}  {}:{}\n",
            record.instance, record.host, record.port
        )
    };
    crate::output::emit_raw(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_table_has_private_service_records() {
        let table = build_table().expect("table");

        assert!(table.lookup(VERIFY_SERVICE, RecordType::PTR).is_some());
        assert!(
            table
                .lookup("WhodisVerify._whodis-verify._tcp.local.", RecordType::SRV)
                .is_some()
        );
        assert!(
            table
                .lookup("WhodisVerify._whodis-verify._tcp.local.", RecordType::TXT)
                .is_some()
        );
        assert!(table.lookup(VERIFY_HOST, RecordType::A).is_some());
    }

    #[test]
    fn default_options_match_cli_timings() {
        let opts = SpoofVerifyOptions::default();

        assert_eq!(opts.timeout, Duration::from_secs(3));
        assert_eq!(opts.startup_delay, Duration::from_millis(100));
    }

    #[test]
    fn expected_result_is_public_payload_shape() {
        let result = expected_result();

        assert_eq!(result.service, VERIFY_SERVICE);
        assert_eq!(result.instance, "WhodisVerify._whodis-verify._tcp.local.");
        assert_eq!(result.host, VERIFY_HOST);
        assert_eq!(result.addr, IpAddr::V4(VERIFY_ADDR));
        assert_eq!(result.port, VERIFY_SRV_PORT);
    }
}
