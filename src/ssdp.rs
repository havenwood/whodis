//! SSDP (Simple Service Discovery Protocol) coverage. Sibling to the mDNS modules.
//!
//! SSDP is HTTP-over-UDP on multicast `239.255.255.250:1900`. M-SEARCH carries
//! discovery queries; NOTIFY carries device announces with `NTS: ssdp:alive` /
//! `ssdp:byebye`. macOS runs no SSDP daemon by default, so port 1900 is open
//! territory; whodis binds it with the same `SO_REUSEADDR + SO_REUSEPORT` shape
//! as mDNS so we coexist cleanly with anything third-party (Plex, VLC) that
//! happens to be listening.
//!
//! v1: browse / probe / flood byebye. v2a: spoof responder + LOCATION HTTP server.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::auth::Authorization;
use crate::error::{Error, Result};
use crate::flood::FloodOptions;
use crate::mode::Mode;
use crate::ssdp_table::SsdpAnswerTable;
use crate::transport::{Destination, Transport, recv_one};

pub const SSDP_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// Placeholder: SSDP-over-IPv6 is non-standard and not used in practice.
/// Kept so `Mode::Custom` accepts a valid v6 group; the v6 socket binds but is unused.
pub const SSDP_GROUP_V6_PLACEHOLDER: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);
pub const SSDP_PORT: u16 = 1900;
const DEFAULT_MX: u32 = 3;

#[must_use]
pub const fn ssdp_mode() -> Mode {
    Mode::Custom {
        group_v4: SSDP_GROUP_V4,
        group_v6: SSDP_GROUP_V6_PLACEHOLDER,
        port: SSDP_PORT,
    }
}

/// A single SSDP-discovered device. Headers beyond the well-known set are
/// preserved in `headers` so callers can inspect vendor-specific values.
#[derive(Debug, Clone, Serialize)]
pub struct SsdpDevice {
    pub usn: String,
    pub st: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u32>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SsdpEvent {
    Alive {
        device: SsdpDevice,
        src: String,
    },
    Byebye {
        usn: String,
        nt: String,
        src: String,
    },
    Reply {
        device: SsdpDevice,
        src: String,
    },
}

#[derive(Debug, Clone)]
pub struct SsdpProbeOptions {
    pub timeout: Duration,
    pub mx: u32,
}

impl Default for SsdpProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            mx: DEFAULT_MX,
        }
    }
}

/// Continuous SSDP browser: sends one M-SEARCH for `ssdp:all` at startup, then
/// listens for unsolicited NOTIFY / unicast M-SEARCH replies until cancelled or
/// the timeout elapses.
pub fn browse(timeout: Duration) -> Result<impl Stream<Item = SsdpEvent> + Send + 'static> {
    let transport = Arc::new(Transport::build(ssdp_mode())?);
    let (tx, rx) = mpsc::channel::<SsdpEvent>(1024);
    let cancel = CancellationToken::new();
    let cancel_rx = cancel.clone();

    let tx_transport = transport.clone();
    tokio::spawn(async move {
        let bytes = build_msearch("ssdp:all", DEFAULT_MX);
        if let Err(e) = tx_transport
            .send_query(&bytes, Destination::Multicast)
            .await
        {
            tracing::debug!(error = %e, "ssdp initial M-SEARCH send failed");
        }
        if timeout > Duration::ZERO {
            tokio::time::sleep(timeout).await;
            cancel.cancel();
        }
    });

    let rx_transport = transport;
    tokio::spawn(async move {
        let v4 = rx_transport.v4();
        let v6 = rx_transport.v6();
        let mut buf = vec![0u8; 9000];
        loop {
            tokio::select! {
                () = cancel_rx.cancelled() => return,
                r = recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                    match r {
                        Ok(Some((n, src))) => {
                            let payload = buf.get(..n).unwrap_or(&[]);
                            if let Some(event) = parse_ssdp_packet(payload, src)
                                && tx.send(event).await.is_err()
                            {
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!(error = %e, "ssdp browse rx error, continuing"),
                    }
                }
            }
        }
    });

    Ok(ReceiverStream::new(rx))
}

/// Targeted M-SEARCH for a specific ST. Collects unicast replies for the
/// duration of `opts.timeout`.
pub async fn probe(st: &str, opts: &SsdpProbeOptions) -> Result<Vec<SsdpDevice>> {
    let transport = Arc::new(Transport::build(ssdp_mode())?);
    let bytes = build_msearch(st, opts.mx);
    transport.send_query(&bytes, Destination::Multicast).await?;

    let v4 = transport.v4();
    let v6 = transport.v6();
    let mut buf = vec![0u8; 9000];
    let deadline = tokio::time::Instant::now() + opts.timeout;
    let mut devices: Vec<SsdpDevice> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        tokio::select! {
            () = tokio::time::sleep(remaining) => break,
            r = recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                match r {
                    Ok(Some((n, src))) => {
                        let payload = buf.get(..n).unwrap_or(&[]);
                        if let Some(SsdpEvent::Reply { device, .. } | SsdpEvent::Alive { device, .. }) =
                            parse_ssdp_packet(payload, src)
                            && seen.insert(device.usn.clone())
                        {
                            devices.push(device);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!(error = %e, "ssdp probe rx error, continuing"),
                }
            }
        }
    }
    Ok(devices)
}

/// Disruptive: emit `NOTIFY * HTTP/1.1` with `NTS: ssdp:byebye`, telling
/// controllers the device is gone. Rate-limited via the existing flood machinery.
pub async fn flood_byebye(
    usn: &str,
    nt: &str,
    auth: &Authorization,
    opts: FloodOptions,
) -> Result<usize> {
    auth.warn_once_if_permissive("ssdp:byebye");
    if let Some(uuid) = extract_uuid_from_usn(usn)
        && !auth.permits_instance(uuid)
    {
        tracing::warn!(target = %usn, "blocked by allow-list");
        return Ok(0);
    }
    let transport = Arc::new(Transport::build(ssdp_mode())?);
    let limiter = byebye_limiter(opts.rate_pps);
    let bytes = build_byebye(usn, nt);

    let mut sent = 0_usize;
    if opts.count == 0 {
        loop {
            limiter.until_ready().await;
            if opts.dry_run {
                tracing::info!(target = %usn, bytes = bytes.len(), "dry-run: would send");
            } else {
                transport.send_query(&bytes, Destination::Multicast).await?;
            }
        }
    }
    for i in 0..opts.count {
        if opts.dry_run {
            tracing::info!(target = %usn, bytes = bytes.len(), iter = i, "dry-run: would send");
        } else {
            limiter.until_ready().await;
            transport.send_query(&bytes, Destination::Multicast).await?;
        }
        sent += 1;
    }
    Ok(sent)
}

fn byebye_limiter(
    rate: NonZeroU32,
) -> Arc<
    governor::RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
> {
    Arc::new(governor::RateLimiter::direct(governor::Quota::per_second(
        rate,
    )))
}

/// Extract the `uuid:...` prefix from a USN so the auth gate's leftmost-label
/// check works the same way it does for mDNS instance names.
#[must_use]
pub fn extract_uuid_from_usn(usn: &str) -> Option<&str> {
    let rest = usn.strip_prefix("uuid:")?;
    let end = rest.find("::").unwrap_or(rest.len());
    rest.get(..end)
}

fn build_msearch(st: &str, mx: u32) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_GROUP_V4}:{SSDP_PORT}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {mx}\r\n\
         ST: {st}\r\n\
         \r\n"
    )
    .into_bytes()
}

fn build_byebye(usn: &str, nt: &str) -> Vec<u8> {
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: {SSDP_GROUP_V4}:{SSDP_PORT}\r\n\
         NT: {nt}\r\n\
         NTS: ssdp:byebye\r\n\
         USN: {usn}\r\n\
         \r\n"
    )
    .into_bytes()
}

fn parse_ssdp_packet(payload: &[u8], src: SocketAddr) -> Option<SsdpEvent> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.split("\r\n");
    let start = lines.next()?.trim();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        headers.insert(k.trim().to_ascii_uppercase(), v.trim().to_string());
    }

    if start.starts_with("HTTP/1.1 200") {
        let device = device_from_headers(&headers, "ST")?;
        return Some(SsdpEvent::Reply {
            device,
            src: src.to_string(),
        });
    }
    if start.starts_with("NOTIFY ") {
        let nts = headers.get("NTS").map_or("", String::as_str);
        if nts.eq_ignore_ascii_case("ssdp:byebye") {
            let usn = headers.get("USN")?.clone();
            let nt = headers.get("NT").cloned().unwrap_or_default();
            return Some(SsdpEvent::Byebye {
                usn,
                nt,
                src: src.to_string(),
            });
        }
        if nts.eq_ignore_ascii_case("ssdp:alive") {
            let device = device_from_headers(&headers, "NT")?;
            return Some(SsdpEvent::Alive {
                device,
                src: src.to_string(),
            });
        }
    }
    None
}

fn device_from_headers(
    headers: &BTreeMap<String, String>,
    st_or_nt_key: &str,
) -> Option<SsdpDevice> {
    let usn = headers.get("USN")?.clone();
    let st = headers.get(st_or_nt_key)?.clone();
    let location = headers.get("LOCATION").cloned();
    let server = headers.get("SERVER").cloned();
    let max_age = headers
        .get("CACHE-CONTROL")
        .and_then(|v| v.split(',').find_map(|p| p.trim().strip_prefix("max-age=")))
        .and_then(|s| s.parse::<u32>().ok());
    let well_known = [
        "USN",
        "NT",
        "ST",
        "LOCATION",
        "SERVER",
        "CACHE-CONTROL",
        "NTS",
        "HOST",
    ];
    let extras: BTreeMap<String, String> = headers
        .iter()
        .filter(|(k, _)| !well_known.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Some(SsdpDevice {
        usn,
        st,
        location,
        server,
        max_age,
        headers: extras,
    })
}

/// Authoritative SSDP responder. Replies to M-SEARCH unicast, optionally emits
/// periodic NOTIFY ssdp:alive, and serves the LOCATION URL via an embedded HTTP
/// server.
pub struct SsdpResponder {
    transport: Arc<Transport>,
    table: Arc<SsdpAnswerTable>,
    auth: Authorization,
    cancel: CancellationToken,
    http_host: Ipv4Addr,
    reannounce: Option<Duration>,
}

impl SsdpResponder {
    pub fn new(
        auth: Authorization,
        table: SsdpAnswerTable,
        http_host: Ipv4Addr,
        reannounce: Option<Duration>,
    ) -> Result<Self> {
        if table.is_empty() {
            return Err(Error::InvalidServiceType(
                "SSDP responder requires at least one device".into(),
            ));
        }
        let transport = Arc::new(Transport::build(ssdp_mode())?);
        Ok(Self {
            transport,
            table: Arc::new(table),
            auth,
            cancel: CancellationToken::new(),
            http_host,
            reannounce,
        })
    }

    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub async fn run(self) -> Result<()> {
        let http_listener = tokio::net::TcpListener::bind(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            self.table.http_port,
        ))
        .await?;
        tracing::info!(
            port = self.table.http_port,
            host = %self.http_host,
            "ssdp responder: HTTP server bound"
        );

        let http_table = self.table.clone();
        let http_cancel = self.cancel.clone();
        let http_task = tokio::spawn(async move {
            http_serve(http_listener, http_table, http_cancel).await;
        });

        let reannounce_task = if let Some(interval) = self.reannounce {
            let table = self.table.clone();
            let auth = self.auth.clone();
            let transport = self.transport.clone();
            let cancel = self.cancel.clone();
            let host = self.http_host;
            Some(tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = cancel.cancelled() => return,
                        _ = tick.tick() => {
                            for d in &table.devices {
                                if !permits_device(&auth, &d.usn) {
                                    continue;
                                }
                                let bytes = build_alive(d, host, table.http_port, table.ttl);
                                if let Err(e) = transport
                                    .send_query(&bytes, Destination::Multicast)
                                    .await
                                {
                                    tracing::debug!(error = %e, "ssdp alive send failed");
                                }
                            }
                        }
                    }
                }
            }))
        } else {
            None
        };

        let v4 = self.transport.v4();
        let v6 = self.transport.v6();
        let mut buf = vec![0u8; 9000];
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                r = recv_one(v4.as_ref(), v6.as_ref(), &mut buf) => {
                    match r {
                        Ok(Some((n, src))) => {
                            let payload = buf.get(..n).unwrap_or(&[]);
                            self.handle_msearch(payload, src).await;
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!(error = %e, "ssdp responder rx error, continuing"),
                    }
                }
            }
        }

        if let Some(t) = reannounce_task {
            t.abort();
        }
        http_task.abort();
        Ok(())
    }

    async fn handle_msearch(&self, payload: &[u8], src: SocketAddr) {
        let Ok(text) = std::str::from_utf8(payload) else {
            return;
        };
        if !text.starts_with("M-SEARCH ") {
            return;
        }
        let mut st: Option<&str> = None;
        for line in text.split("\r\n") {
            if let Some(v) = line
                .strip_prefix("ST:")
                .or_else(|| line.strip_prefix("st:"))
            {
                st = Some(v.trim());
                break;
            }
        }
        let Some(search_st) = st else {
            return;
        };
        if !self.auth.permits_addr(src.ip()) {
            tracing::debug!(src = %src, "ssdp responder: blocked by allow-list");
            return;
        }
        for device in self.table.match_st(search_st) {
            if !permits_device(&self.auth, &device.usn) {
                continue;
            }
            let bytes = build_msearch_reply(
                device,
                self.http_host,
                self.table.http_port,
                self.table.ttl,
                search_st,
            );
            if let Err(e) = self
                .transport
                .send_query(&bytes, Destination::Unicast(src))
                .await
            {
                tracing::debug!(error = %e, src = %src, "ssdp reply send failed");
            }
        }
    }
}

fn permits_device(auth: &Authorization, usn: &str) -> bool {
    extract_uuid_from_usn(usn).is_none_or(|uuid| auth.permits_instance(uuid))
}

fn build_msearch_reply(
    device: &crate::ssdp_table::SsdpDeviceEntry,
    http_host: Ipv4Addr,
    http_port: u16,
    ttl: u32,
    requested_st: &str,
) -> Vec<u8> {
    // Per UPnP DA: response ST is always the device's specific URN, not the
    // requested ST (even for ssdp:all). The `requested_st` arg is kept for future
    // extension (e.g. logging).
    let _ = requested_st;
    let response_st = device.st.as_str();
    format!(
        "HTTP/1.1 200 OK\r\n\
         CACHE-CONTROL: max-age={ttl}\r\n\
         DATE: {date}\r\n\
         EXT:\r\n\
         LOCATION: http://{http_host}:{http_port}{path}\r\n\
         SERVER: {server}\r\n\
         ST: {response_st}\r\n\
         USN: {usn}\r\n\
         \r\n",
        date = http_date_now(),
        path = device.location_path,
        server = device.server,
        usn = device.usn,
    )
    .into_bytes()
}

fn build_alive(
    device: &crate::ssdp_table::SsdpDeviceEntry,
    http_host: Ipv4Addr,
    http_port: u16,
    ttl: u32,
) -> Vec<u8> {
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: {SSDP_GROUP_V4}:{SSDP_PORT}\r\n\
         CACHE-CONTROL: max-age={ttl}\r\n\
         LOCATION: http://{http_host}:{http_port}{path}\r\n\
         NT: {nt}\r\n\
         NTS: ssdp:alive\r\n\
         SERVER: {server}\r\n\
         USN: {usn}\r\n\
         \r\n",
        path = device.location_path,
        nt = device.st,
        server = device.server,
        usn = device.usn,
    )
    .into_bytes()
}

fn http_date_now() -> String {
    // IMF-fixdate per RFC 7231 §7.1.1.1 (a.k.a. RFC 1123 HTTP-date), the form
    // UPnP DA expects in the DATE header.
    use time::OffsetDateTime;
    use time::macros::format_description;
    let fmt = format_description!(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] \
         [hour]:[minute]:[second] GMT"
    );
    OffsetDateTime::now_utc()
        .format(fmt)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

const HTTP_MAX_REQUEST_SIZE: usize = 4 * 1024;
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_MAX_CONCURRENT: usize = 32;

async fn http_serve(
    listener: tokio::net::TcpListener,
    table: Arc<SsdpAnswerTable>,
    cancel: CancellationToken,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(HTTP_MAX_CONCURRENT));
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            r = listener.accept() => {
                match r {
                    Ok((stream, peer)) => {
                        let Ok(permit) = sem.clone().try_acquire_owned() else {
                            tracing::debug!(peer = %peer, "ssdp http: dropping connection (over limit)");
                            continue;
                        };
                        let table = table.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = http_handle(stream, table).await {
                                tracing::debug!(error = %e, peer = %peer, "ssdp http handle error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "ssdp http accept error");
                    }
                }
            }
        }
    }
}

async fn http_handle(
    mut stream: tokio::net::TcpStream,
    table: Arc<SsdpAnswerTable>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; HTTP_MAX_REQUEST_SIZE];
    let mut filled = 0;
    let read_fut = async {
        loop {
            let Some(rest) = buf.get_mut(filled..) else {
                return Ok::<(), std::io::Error>(());
            };
            let n = stream.read(rest).await?;
            if n == 0 {
                return Ok(());
            }
            filled += n;
            if buf
                .get(..filled)
                .is_some_and(|s| s.windows(4).any(|w| w == b"\r\n\r\n"))
            {
                return Ok(());
            }
            if filled >= buf.len() {
                return Ok(());
            }
        }
    };
    if let Err(e) = tokio::time::timeout(HTTP_READ_TIMEOUT, read_fut).await {
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, e));
    }

    let request = std::str::from_utf8(buf.get(..filled).unwrap_or(&[])).unwrap_or("");
    let start_line = request.split("\r\n").next().unwrap_or("");
    if start_line.is_empty() {
        stream.write_all(http_404().as_bytes()).await?;
        return Ok(());
    }
    // Expect "GET <path> HTTP/1.1"
    let mut parts = start_line.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let response = table.find_by_path(path).map_or_else(
        || http_404().into_bytes(),
        |device| {
            let body = device.description_xml.as_bytes();
            let mut out = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/xml; charset=\"utf-8\"\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(body);
            out
        },
    );
    stream.write_all(&response).await?;
    stream.shutdown().await.ok();
    Ok(())
}

fn http_404() -> String {
    let body = b"404 Not Found";
    format!(
        "HTTP/1.1 404 Not Found\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    ) + std::str::from_utf8(body).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    #[test]
    fn build_msearch_has_required_headers() {
        let bytes = build_msearch("ssdp:all", 3);
        let s = std::str::from_utf8(&bytes).expect("utf8");
        assert!(s.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(s.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(s.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(s.contains("MX: 3\r\n"));
        assert!(s.contains("ST: ssdp:all\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_byebye_has_required_headers() {
        let bytes = build_byebye(
            "uuid:abc::urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        );
        let s = std::str::from_utf8(&bytes).expect("utf8");
        assert!(s.starts_with("NOTIFY * HTTP/1.1\r\n"));
        assert!(s.contains("NTS: ssdp:byebye\r\n"));
        assert!(s.contains("USN: uuid:abc::urn:schemas-upnp-org:service:WANIPConnection:1\r\n"));
        assert!(s.contains("NT: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"));
    }

    #[test]
    fn extract_uuid_handles_typical_usn() {
        assert_eq!(
            extract_uuid_from_usn("uuid:abc-123::urn:schemas-upnp-org:device:MediaRenderer:1"),
            Some("abc-123")
        );
        assert_eq!(extract_uuid_from_usn("uuid:bare"), Some("bare"));
        assert_eq!(extract_uuid_from_usn("not-a-usn"), None);
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn parse_alive_notify_yields_event() {
        let payload = b"NOTIFY * HTTP/1.1\r\n\
                        HOST: 239.255.255.250:1900\r\n\
                        CACHE-CONTROL: max-age=1800\r\n\
                        LOCATION: http://192.168.1.1:5000/desc.xml\r\n\
                        NT: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                        NTS: ssdp:alive\r\n\
                        SERVER: TestRouter/1.0 UPnP/1.0\r\n\
                        USN: uuid:r1::urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                        \r\n";
        let evt = parse_ssdp_packet(payload, sock("192.168.1.1:1900")).expect("parsed");
        let SsdpEvent::Alive { device, .. } = evt else {
            panic!("expected Alive");
        };
        assert_eq!(
            device.usn,
            "uuid:r1::urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(device.st, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(
            device.location.as_deref(),
            Some("http://192.168.1.1:5000/desc.xml")
        );
        assert_eq!(device.server.as_deref(), Some("TestRouter/1.0 UPnP/1.0"));
        assert_eq!(device.max_age, Some(1800));
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn parse_byebye_yields_event() {
        let payload = b"NOTIFY * HTTP/1.1\r\n\
                        HOST: 239.255.255.250:1900\r\n\
                        NT: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                        NTS: ssdp:byebye\r\n\
                        USN: uuid:r1::urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                        \r\n";
        let evt = parse_ssdp_packet(payload, sock("192.168.1.1:1900")).expect("parsed");
        match evt {
            SsdpEvent::Byebye { usn, nt, .. } => {
                assert_eq!(
                    usn,
                    "uuid:r1::urn:schemas-upnp-org:service:WANIPConnection:1"
                );
                assert_eq!(nt, "urn:schemas-upnp-org:service:WANIPConnection:1");
            }
            other => panic!("expected Byebye, got {other:?}"),
        }
    }

    #[test]
    fn parse_msearch_response_yields_reply() {
        let payload = b"HTTP/1.1 200 OK\r\n\
                        CACHE-CONTROL: max-age=1800\r\n\
                        EXT:\r\n\
                        LOCATION: http://192.168.1.1:5000/desc.xml\r\n\
                        SERVER: TestRouter/1.0 UPnP/1.0\r\n\
                        ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                        USN: uuid:r1::urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                        \r\n";
        let evt = parse_ssdp_packet(payload, sock("192.168.1.1:1900")).expect("parsed");
        assert!(matches!(evt, SsdpEvent::Reply { .. }));
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_ssdp_packet(b"", sock("1.2.3.4:1900")).is_none());
        assert!(parse_ssdp_packet(b"\xff\xfe garbage", sock("1.2.3.4:1900")).is_none());
        assert!(parse_ssdp_packet(b"GET / HTTP/1.1\r\n\r\n", sock("1.2.3.4:1900")).is_none());
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn parse_preserves_extra_headers() {
        let payload = b"NOTIFY * HTTP/1.1\r\n\
                        NT: x\r\nNTS: ssdp:alive\r\n\
                        USN: uuid:1::x\r\n\
                        BOOTID.UPNP.ORG: 42\r\n\
                        \r\n";
        let evt = parse_ssdp_packet(payload, sock("1.2.3.4:1900")).expect("parsed");
        let SsdpEvent::Alive { device, .. } = evt else {
            panic!("expected Alive");
        };
        assert_eq!(
            device.headers.get("BOOTID.UPNP.ORG").map(String::as_str),
            Some("42")
        );
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "test assertion intentionally panics on wrong variant"
    )]
    fn ssdp_mode_uses_documented_constants() {
        let m = ssdp_mode();
        match m {
            Mode::Custom { group_v4, port, .. } => {
                assert_eq!(group_v4, SSDP_GROUP_V4);
                assert_eq!(port, SSDP_PORT);
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }
}
