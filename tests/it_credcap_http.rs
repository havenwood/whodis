//! Integration test: `HttpListener` captures NTLMSSP hashes via simulated browser handshake.

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use whodis::credcap::HttpListener;

#[tokio::test(flavor = "multi_thread")]
async fn http_listener_captures_synthetic_ntlm_handshake() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_listener = captured.clone();
    let cancel = CancellationToken::new();

    let listener = HttpListener::bind("127.0.0.1:0", move |line| {
        let captured = captured_for_listener.clone();
        async move {
            if let Ok(mut g) = captured.lock() {
                g.push(line);
            }
        }
    })
    .await
    .expect("bind");
    let port = listener.local_addr().port();

    let cancel_for_run = cancel.clone();
    tokio::spawn(async move { listener.run(cancel_for_run).await });

    // Step 1: GET /, expect 401 + WWW-Authenticate: NTLM
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    let resp = read_response(&mut s).await;
    assert!(resp.contains("401"), "expected 401, got: {resp}");
    assert!(
        resp.to_ascii_lowercase().contains("www-authenticate: ntlm"),
        "expected WWW-Authenticate: NTLM in response: {resp}"
    );

    // Step 2: send Authorization: NTLM <Type 1>
    let type1 = synth_type1();
    let b64_t1 = base64::engine::general_purpose::STANDARD.encode(&type1);
    s.write_all(
        format!("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM {b64_t1}\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write");
    let resp = read_response(&mut s).await;
    let www_line = resp
        .lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with("www-authenticate: ntlm ")
        })
        .expect("type2 challenge in WWW-Authenticate");
    let b64_t2 = www_line.split_whitespace().nth(2).expect("b64");
    let type2 = base64::engine::general_purpose::STANDARD
        .decode(b64_t2)
        .expect("decode type2");
    assert_eq!(type2.first_chunk::<8>().expect("sig"), b"NTLMSSP\0");
    let server_challenge: [u8; 8] = type2
        .get(24..32)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .expect("challenge slice");

    // Step 3: send Type 3 (synthetic but valid layout)
    let type3 = synth_type3();
    let b64_t3 = base64::engine::general_purpose::STANDARD.encode(&type3);
    s.write_all(
        format!("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM {b64_t3}\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write");
    let _resp = read_response(&mut s).await;

    // Wait for the captured callback to fire (it's spawned on a separate task).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if has_capture(&captured) {
            break;
        }
    }
    assert!(
        has_capture(&captured),
        "expected at least one captured line"
    );
    let line = first_capture(&captured).expect("first");
    assert!(line.contains("alice"), "expected alice in {line}");
    assert!(line.contains("TESTDOM"), "expected TESTDOM in {line}");
    let _ = server_challenge; // future: assert srvchal hex matches our captured line

    cancel.cancel();
}

async fn read_response(s: &mut TcpStream) -> String {
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(1), s.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read");
    String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).to_string()
}

fn has_capture(c: &Arc<Mutex<Vec<String>>>) -> bool {
    c.lock().is_ok_and(|g| !g.is_empty())
}

fn first_capture(c: &Arc<Mutex<Vec<String>>>) -> Option<String> {
    c.lock().ok().and_then(|g| g.first().cloned())
}

fn synth_type1() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"NTLMSSP\0");
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&[0u8; 4]);
    v
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
    let nt: Vec<u8> = (0..32).map(|_| 0xCDu8).collect();

    let header_len = 64usize;
    let lm_off = header_len;
    let nt_off = lm_off + lm.len();
    let domain_off = nt_off + nt.len();
    let user_off = domain_off + domain.len();
    let ws_off = user_off + user.len();

    let mut v = Vec::new();
    v.extend_from_slice(b"NTLMSSP\0");
    v.extend_from_slice(&3u32.to_le_bytes());
    for (len, off) in [
        (lm.len(), lm_off),
        (nt.len(), nt_off),
        (domain.len(), domain_off),
        (user.len(), user_off),
        (ws.len(), ws_off),
    ] {
        let l = u16::try_from(len).expect("len fits");
        let o = u32::try_from(off).expect("off fits");
        v.extend_from_slice(&l.to_le_bytes());
        v.extend_from_slice(&l.to_le_bytes());
        v.extend_from_slice(&o.to_le_bytes());
    }
    while v.len() < header_len {
        v.push(0);
    }
    v.extend_from_slice(&lm);
    v.extend_from_slice(&nt);
    v.extend_from_slice(&domain);
    v.extend_from_slice(&user);
    v.extend_from_slice(&ws);
    v
}
