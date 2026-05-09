//! Integration test: `WpadListener` serves PAC body after NTLM auth completes.

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use whodis::credcap::WpadListener;

#[tokio::test(flavor = "multi_thread")]
async fn wpad_listener_serves_pac_after_ntlm() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_listener = captured.clone();
    let cancel = CancellationToken::new();

    let listener = WpadListener::bind("127.0.0.1:0", "127.0.0.1", 8888, move |line| {
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

    // Step 1: GET /wpad.dat without auth -> 401 + WWW-Authenticate: NTLM
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");
    s.write_all(b"GET /wpad.dat HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    let resp1 = read_response(&mut s).await;
    assert!(resp1.contains("401"), "expected 401, got {resp1}");

    // Step 2: send Type 1 -> expect 401 + WWW-Authenticate: NTLM <base64-Type2>
    let t1 = synth_type1();
    let b64_t1 = base64::engine::general_purpose::STANDARD.encode(&t1);
    s.write_all(
        format!("GET /wpad.dat HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM {b64_t1}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .expect("write");
    let resp2 = read_response(&mut s).await;
    assert!(
        resp2
            .to_ascii_lowercase()
            .contains("www-authenticate: ntlm "),
        "expected Type 2 challenge in response: {resp2}"
    );

    // Step 3: send Type 3 -> expect 200 OK with PAC body
    let t3 = synth_type3();
    let b64_t3 = base64::engine::general_purpose::STANDARD.encode(&t3);
    s.write_all(
        format!("GET /wpad.dat HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM {b64_t3}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .expect("write");
    let resp3 = read_response(&mut s).await;
    assert!(resp3.contains("200 OK"), "expected 200 OK, got {resp3}");
    assert!(
        resp3.contains("FindProxyForURL"),
        "expected PAC body in response: {resp3}"
    );
    assert!(
        resp3.contains("PROXY 127.0.0.1:8888"),
        "expected PROXY directive in response: {resp3}"
    );

    // Wait for callback to fire.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if has_capture(&captured) {
            break;
        }
    }
    assert!(has_capture(&captured), "expected captured hash");
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

fn synth_type1() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"NTLMSSP\0");
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&[0u8; 4]);
    v
}

fn synth_type3() -> Vec<u8> {
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
