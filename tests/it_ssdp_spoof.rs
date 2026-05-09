//! Integration test for the SSDP responder. Spawns `SsdpResponder` on the
//! standard SSDP port, sends an M-SEARCH from a local UDP socket, asserts we
//! get a 200 OK reply with the expected USN and that the LOCATION URL serves
//! the description XML.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use whodis::Authorization;
use whodis::ssdp::SsdpResponder;
use whodis::ssdp_table::SsdpAnswerTable;

fn build_table(http_port: u16) -> SsdpAnswerTable {
    let toml_src = format!(
        r#"
            ttl = 60
            http_port = {http_port}

            [[device]]
            usn = "uuid:whodis-spoof-test::urn:test:device:Whodis:1"
            st = "urn:test:device:Whodis:1"
            location_path = "/desc.xml"
            server = "WhodisTest/1.0 UPnP/1.0"
            description_xml = "<?xml version=\"1.0\"?><root/>"
        "#
    );
    whodis::ssdp_table::load(&toml_src).expect("load table")
}

fn pick_free_port() -> u16 {
    let s = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let p = s.local_addr().expect("addr").port();
    drop(s);
    p
}

#[tokio::test]
async fn ssdp_responder_replies_to_msearch_and_serves_description() {
    drop(tracing_subscriber::fmt::try_init());
    let http_port = pick_free_port();
    let table = build_table(http_port);
    let responder =
        SsdpResponder::new(Authorization::new(), table, Ipv4Addr::LOCALHOST, None).expect("build");
    let cancel = responder.cancel_token();
    let task = tokio::spawn(async move { responder.run().await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send M-SEARCH for our test ST from a localhost socket. Responder replies
    // unicast to our source addr. Use tokio's async UdpSocket so we don't block
    // the single-threaded test runtime while waiting for the reply.
    let probe = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("probe bind");
    let msearch = b"M-SEARCH * HTTP/1.1\r\n\
                    HOST: 239.255.255.250:1900\r\n\
                    MAN: \"ssdp:discover\"\r\n\
                    MX: 1\r\n\
                    ST: urn:test:device:Whodis:1\r\n\
                    \r\n";
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), whodis::ssdp::SSDP_PORT);
    probe.send_to(msearch, dst).await.expect("send msearch");

    let mut buf = [0u8; 4096];
    let recv = tokio::time::timeout(Duration::from_secs(2), probe.recv_from(&mut buf))
        .await
        .expect("recv reply within 2s")
        .expect("recv reply ok");
    let n = recv.0;
    let received = buf.get(..n).expect("recv slice in bounds");
    let reply = std::str::from_utf8(received).expect("utf8");
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "got: {reply}");
    assert!(reply.contains("USN: uuid:whodis-spoof-test::urn:test:device:Whodis:1"));
    assert!(reply.contains("ST: urn:test:device:Whodis:1"));
    assert!(reply.contains(&format!("LOCATION: http://127.0.0.1:{http_port}/desc.xml")));
    assert!(reply.contains("EXT:"));
    assert!(reply.contains("CACHE-CONTROL: max-age=60"));

    // Fetch the LOCATION URL and verify the description XML is served.
    let url = format!("http://127.0.0.1:{http_port}/desc.xml");
    let body = fetch_http(&url).await.expect("fetch desc.xml");
    assert!(body.contains("<root/>"), "got: {body}");

    // Unknown path returns 404.
    let body_404 = fetch_http(&format!("http://127.0.0.1:{http_port}/nope"))
        .await
        .expect("fetch 404");
    assert!(body_404.contains("404 Not Found"), "got: {body_404}");

    cancel.cancel();
    drop(task.await);
}

async fn fetch_http(url: &str) -> std::io::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = stripped.split_once('/').map_or_else(
        || (stripped.to_string(), "/".to_string()),
        |(hp, p)| (hp.to_string(), format!("/{p}")),
    );
    let mut stream = TcpStream::connect(&host_port).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
