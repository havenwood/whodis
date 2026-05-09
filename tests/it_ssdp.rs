//! Integration test for SSDP browse. Binds a fake responder on localhost and
//! verifies whodis's browse stream receives the synthesized NOTIFY.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tokio_stream::StreamExt;
use whodis::ssdp::{self, SsdpEvent};

fn send_unicast(payload: &[u8], port: u16) {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    sock.send_to(payload, dst).expect("send");
}

#[tokio::test]
async fn ssdp_browse_emits_alive_event_for_unicast_notify() {
    // Use the real SSDP port (1900) — macOS doesn't run a native SSDP daemon, so
    // this is safe in test environments. The browse() function joins the SSDP
    // multicast group; we send unicast NOTIFY to localhost:1900 which the bound
    // socket receives via the `0.0.0.0:1900` bind.
    let stream = ssdp::browse(Duration::from_secs(3)).expect("browse");
    tokio::pin!(stream);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let payload = b"NOTIFY * HTTP/1.1\r\n\
                    HOST: 239.255.255.250:1900\r\n\
                    CACHE-CONTROL: max-age=1800\r\n\
                    LOCATION: http://127.0.0.1:65535/desc.xml\r\n\
                    NT: urn:test:device:Whodis:1\r\n\
                    NTS: ssdp:alive\r\n\
                    SERVER: WhodisTest/1.0 UPnP/1.0\r\n\
                    USN: uuid:whodis-test::urn:test:device:Whodis:1\r\n\
                    \r\n";
    send_unicast(payload, ssdp::SSDP_PORT);

    let mut got_alive = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        tokio::select! {
            ev = stream.next() => {
                match ev {
                    Some(SsdpEvent::Alive { device, .. }) => {
                        if device.usn == "uuid:whodis-test::urn:test:device:Whodis:1" {
                            got_alive = true;
                            break;
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    assert!(
        got_alive,
        "expected SsdpEvent::Alive for our test USN within 3s"
    );
}
