//! Integration test for the passive spoof-detector. Each test binds its own
//! `Mode::Custom` group/port pair so they can run concurrently without the
//! detectors stealing each other's packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use whodis::Mode;
use whodis::detect::{Anomaly, Detector};

mod common;

fn isolated_mode(port_offset: u16) -> (Mode, u16) {
    let port = 15400 + port_offset;
    (
        Mode::Custom {
            group_v4: Ipv4Addr::new(239, 255, 99, 99),
            group_v6: Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0, 0xabcd),
            port,
        },
        port,
    )
}

fn build_a_with_cache_flush(name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.authoritative = true;
    msg.metadata.response_code = ResponseCode::NoError;
    let n = Name::from_utf8(name).expect("name");
    let mut rec = Record::from_rdata(n, 120, RData::A(A(ip)));
    rec.dns_class = DNSClass::IN;
    rec.mdns_cache_flush = true;
    msg.add_answer(rec);
    msg.to_bytes().expect("encode")
}

fn send_unicast(payload: &[u8], port: u16) {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    sock.send_to(payload, dst).expect("send");
}

#[tokio::test]
async fn detector_fires_cache_flush_rate_exceeded() {
    let (mode, port) = isolated_mode(0);
    let captured: Arc<Mutex<Vec<Anomaly>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let detector = Detector::new(mode)
        .expect("detector")
        .with_event_callback(move |a| {
            if let Ok(mut g) = cap.lock() {
                g.push(a);
            }
        });
    let cancel = detector.cancel_token();
    let task = tokio::spawn(async move { detector.run().await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let payload = build_a_with_cache_flush("Camera.local.", Ipv4Addr::UNSPECIFIED);
    for _ in 0..3 {
        send_unicast(&payload, port);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(common::settle()).await;

    cancel.cancel();
    drop(task.await);

    let anomalies: Vec<Anomaly> = captured.lock().expect("lock").clone();
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::CacheFlushRateExceeded { .. })),
        "expected CacheFlushRateExceeded, got {anomalies:?}"
    );
}

fn primary_v4_interface_ip() -> Option<Ipv4Addr> {
    for iface in get_if_addrs::get_if_addrs().ok()? {
        if iface.is_loopback() {
            continue;
        }
        if let IpAddr::V4(v4) = iface.ip() {
            return Some(v4);
        }
    }
    None
}

fn send_from_iface(payload: &[u8], src_ip: Ipv4Addr, port: u16) {
    let sock = UdpSocket::bind(SocketAddr::from((src_ip, 0))).expect("bind");
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    sock.send_to(payload, dst).expect("send");
}

async fn run_local_traffic_test(
    mode: Mode,
    port: u16,
    include_local: bool,
    src_ip: Ipv4Addr,
) -> Vec<Anomaly> {
    let captured: Arc<Mutex<Vec<Anomaly>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let detector = Detector::new(mode)
        .expect("detector")
        .with_include_local(include_local)
        .with_event_callback(move |a| {
            if let Ok(mut g) = cap.lock() {
                g.push(a);
            }
        });
    let cancel = detector.cancel_token();
    let task = tokio::spawn(async move { detector.run().await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let payload = build_a_with_cache_flush("LocalCam.local.", Ipv4Addr::UNSPECIFIED);
    for _ in 0..3 {
        send_from_iface(&payload, src_ip, port);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(common::settle()).await;

    cancel.cancel();
    drop(task.await);
    captured.lock().expect("lock").clone()
}

#[tokio::test]
async fn include_local_off_filters_traffic_from_local_interface() {
    let Some(iface_ip) = primary_v4_interface_ip() else {
        return;
    };
    let (mode, port) = isolated_mode(2);
    let anomalies = run_local_traffic_test(mode, port, false, iface_ip).await;
    assert!(
        anomalies.is_empty(),
        "with include_local=false, traffic from local interface must be filtered, got {anomalies:?}"
    );
}

#[tokio::test]
async fn include_local_on_observes_traffic_from_local_interface() {
    let Some(iface_ip) = primary_v4_interface_ip() else {
        return;
    };
    let (mode, port) = isolated_mode(3);
    let anomalies = run_local_traffic_test(mode, port, true, iface_ip).await;
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::CacheFlushRateExceeded { .. })),
        "with include_local=true, 3 cache-flush packets from local iface must fire \
         CacheFlushRateExceeded, got {anomalies:?}"
    );
}

#[tokio::test]
async fn detector_does_not_fire_multi_source_for_single_origin() {
    // Both packets come from 127.0.0.1, so by design `MultiSourceUniqueRr` must
    // not fire. The positive path requires distinct source IPs and is covered by
    // the unit test in `detect.rs`.
    let (mode, port) = isolated_mode(1);
    let captured: Arc<Mutex<Vec<Anomaly>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let detector = Detector::new(mode)
        .expect("detector")
        .with_event_callback(move |a| {
            if let Ok(mut g) = cap.lock() {
                g.push(a);
            }
        });
    let cancel = detector.cancel_token();
    let task = tokio::spawn(async move { detector.run().await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let p1 = build_a_with_cache_flush("Printer.local.", Ipv4Addr::new(192, 168, 1, 1));
    let p2 = build_a_with_cache_flush("Printer.local.", Ipv4Addr::new(192, 168, 1, 2));
    send_unicast(&p1, port);
    tokio::time::sleep(Duration::from_millis(100)).await;
    send_unicast(&p2, port);
    tokio::time::sleep(common::settle()).await;

    cancel.cancel();
    drop(task.await);

    let anomalies: Vec<Anomaly> = captured.lock().expect("lock").clone();
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::MultiSourceUniqueRr { .. })),
        "single-origin repeats must not fire MultiSourceUniqueRr, got {anomalies:?}"
    );
}
