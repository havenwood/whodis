//! Integration test: Detector with --llmnr fires `LlmnrPoisonResponder`.

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;

use whodis::detect::{Anomaly, Detector};

use crate::common::{llmnr_test_mode, settle, test_mode};

fn has_wpad_poison(captured: &Arc<Mutex<Vec<Anomaly>>>) -> bool {
    let Ok(g) = captured.lock() else {
        return false;
    };
    g.iter().any(|a| {
        matches!(
            a,
            Anomaly::LlmnrPoisonResponder { name, .. } if name == "wpad"
        )
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_llmnr_emits_poison_anomaly() {
    let mdns_mode = test_mode();
    let llmnr_mode = llmnr_test_mode();
    let whodis::Mode::Custom {
        port: llmnr_port, ..
    } = llmnr_mode
    else {
        unreachable!("llmnr_test_mode is Mode::Custom")
    };

    let captured: Arc<Mutex<Vec<Anomaly>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_cb = captured.clone();
    let detector = Detector::new(mdns_mode)
        .expect("detector new")
        .with_llmnr_mode(llmnr_test_mode())
        .expect("with_llmnr_mode")
        .with_include_local(true)
        .with_event_callback(move |a| {
            if let Ok(mut g) = captured_for_cb.lock() {
                g.push(a);
            }
        });
    let cancel = detector.cancel_token();

    let run_handle = tokio::spawn(async move { detector.run().await });

    tokio::time::sleep(settle()).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let mut resp = Message::new(0xABCD, MessageType::Response, OpCode::Query);
    resp.metadata.response_code = ResponseCode::NoError;
    let name = Name::from_ascii("wpad.").expect("name");
    resp.add_query(Query::query(name.clone(), RecordType::A));
    resp.add_answer(Record::from_rdata(
        name,
        30,
        RData::A(A([10, 0, 0, 5].into())),
    ));
    let bytes = resp.to_bytes().expect("encode");
    // Unicast to loopback: macOS-15 CI restricts multicast routing.
    let dest = format!("127.0.0.1:{llmnr_port}");
    sock.send_to(&bytes, &dest).await.expect("send");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if has_wpad_poison(&captured) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
    }

    assert!(
        has_wpad_poison(&captured),
        "expected LlmnrPoisonResponder for wpad"
    );

    cancel.cancel();
    let _outcome = tokio::time::timeout(Duration::from_secs(1), run_handle).await;
}
