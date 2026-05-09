mod common;

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use whodis::Authorization;
use whodis::name_res::llmnr::Responder;
use whodis::name_res::table::AnswerTable;

use crate::common::{llmnr_test_mode, settle};

#[tokio::test(flavor = "multi_thread")]
async fn responder_answers_for_matching_name() {
    let mode = llmnr_test_mode();
    let whodis::Mode::Custom { port, .. } = mode else {
        unreachable!("llmnr_test_mode is Mode::Custom")
    };

    let table = AnswerTable::from_toml(
        r#"[[name]]
           match  = "wpad"
           answer = "10.0.0.5"
        "#,
    )
    .expect("parse");

    let cancel = CancellationToken::new();
    let cancel_for_responder = cancel.clone();
    let join = tokio::spawn(async move {
        let r = Responder::new(mode, table, Authorization::new(), false).expect("responder");
        r.run(cancel_for_responder).await
    });

    tokio::time::sleep(settle()).await;

    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
    let mut q = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    let qname = Name::from_ascii("wpad.").expect("name");
    q.add_query(Query::query(qname, RecordType::A));
    let qbytes = q.to_bytes().expect("encode");
    // Unicast to loopback: macOS-15 CI restricts multicast routing.
    let dest: SocketAddr = format!("127.0.0.1:{port}").parse().expect("dest");
    probe.send_to(&qbytes, dest).await.expect("send");

    let mut buf = vec![0u8; 2048];
    let recv = tokio::time::timeout(Duration::from_secs(2), probe.recv_from(&mut buf))
        .await
        .expect("timeout")
        .expect("recv");
    let resp = Message::from_vec(buf.get(..recv.0).expect("slice")).expect("parse");
    assert_eq!(resp.metadata.message_type, MessageType::Response);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let a = resp.answers.first().expect("answer");
    assert_eq!(a.name.to_ascii(), "wpad.");

    cancel.cancel();
    drop(tokio::time::timeout(Duration::from_secs(1), join).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn responder_drops_query_outside_allow_list() {
    let mode = llmnr_test_mode();
    let whodis::Mode::Custom { port, .. } = mode else {
        unreachable!("llmnr_test_mode is Mode::Custom")
    };

    let table = AnswerTable::from_toml(
        r#"[[name]]
           match  = "wpad"
           answer = "10.0.0.5"
        "#,
    )
    .expect("parse");
    let auth = Authorization::new().allow_name("printserver");

    let cancel = CancellationToken::new();
    let cancel_for_responder = cancel.clone();
    let _join = tokio::spawn(async move {
        let r = Responder::new(mode, table, auth, false).expect("responder");
        r.run(cancel_for_responder).await
    });

    tokio::time::sleep(settle()).await;

    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    let qname = Name::from_ascii("wpad.").expect("name");
    q.add_query(Query::query(qname, RecordType::A));
    let qbytes = q.to_bytes().expect("encode");
    // Unicast to loopback: macOS-15 CI restricts multicast routing.
    let dest: SocketAddr = format!("127.0.0.1:{port}").parse().expect("dest");
    probe.send_to(&qbytes, dest).await.expect("send");

    let mut buf = vec![0u8; 2048];
    let recv = tokio::time::timeout(Duration::from_millis(500), probe.recv_from(&mut buf)).await;
    assert!(recv.is_err(), "expected no response, got {recv:?}");

    cancel.cancel();
}
