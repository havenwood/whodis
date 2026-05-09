mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use common::{LLMNR_TEST_PORT, llmnr_test_mode, settle};

#[tokio::test(flavor = "multi_thread")]
async fn probe_llmnr_collects_response() {
    let mode = llmnr_test_mode();

    let cancel = CancellationToken::new();
    let mode_for_probe = mode;
    let cancel_for_probe = cancel.clone();
    let answers_handle = tokio::spawn(async move {
        whodis::probe::probe_llmnr_with_mode(
            "wpad",
            false,
            Duration::from_secs(2),
            mode_for_probe,
            cancel_for_probe,
        )
        .await
    });

    tokio::time::sleep(settle()).await;

    // Build a synthetic LLMNR response and send it to the test multicast group.
    let mut resp = Message::new(0xABCD, MessageType::Query, OpCode::Query);
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NoError;

    let name = Name::from_ascii("wpad.").expect("name");
    resp.add_query(Query::query(name.clone(), RecordType::A));
    resp.add_answer(Record::from_rdata(
        name,
        30,
        RData::A(A(Ipv4Addr::new(10, 0, 0, 5))),
    ));
    let bytes = resp.to_bytes().expect("encode");

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    // Unicast to loopback rather than the multicast group: macOS-15 CI
    // runners restrict multicast routing, and the probe's transport binds
    // UNSPECIFIED:port so unicast still reaches it.
    let dest = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), LLMNR_TEST_PORT);
    sock.send_to(&bytes, dest).await.expect("send");

    let result = answers_handle.await.expect("join").expect("probe ok");
    assert!(
        result.iter().any(|a| a.addr.to_string() == "10.0.0.5"),
        "expected 10.0.0.5 in answers, got {result:?}"
    );
}
