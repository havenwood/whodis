#![allow(
    dead_code,
    reason = "shared test helpers, used selectively across files"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use whodis::Mode;
use whodis::spoof::{AnswerTable, AnswerTableBuilder, Responder};

pub(crate) const TEST_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 99, 99);
pub(crate) const TEST_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0, 0xabcd);
pub(crate) const TEST_PORT: u16 = 15353;

pub(crate) fn test_mode() -> Mode {
    Mode::Custom {
        group_v4: TEST_GROUP_V4,
        group_v6: TEST_GROUP_V6,
        port: TEST_PORT,
    }
}

pub(crate) fn fake_appletv_table() -> AnswerTable {
    let host = Name::from_utf8("FakeATV.local.").expect("name");
    AnswerTableBuilder::new()
        .ttl(60)
        .answer(
            "_pentest-test._tcp.local.",
            RecordType::PTR,
            RData::PTR(PTR(
                Name::from_utf8("FakeATV._pentest-test._tcp.local.").expect("name")
            )),
        )
        .expect("ptr")
        .answer(
            "FakeATV._pentest-test._tcp.local.",
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 7000, host)),
        )
        .expect("srv")
        .answer(
            "FakeATV._pentest-test._tcp.local.",
            RecordType::TXT,
            RData::TXT(TXT::new(vec!["model=AppleTV11,1".to_string()])),
        )
        .expect("txt")
        .answer(
            "FakeATV.local.",
            RecordType::A,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        )
        .expect("a")
        .build()
}

pub(crate) fn spawn_test_responder(table: AnswerTable) -> Responder {
    Responder::new(test_mode(), whodis::Authorization::new(), table, 1, None).expect("responder")
}

/// Build and send a single mDNS response containing PTR + SRV + TXT + A records
/// for `FakeATV._pentest-test._tcp.local.` to the test multicast group.
/// The browser must be running and joined to the group before calling this.
pub(crate) fn send_fake_appletv_announcement() {
    let instance = Name::from_utf8("FakeATV._pentest-test._tcp.local.").expect("instance name");
    let svc_type = Name::from_utf8("_pentest-test._tcp.local.").expect("svc type name");
    let host = Name::from_utf8("FakeATV.local.").expect("host name");

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.authoritative = true;
    msg.metadata.response_code = ResponseCode::NoError;

    // PTR: _pentest-test._tcp.local. -> FakeATV._pentest-test._tcp.local.
    let mut ptr_rec = Record::from_rdata(svc_type, 60, RData::PTR(PTR(instance.clone())));
    ptr_rec.dns_class = DNSClass::IN;
    msg.add_answer(ptr_rec);

    // SRV: FakeATV._pentest-test._tcp.local. -> FakeATV.local.:7000
    let mut srv_rec =
        Record::from_rdata(instance.clone(), 60, RData::SRV(SRV::new(0, 0, 7000, host)));
    srv_rec.dns_class = DNSClass::IN;
    msg.add_answer(srv_rec);

    // TXT: FakeATV._pentest-test._tcp.local. model=AppleTV11,1
    let mut txt_rec = Record::from_rdata(
        instance,
        60,
        RData::TXT(TXT::new(vec!["model=AppleTV11,1".to_string()])),
    );
    txt_rec.dns_class = DNSClass::IN;
    msg.add_answer(txt_rec);

    // A: FakeATV.local. -> 127.0.0.1
    let host = Name::from_utf8("FakeATV.local.").expect("host name");
    let mut a_rec = Record::from_rdata(host, 60, RData::A(A(Ipv4Addr::LOCALHOST)));
    a_rec.dns_class = DNSClass::IN;
    msg.add_answer(a_rec);

    let bytes = msg.to_bytes().expect("encode");

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind sender");
    sock.set_multicast_loop_v4(true).expect("multicast loop");
    let dst = SocketAddr::new(IpAddr::V4(TEST_GROUP_V4), TEST_PORT);
    sock.send_to(&bytes, dst).expect("send");
}

/// Send a TTL=0 goodbye for `FakeATV._pentest-test._tcp.local.` to the test group.
pub(crate) fn send_fake_appletv_goodbye() {
    let instance = Name::from_utf8("FakeATV._pentest-test._tcp.local.").expect("instance name");
    let svc_type = Name::from_utf8("_pentest-test._tcp.local.").expect("svc type name");

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.authoritative = true;
    msg.metadata.response_code = ResponseCode::NoError;

    // PTR with TTL=0 signals goodbye
    let mut ptr_rec = Record::from_rdata(svc_type, 0, RData::PTR(PTR(instance)));
    ptr_rec.dns_class = DNSClass::IN;
    msg.add_answer(ptr_rec);

    let bytes = msg.to_bytes().expect("encode");

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind sender");
    sock.set_multicast_loop_v4(true).expect("multicast loop");
    let dst = SocketAddr::new(IpAddr::V4(TEST_GROUP_V4), TEST_PORT);
    sock.send_to(&bytes, dst).expect("send");
}

pub(crate) fn settle() -> Duration {
    Duration::from_millis(500)
}
