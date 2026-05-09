//! Integration test for `ssdp::clone_device`. Spawns an `SsdpResponder` with a
//! known device, runs clone against its USN, and verifies the resulting TOML
//! round-trips through `ssdp_table::load` with all the expected fields.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use whodis::Authorization;
use whodis::ssdp::{self, SsdpResponder};
use whodis::ssdp_table::{self, SsdpAnswerTable};

fn build_table(http_port: u16) -> SsdpAnswerTable {
    let toml_src = format!(
        r#"
            ttl = 60
            http_port = {http_port}

            [[device]]
            usn = "uuid:whodis-clone-test::urn:test:device:CloneMe:1"
            st = "urn:test:device:CloneMe:1"
            location_path = "/desc.xml"
            server = "WhodisClone/1.0 UPnP/1.0"
            description_xml = "<?xml version=\"1.0\"?><root><device><friendlyName>Clone Me</friendlyName></device></root>"
        "#
    );
    ssdp_table::load(&toml_src).expect("load table")
}

fn pick_free_port() -> u16 {
    let s = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let p = s.local_addr().expect("addr").port();
    drop(s);
    p
}

#[tokio::test]
async fn clone_device_captures_usn_st_server_and_description_xml() {
    let http_port = pick_free_port();
    let table = build_table(http_port);
    let responder = SsdpResponder::new(Authorization::new(), table, Ipv4Addr::LOCALHOST, None)
        .expect("build");
    let cancel = responder.cancel_token();
    let task = tokio::spawn(async move { responder.run().await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let cloned = ssdp::clone_device(
        "uuid:whodis-clone-test::urn:test:device:CloneMe:1",
        Duration::from_secs(3),
    )
    .await
    .expect("clone_device");

    assert_eq!(cloned.usn, "uuid:whodis-clone-test::urn:test:device:CloneMe:1");
    assert_eq!(cloned.st, "urn:test:device:CloneMe:1");
    assert_eq!(cloned.location_path, "/desc.xml");
    assert_eq!(cloned.http_port, http_port);
    assert_eq!(cloned.server.as_deref(), Some("WhodisClone/1.0 UPnP/1.0"));
    assert!(
        cloned.description_xml.contains("<friendlyName>Clone Me</friendlyName>"),
        "got: {}",
        cloned.description_xml
    );

    // Round-trip: emitted TOML loads back through ssdp_table::load.
    let toml_src = cloned.to_toml();
    let reloaded = ssdp_table::load(&toml_src).expect("reload TOML");
    let dev = reloaded
        .devices
        .first()
        .expect("at least one device after reload");
    assert_eq!(dev.usn, "uuid:whodis-clone-test::urn:test:device:CloneMe:1");
    assert_eq!(dev.st, "urn:test:device:CloneMe:1");
    assert_eq!(dev.location_path, "/desc.xml");

    cancel.cancel();
    drop(task.await);
}

#[tokio::test]
async fn clone_device_returns_no_records_for_unknown_usn() {
    // No responder running. clone_device should time out and return NoRecords.
    let result = ssdp::clone_device(
        "uuid:does-not-exist::urn:test:device:Nope:1",
        Duration::from_millis(800),
    )
    .await;
    assert!(result.is_err(), "expected Err for missing target");
}
