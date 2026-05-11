//! Integration test: drive the inventory graph through a deterministic
//! observation sequence and verify cross-source fusion plus evidence
//! disclosure.

use std::time::{Duration, SystemTime};

use whodis::ble::{DeviceClass, PeripheralId};
use whodis::inventory::log::{append, replay_into};
use whodis::inventory::{Confidence, IdentityGraph, LinkKind, Observation};

fn now0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(10_000)
}

#[test]
fn arp_mdns_ssdp_fuse_into_one_candidate_with_full_evidence() {
    let mut g = IdentityGraph::new();
    let ip = "10.0.5.20".parse::<std::net::IpAddr>().expect("ip");

    drop(g.observe(Observation::Neighbor {
        ip,
        mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        vendor: Some("Apple".into()),
        interface: "en0".into(),
        observed_at: now0(),
    }));
    drop(g.observe(Observation::MdnsInstance {
        fqdn: "Living._airplay._tcp.local.".into(),
        service_type: "_airplay._tcp.local.".into(),
        instance_name: "Living".into(),
        host: "AppleTV.local.".into(),
        port: 7000,
        addrs: vec![ip],
        txt: std::collections::BTreeMap::new(),
        observed_at: now0() + Duration::from_secs(1),
    }));
    drop(g.observe(Observation::SsdpService {
        usn: "uuid:appletv::urn:dial-multiscreen-org:service:dial:1".into(),
        st: "urn:dial-multiscreen-org:service:dial:1".into(),
        location: Some("http://10.0.5.20:8060/dial/dd.xml".into()),
        server: Some("Roku UPnP/1.0 MiniUPnPd/1.4".into()),
        src_ip: ip,
        max_age: Some(1800),
        observed_at: now0() + Duration::from_secs(2),
    }));

    assert_eq!(g.len(), 1, "ARP + mDNS + SSDP fuse by IP");
    let c = g.candidates().next().expect("one");

    assert!(c.ips.contains(&ip), "IP attached");
    assert!(
        c.macs.contains(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        "MAC attached"
    );
    assert!(
        c.hostnames.iter().any(|h| h == "AppleTV.local."),
        "hostname attached"
    );
    assert_eq!(c.mdns_services.len(), 1);
    assert_eq!(c.ssdp_services.len(), 1);

    assert!(
        c.evidence.iter().any(|e| e.kind == LinkKind::SameMac),
        "evidence: SameMac missing"
    );
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == LinkKind::MdnsInstanceTargetsHost),
        "evidence: MdnsInstanceTargetsHost missing"
    );
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == LinkKind::HostnameResolvesToIp),
        "evidence: HostnameResolvesToIp missing"
    );
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == LinkKind::SsdpLocationOnIp),
        "evidence: SsdpLocationOnIp missing"
    );

    assert!(
        c.evidence
            .iter()
            .any(|e| e.confidence == Confidence::VeryHigh),
        "expected at least one VeryHigh-confidence evidence link"
    );
}

#[test]
fn ble_with_matching_local_name_attaches_satellite_but_keeps_own_root() {
    let mut g = IdentityGraph::new();
    let ip = "10.0.5.20".parse::<std::net::IpAddr>().expect("ip");

    drop(g.observe(Observation::Neighbor {
        ip,
        mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        vendor: None,
        interface: "en0".into(),
        observed_at: now0(),
    }));
    drop(g.observe(Observation::MdnsInstance {
        fqdn: "Shannon's iPhone._companion-link._tcp.local.".into(),
        service_type: "_companion-link._tcp.local.".into(),
        instance_name: "Shannon's iPhone".into(),
        host: "iPhone.local.".into(),
        port: 49152,
        addrs: vec![ip],
        txt: std::collections::BTreeMap::new(),
        observed_at: now0() + Duration::from_secs(1),
    }));
    assert_eq!(g.len(), 1, "ARP + mDNS fuse");

    drop(g.observe(Observation::BleDevice {
        peripheral_id: PeripheralId::new("CB-UUID-XYZ"),
        local_name: Some("iPhone.local.".into()),
        vendor: Some("Apple".into()),
        product: None,
        device_class: DeviceClass::Phone,
        rssi: -50,
        service_uuids: vec![],
        observed_at: now0() + Duration::from_secs(2),
    }));

    assert_eq!(g.len(), 2, "BLE creates own root Candidate, never merges");

    let with_sat = g
        .candidates()
        .find(|c| !c.mdns_services.is_empty())
        .expect("ip-having candidate");
    assert_eq!(with_sat.ble_satellites.len(), 1);
    let sat = with_sat.ble_satellites.first().expect("satellite present");
    assert!(
        sat.evidence
            .iter()
            .any(|e| e.kind == LinkKind::BleNameMatchesMdnsName && e.confidence == Confidence::Low),
        "satellite carries low-confidence BleNameMatchesMdnsName evidence"
    );
}

#[test]
fn jsonl_log_replay_round_trips_with_evidence_preserved() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "whodis-inventory-it-{}-{}.jsonl",
        std::process::id(),
        nanos
    ));
    drop(std::fs::remove_file(&path));

    let ip = "10.0.5.20".parse::<std::net::IpAddr>().expect("ip");
    let obs_a = Observation::Neighbor {
        ip,
        mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        vendor: Some("Apple".into()),
        interface: "en0".into(),
        observed_at: now0(),
    };
    let obs_b = Observation::MdnsInstance {
        fqdn: "Living._airplay._tcp.local.".into(),
        service_type: "_airplay._tcp.local.".into(),
        instance_name: "Living".into(),
        host: "AppleTV.local.".into(),
        port: 7000,
        addrs: vec![ip],
        txt: std::collections::BTreeMap::new(),
        observed_at: now0() + Duration::from_secs(1),
    };
    append(&path, &obs_a).expect("append a");
    append(&path, &obs_b).expect("append b");

    let mut g = IdentityGraph::new();
    let n = replay_into(&mut g, &path).expect("replay");
    assert!(n >= 2);
    assert_eq!(g.len(), 1);
    let c = g.candidates().next().expect("one");
    assert!(c.evidence.iter().any(|e| e.kind == LinkKind::SameMac));
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == LinkKind::MdnsInstanceTargetsHost)
    );

    drop(std::fs::remove_file(&path));
}
