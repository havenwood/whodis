//! Integration tests for `whodis sweep`.
//!
//! These tests require a live loopback interface that responds to ICMP echo.
//! On GitHub Actions macOS runners ICMP may be blocked; such tests are marked
//! `#[ignore]` and can be run locally with `cargo test -- --ignored`.

use std::time::Duration;

use whodis::sweep::{SweepOptions, sweep};

/// Sweep the loopback /32 and expect exactly one alive result.
///
/// Run locally: `cargo test sweep_loopback -- --ignored`
#[tokio::test]
#[ignore = "requires ICMP echo on loopback; run locally with cargo test -- --ignored"]
#[cfg(target_os = "macos")]
async fn sweep_loopback_returns_localhost_alive() {
    let net: ipnet::Ipv4Net = "127.0.0.1/32".parse().expect("cidr");
    let opts = SweepOptions {
        timeout: Duration::from_secs(1),
        max_concurrent: 1,
    };
    let results = sweep(net, opts).await.expect("sweep");
    assert_eq!(results.len(), 1, "expected exactly one probe result");
    let r = results.first().expect("first");
    assert_eq!(r.ip, "127.0.0.1".parse::<std::net::Ipv4Addr>().expect("ip"));
    assert!(r.alive, "127.0.0.1 should be alive");
    assert!(r.rtt.is_some(), "should have an rtt");
}

/// Sweep a single RFC 5737 test address (`198.51.100.1/32`) and expect it to be dead.
/// With `--show-dead` omitted the CLI emits 0 results; here we check the raw probe.
///
/// Run locally: `cargo test sweep_unreachable -- --ignored`
#[tokio::test]
#[ignore = "requires real network stack; run locally with cargo test -- --ignored"]
async fn sweep_unreachable_test_net_returns_dead_when_show_dead() {
    // RFC 5737 TEST-NET-2: 198.51.100.0/24 - should not be routable.
    let net: ipnet::Ipv4Net = "198.51.100.1/32".parse().expect("cidr");
    let opts = SweepOptions {
        timeout: Duration::from_millis(300),
        max_concurrent: 1,
    };
    let results = sweep(net, opts).await.expect("sweep");
    assert_eq!(results.len(), 1, "expected exactly one probe result");
    let r = results.first().expect("first");
    assert!(!r.alive, "198.51.100.1 should not be alive");
    assert!(r.rtt.is_none(), "dead host should have no rtt");
}
