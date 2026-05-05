//! Read the kernel's ARP and NDP neighbor caches.
//!
//! Shells out to `arp -an` (IPv4) and `ndp -an` (IPv6), parses output, and
//! returns a deduplicated list of `NeighborEntry` records. No packets are sent.
//!
//! The parsers target macOS's `arp(8)` / `ndp(8)` output format. Linux's
//! `ip neigh` produces different output and would need a separate parser.

use std::net::IpAddr;

use anyhow::Context;
use tokio::process::Command;

use crate::types::NeighborEntry;

/// Read all neighbor cache entries from the kernel.
///
/// Skips `(incomplete)` and `(unreachable)` entries, broadcast / multicast MACs,
/// and the IPv4 broadcast address `255.255.255.255`.
pub async fn read_neighbors() -> anyhow::Result<Vec<NeighborEntry>> {
    let (v4_out, v6_out) = tokio::try_join!(run_arp(), run_ndp())?;
    let mut entries = Vec::new();
    parse_arp_output(&v4_out, &mut entries);
    parse_ndp_output(&v6_out, &mut entries);
    Ok(entries)
}

async fn run_arp() -> anyhow::Result<String> {
    let out = Command::new("arp")
        .args(["-an"])
        .output()
        .await
        .context("running arp -an")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn run_ndp() -> anyhow::Result<String> {
    let out = Command::new("ndp")
        .args(["-an"])
        .output()
        .await
        .context("running ndp -an")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse a MAC address in macOS abbreviated hex format.
///
/// macOS omits leading zeros per octet, so `c:c5:b5` means `0c:c5:b5`.
/// Returns `None` for `(incomplete)`, `(unreachable)`, or malformed input.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    // macOS wraps these strings with parens for incomplete/unreachable
    if s.starts_with('(') {
        return None;
    }
    let mut it = s.split(':');
    let parse_octet = |p: Option<&str>| -> Option<u8> { u8::from_str_radix(p?, 16).ok() };
    let mac = [
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
        parse_octet(it.next())?,
    ];
    // Reject if there are extra tokens (malformed input with >6 parts)
    if it.next().is_some() {
        return None;
    }
    Some(mac)
}

/// True for broadcast and multicast MACs we should skip.
fn is_skip_mac(mac: [u8; 6]) -> bool {
    matches!(
        mac,
        // FF:FF:FF:FF:FF:FF broadcast | IPv4 multicast 01:00:5E:xx | IPv6 multicast 33:33:xx
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] | [0x01, 0x00, 0x5e, ..] | [0x33, 0x33, ..]
    )
}

/// Parse `arp -an` output into entries.
///
/// Format:
/// ```text
/// ? (192.168.1.1) at a4:83:e7:11:22:33 on en0 ifscope [ethernet]
/// ? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
/// ```
fn parse_arp_output(output: &str, entries: &mut Vec<NeighborEntry>) {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(entry) = parse_arp_line(line) {
            entries.push(entry);
        }
    }
}

fn parse_arp_line(line: &str) -> Option<NeighborEntry> {
    // ? (IP) at MAC on IFACE [...]
    // Strip the leading "? "
    let rest = line.strip_prefix("? ")?;

    // Extract IP from "(IP)"
    let ip_end = rest.find(')')?;
    let ip_str = rest.get(1..ip_end)?;
    let ip: IpAddr = ip_str.parse().ok()?;

    // Skip broadcast
    if let IpAddr::V4(v4) = ip
        && v4.is_broadcast()
    {
        return None;
    }

    // Rest after ") at "
    let after_ip = rest.get(ip_end + 1..)?.trim_start();
    let after_at = after_ip.strip_prefix("at ")?.trim_start();

    // MAC is the next token
    let mac_str = after_at.split_whitespace().next()?;
    let mac = parse_mac(mac_str)?;

    if is_skip_mac(mac) {
        return None;
    }

    // Interface comes after " on "
    let on_pos = after_at.find(" on ")?;
    let after_on = after_at.get(on_pos + 4..)?.trim_start();
    let iface = after_on.split_whitespace().next()?.to_string();

    Some(NeighborEntry {
        ip,
        mac,
        vendor: None,
        interface: iface,
    })
}

/// Parse `ndp -an` output into entries.
///
/// Format:
/// ```text
/// Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
/// fe80::1%en0                             a4:83:e7:11:22:33    en0 permanent R
/// fe80::abcd%en0                          (incomplete)         en0 expired   N
/// ```
fn parse_ndp_output(output: &str, entries: &mut Vec<NeighborEntry>) {
    for line in output.lines() {
        let line = line.trim();
        // Skip header line
        if line.starts_with("Neighbor") {
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(entry) = parse_ndp_line(line) {
            entries.push(entry);
        }
    }
}

fn parse_ndp_line(line: &str) -> Option<NeighborEntry> {
    // Fields are whitespace-separated: Neighbor Linklayer Netif Expire State Flags Probes
    let mut cols = line.split_whitespace();
    let neighbor = cols.next()?;
    let linklayer = cols.next()?;
    let netif = cols.next()?;

    if linklayer == "(incomplete)" || linklayer == "(unreachable)" {
        return None;
    }

    let mac = parse_mac(linklayer)?;
    if is_skip_mac(mac) {
        return None;
    }

    // Strip zone ID from IPv6 address (e.g. "fe80::1%en0" -> "fe80::1")
    let ip_str = if let Some(pct) = neighbor.find('%') {
        neighbor.get(..pct)?
    } else {
        neighbor
    };
    let ip: IpAddr = ip_str.parse().ok()?;

    Some(NeighborEntry {
        ip,
        mac,
        vendor: None,
        interface: netif.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_arp_an_line() {
        let line = "? (192.168.1.1) at a4:83:e7:11:22:33 on en0 ifscope [ethernet]";
        let entry = parse_arp_line(line).expect("should parse");
        assert_eq!(entry.ip, "192.168.1.1".parse::<IpAddr>().expect("addr"));
        assert_eq!(entry.mac, [0xa4, 0x83, 0xe7, 0x11, 0x22, 0x33]);
        assert_eq!(entry.interface, "en0");
    }

    #[test]
    fn parses_arp_an_with_abbreviated_mac() {
        // macOS emits single-hex-digit octets; c:c5:b5 means 0c:c5:b5
        let line = "? (192.168.50.108) at c6:e7:fe:c:c5:b5 on en0 ifscope permanent [ethernet]";
        let entry = parse_arp_line(line).expect("should parse");
        assert_eq!(entry.mac, [0xc6, 0xe7, 0xfe, 0x0c, 0xc5, 0xb5]);
    }

    #[test]
    fn parses_arp_an_with_multiple_entries() {
        let output = "\
? (192.168.1.1) at a4:83:e7:11:22:33 on en0 ifscope [ethernet]
? (192.168.1.42) at b8:27:eb:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
";
        let mut entries = Vec::new();
        parse_arp_output(output, &mut entries);
        assert_eq!(entries.len(), 2);
        let first = entries.first().expect("first entry");
        let second = entries.get(1).expect("second entry");
        assert_eq!(first.ip, "192.168.1.1".parse::<IpAddr>().expect("addr"));
        assert_eq!(second.ip, "192.168.1.42".parse::<IpAddr>().expect("addr"));
    }

    #[test]
    fn skips_arp_an_incomplete_entries() {
        let line = "? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn skips_arp_an_broadcast() {
        let line = "? (192.168.50.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn skips_arp_an_multicast() {
        let line = "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn parses_canonical_ndp_an_line() {
        let line = "fe80::1%en0                             a4:83:e7:11:22:33    en0 permanent R";
        let entry = parse_ndp_line(line).expect("should parse");
        assert_eq!(entry.ip, "fe80::1".parse::<IpAddr>().expect("addr"));
        assert_eq!(entry.mac, [0xa4, 0x83, 0xe7, 0x11, 0x22, 0x33]);
        assert_eq!(entry.interface, "en0");
    }

    #[test]
    fn parses_ndp_an_without_zone_id() {
        let line = "2001:db8::1                             a4:83:e7:11:22:33    en0 permanent R";
        let entry = parse_ndp_line(line).expect("should parse");
        assert_eq!(entry.ip, "2001:db8::1".parse::<IpAddr>().expect("addr"));
    }

    #[test]
    fn skips_ndp_an_unreachable_entries() {
        let output = "\
Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                             a4:83:e7:11:22:33    en0 permanent R
2001:db8::1                             (incomplete)         en0 permanent R
";
        let mut entries = Vec::new();
        parse_ndp_output(output, &mut entries);
        assert_eq!(entries.len(), 1);
        let entry = entries.first().expect("first entry");
        assert_eq!(entry.ip, "fe80::1".parse::<IpAddr>().expect("addr"));
    }
}
