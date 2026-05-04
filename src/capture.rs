//! mDNS pcap capture.

use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::mode::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, Mode};
use crate::transport::Transport;

const SNAPLEN: u32 = 65535;
const LINKTYPE_RAW: u32 = 101;

pub(crate) async fn run(path: &Path, timeout: u64) -> Result<usize> {
    let file = std::fs::File::create(path)?;
    let mut w = BufWriter::new(file);
    write_global_header(&mut w)?;

    let transport = Arc::new(Transport::build(Mode::Listen)?);
    let v4 = transport.v4();
    let v6 = transport.v6();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_for_signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_for_signal.cancel();
        }
    });

    let deadline = if timeout == 0 {
        None
    } else {
        Some(tokio::time::Instant::now() + Duration::from_secs(timeout))
    };

    let mut count = 0_usize;
    loop {
        if let Some(d) = deadline {
            if tokio::time::Instant::now() >= d {
                break;
            }
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            res = recv_one(v4.as_ref(), v6.as_ref()) => {
                match res {
                    Ok(Some((payload, src))) => {
                        if let Err(e) = write_packet(&mut w, src, &payload) {
                            tracing::debug!(error = %e, "pcap write failed; continuing");
                            continue;
                        }
                        count += 1;
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!(error = %e, "rx error, continuing"),
                }
            }
        }
    }
    w.flush()?;
    Ok(count)
}

async fn recv_one(
    v4: Option<&Arc<tokio::net::UdpSocket>>,
    v6: Option<&Arc<tokio::net::UdpSocket>>,
) -> std::io::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut buf = vec![0u8; SNAPLEN as usize];
    match (v4, v6) {
        (Some(s4), Some(s6)) => {
            let mut buf2 = vec![0u8; SNAPLEN as usize];
            tokio::select! {
                r = s4.recv_from(&mut buf) => r.map(|(n, a)| {
                    buf.truncate(n);
                    Some((buf, a))
                }),
                r = s6.recv_from(&mut buf2) => r.map(|(n, a)| {
                    buf2.truncate(n);
                    Some((buf2, a))
                }),
            }
        }
        (Some(s4), None) => s4.recv_from(&mut buf).await.map(|(n, a)| {
            buf.truncate(n);
            Some((buf, a))
        }),
        (None, Some(s6)) => s6.recv_from(&mut buf).await.map(|(n, a)| {
            buf.truncate(n);
            Some((buf, a))
        }),
        (None, None) => Ok(None),
    }
}

fn write_global_header(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?;
    w.write_all(&2_u16.to_le_bytes())?;
    w.write_all(&4_u16.to_le_bytes())?;
    w.write_all(&0_i32.to_le_bytes())?;
    w.write_all(&0_u32.to_le_bytes())?;
    w.write_all(&SNAPLEN.to_le_bytes())?;
    w.write_all(&LINKTYPE_RAW.to_le_bytes())?;
    Ok(())
}

#[allow(
    clippy::similar_names,
    reason = "ts_sec and ts_usec are standard pcap field names; renaming would obscure the spec"
)]
fn write_packet(w: &mut impl Write, src: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts_sec = u32::try_from(now.as_secs()).unwrap_or(u32::MAX);
    let ts_usec = now.subsec_micros();

    let pkt = match src.ip() {
        IpAddr::V4(src_ip) => {
            build_v4_packet(src_ip, MDNS_GROUP_V4, src.port(), MDNS_PORT, payload)
        }
        IpAddr::V6(src_ip) => {
            build_v6_packet(src_ip, MDNS_GROUP_V6, src.port(), MDNS_PORT, payload)
        }
    };

    let len = u32::try_from(pkt.len()).unwrap_or(SNAPLEN);
    w.write_all(&ts_sec.to_le_bytes())?;
    w.write_all(&ts_usec.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&pkt)?;
    Ok(())
}

fn build_v4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = u16::try_from(20 + 8 + payload.len()).unwrap_or(u16::MAX);
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45;
    hdr[1] = 0x00;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&0_u16.to_be_bytes());
    hdr[6..8].copy_from_slice(&0_u16.to_be_bytes());
    hdr[8] = 255;
    hdr[9] = 17;
    // bytes 10..12 left zero for checksum computation
    hdr[12..16].copy_from_slice(&src.octets());
    hdr[16..20].copy_from_slice(&dst.octets());
    let csum = ipv4_checksum(&hdr);
    hdr[10..12].copy_from_slice(&csum.to_be_bytes());

    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&0_u16.to_be_bytes());

    let mut out = Vec::with_capacity(20 + 8 + payload.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&udp);
    out.extend_from_slice(payload);
    out
}

fn build_v6_packet(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut hdr = [0u8; 40];
    hdr[0..4].copy_from_slice(&0x6000_0000_u32.to_be_bytes());
    hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
    hdr[6] = 17;
    hdr[7] = 255;
    hdr[8..24].copy_from_slice(&src.octets());
    hdr[24..40].copy_from_slice(&dst.octets());

    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&0xffff_u16.to_be_bytes());

    let mut out = Vec::with_capacity(40 + 8 + payload.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&udp);
    out.extend_from_slice(payload);
    out
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let hi = chunk.first().copied().unwrap_or(0);
        let lo = chunk.get(1).copied().unwrap_or(0);
        let word = u16::from_be_bytes([hi, lo]);
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum & 0xffff).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_writes_24_bytes() {
        let mut buf = Vec::new();
        write_global_header(&mut buf).expect("write");
        assert_eq!(buf.len(), 24);
        assert_eq!(
            buf.get(0..4),
            Some(0xa1b2_c3d4_u32.to_le_bytes().as_slice())
        );
        assert_eq!(
            buf.get(20..24),
            Some(LINKTYPE_RAW.to_le_bytes().as_slice())
        );
    }

    #[test]
    fn v4_packet_has_right_length() {
        let payload = b"hello";
        let pkt = build_v4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            5353,
            payload,
        );
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt.first().copied(), Some(0x45));
        assert_eq!(pkt.get(9).copied(), Some(17));
    }

    #[test]
    fn ipv4_checksum_matches_known_value() {
        let hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let cs = ipv4_checksum(&hdr);
        assert_eq!(cs, 0xb861);
    }

    #[test]
    fn write_packet_produces_correct_record_size() {
        let src: SocketAddr = "10.0.0.1:5353".parse().expect("addr");
        let payload = b"mdns";
        let mut buf = Vec::new();
        write_packet(&mut buf, src, payload).expect("write");
        // 16-byte pcap record header + 20 IPv4 + 8 UDP + payload
        assert_eq!(buf.len(), 16 + 20 + 8 + payload.len());
    }

}
