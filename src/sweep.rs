//! Active LAN host discovery via unprivileged ICMP echo (`SOCK_DGRAM` + `IPPROTO_ICMP`).
//!
//! No root, no setuid, no `ping` shell-out. macOS allows `SOCK_DGRAM` ICMP sockets
//! from unprivileged processes. After the sweep returns, callers can query the kernel
//! ARP cache (freshly populated by the outbound ICMP traffic) for MAC + vendor info.
//!
//! ## macOS recv quirk
//!
//! On macOS, `SOCK_DGRAM + IPPROTO_ICMP` reply buffers include the 20-byte IPv4
//! header prepended by the kernel. The ICMP type byte therefore sits at offset 20,
//! not offset 0. Linux strips the header; macOS does not.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::OwnedFd;
use std::time::{Duration, Instant};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Options for the ICMP sweep.
pub struct SweepOptions {
    /// Per-probe timeout.
    pub timeout: Duration,
    /// Maximum concurrent probes. 0 means unbounded.
    pub max_concurrent: usize,
}

impl Default for SweepOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(500),
            max_concurrent: 256,
        }
    }
}

/// Result of a single ICMP probe.
#[derive(Debug, Clone)]
pub struct SweepProbe {
    pub ip: Ipv4Addr,
    pub alive: bool,
    pub rtt: Option<Duration>,
}

fn open_icmp_socket() -> anyhow::Result<Socket> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).context("open ICMP DGRAM socket")
}

fn dead_sweep_probe(ip: Ipv4Addr) -> SweepProbe {
    SweepProbe {
        ip,
        alive: false,
        rtt: None,
    }
}

fn sweep_probe_from_result(ip: Ipv4Addr, result: anyhow::Result<Option<Duration>>) -> SweepProbe {
    match result {
        Ok(rtt) => SweepProbe {
            ip,
            alive: rtt.is_some(),
            rtt,
        },
        Err(e) => {
            tracing::debug!(ip = %ip, error = %e, "probe failed");
            dead_sweep_probe(ip)
        }
    }
}

/// Send one ICMP echo request and wait for an echo reply.
/// Returns `Some(rtt)` on success and `None` when the host does not reply.
async fn probe_one(
    target: Ipv4Addr,
    id: u16,
    seq: u16,
    t: Duration,
) -> anyhow::Result<Option<Duration>> {
    let result = timeout(t, async move {
        // Open an unprivileged ICMP DGRAM socket. Works without root on macOS.
        let sock2 = open_icmp_socket()?;

        let dst = SocketAddrV4::new(target, 0);
        if let Err(e) = sock2.connect(&dst.into()) {
            if is_dead_probe_io_error(&e) {
                return Ok(None);
            }
            return Err(e).context(format!("connect ICMP socket to {target}"));
        }

        // Convert to OwnedFd (safe, no unsafe block), then to std UdpSocket
        // so we can use plain &mut [u8] for recv instead of MaybeUninit.
        let owned: OwnedFd = sock2.into();
        let udp = UdpSocket::from(owned);
        udp.set_nonblocking(false)
            .context("set_nonblocking false")?;

        let pkt = build_echo_packet(id, seq);
        let start = Instant::now();

        // spawn_blocking: send + recv loop runs in a blocking thread.
        let send_res: anyhow::Result<Option<()>> = tokio::task::spawn_blocking(move || {
            if let Err(e) = udp.send(&pkt) {
                if is_dead_probe_io_error(&e) {
                    return Ok(None);
                }
                return Err(e).context(format!("send ICMP echo request to {target}"));
            }

            let mut buf = [0u8; 256];
            loop {
                let n = match udp.recv(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        if is_dead_probe_io_error(&e) {
                            return Ok(None);
                        }
                        return Err(e).context(format!("receive ICMP echo reply from {target}"));
                    }
                };
                #[allow(
                    clippy::indexing_slicing,
                    reason = "n is the byte count returned by recv, always <= buf.len()"
                )]
                if is_echo_reply(&buf[..n], id, seq) {
                    return Ok(Some(()));
                }
            }
        })
        .await
        .context("spawn_blocking join")?;

        send_res.map(|probe| probe.map(|()| start.elapsed()))
    })
    .await;

    match result {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

fn is_dead_probe_io_error(e: &io::Error) -> bool {
    const EWOULDBLOCK: i32 = 35;
    const EADDRNOTAVAIL: i32 = 49;
    const ENETDOWN: i32 = 50;
    const ENETUNREACH: i32 = 51;
    const ETIMEDOUT: i32 = 60;
    const ECONNREFUSED: i32 = 61;
    const EHOSTDOWN: i32 = 64;
    const EHOSTUNREACH: i32 = 65;

    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) || matches!(
        e.raw_os_error(),
        Some(
            EWOULDBLOCK
                | EADDRNOTAVAIL
                | ENETDOWN
                | ENETUNREACH
                | ETIMEDOUT
                | ECONNREFUSED
                | EHOSTDOWN
                | EHOSTUNREACH
        )
    )
}

/// Build an ICMP echo request packet (type=8, code=0).
pub(crate) fn build_echo_packet(id: u16, seq: u16) -> Vec<u8> {
    let mut pkt = [0u8; 8];
    pkt[0] = 8; // type: echo request
    pkt[1] = 0; // code
    // bytes 2-3: checksum (zero while computing)
    pkt[4] = (id >> 8) as u8;
    pkt[5] = (id & 0xff) as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = (seq & 0xff) as u8;
    let cksum = icmp_checksum(&pkt);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xff) as u8;
    pkt.to_vec()
}

/// Compute Internet checksum (RFC 1071).
pub(crate) fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let chunks = data.chunks_exact(2);
    let remainder = chunks.remainder();
    for chunk in chunks {
        if let [hi, lo] = *chunk {
            let word = (u32::from(hi) << 8) | u32::from(lo);
            sum = sum.wrapping_add(word);
        }
    }
    if let Some(&b) = remainder.first() {
        sum = sum.wrapping_add(u32::from(b) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parse two bytes from a `&[u8]` slice into a big-endian `u16`.
/// Returns 0 if the slice is shorter than 2 bytes.
fn read_u16_be(b: &[u8]) -> u16 {
    match (b.first(), b.get(1)) {
        (Some(&hi), Some(&lo)) => (u16::from(hi) << 8) | u16::from(lo),
        _ => 0,
    }
}

/// Check if `buf` is an ICMP echo reply (type=0) matching `id` and `seq`.
///
/// macOS `SOCK_DGRAM + IPPROTO_ICMP`: the kernel prepends the 20-byte IPv4
/// header before handing the datagram to userspace. The ICMP type byte sits at
/// offset 20, not offset 0.
pub(crate) fn is_echo_reply(buf: &[u8], id: u16, seq: u16) -> bool {
    // 20-byte IPv4 header + 8-byte ICMP header minimum.
    const HDR: usize = 20;
    const MIN: usize = HDR + 8;
    if buf.len() < MIN {
        return false;
    }
    let ty = buf.get(HDR).copied().unwrap_or(0xff);
    let code = buf.get(HDR + 1).copied().unwrap_or(0xff);
    if ty != 0 || code != 0 {
        return false;
    }
    let reply_id = buf.get(HDR + 4..HDR + 6).map_or(0, read_u16_be);
    let reply_seq = buf.get(HDR + 6..HDR + 8).map_or(0, read_u16_be);
    reply_id == id && reply_seq == seq
}

/// Sweep a CIDR block with ICMP echo probes.
///
/// Returns one `SweepProbe` per host in the network (excluding network and
/// broadcast addresses). Order of results is non-deterministic; sort by IP if
/// needed.
pub async fn sweep(net: ipnet::Ipv4Net, opts: SweepOptions) -> anyhow::Result<Vec<SweepProbe>> {
    let id = (std::process::id() & 0xffff) as u16;
    let hosts: Vec<Ipv4Addr> = net.hosts().collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    // Fail fast for setup-level problems that make the sweep impossible, such
    // as the platform refusing unprivileged ICMP sockets.
    drop(open_icmp_socket()?);

    let t = opts.timeout;
    let max = opts.max_concurrent;

    let sem = if max > 0 {
        Some(std::sync::Arc::new(Semaphore::new(max)))
    } else {
        None
    };

    let mut join_set: JoinSet<SweepProbe> = JoinSet::new();

    for (i, ip) in hosts.into_iter().enumerate() {
        let seq = (i & 0xffff) as u16;
        let sem_clone = sem.clone();

        join_set.spawn(async move {
            if let Some(s) = sem_clone {
                // If the semaphore is closed (process shutting down), report
                // the host as unreachable rather than panicking.
                let Ok(_permit) = s.acquire_owned().await else {
                    return dead_sweep_probe(ip);
                };
            }
            sweep_probe_from_result(ip, probe_one(ip, id, seq, t).await)
        });
    }

    let mut results = Vec::with_capacity(join_set.len());
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(probe) => results.push(probe),
            Err(e) => tracing::debug!(error = %e, "probe task panicked"),
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_echo_packet_has_correct_header() {
        let pkt = build_echo_packet(0x1234, 0x0001);
        assert_eq!(pkt.len(), 8);
        assert_eq!(pkt.first().copied(), Some(8), "ICMP type must be 8");
        assert_eq!(pkt.get(1).copied(), Some(0), "ICMP code must be 0");
        // Recomputing checksum over the complete packet must yield 0.
        let cksum = icmp_checksum(&pkt);
        assert_eq!(cksum, 0, "checksum over complete packet must be 0");
        // ID and seq encoded correctly.
        assert_eq!(pkt.get(4).copied(), Some(0x12_u8));
        assert_eq!(pkt.get(5).copied(), Some(0x34_u8));
        assert_eq!(pkt.get(6).copied(), Some(0x00_u8));
        assert_eq!(pkt.get(7).copied(), Some(0x01_u8));
    }

    #[test]
    fn parse_reply_skips_ipv4_header_offset_20() {
        // Build a buffer: 20 bytes of fake IPv4 header + 8 bytes of ICMP echo reply.
        let mut buf = [0u8; 28];
        // ICMP type=0 (echo reply) at offset 20
        buf[20] = 0; // type: echo reply
        buf[21] = 0; // code
        // id = 0xabcd
        buf[24] = 0xab;
        buf[25] = 0xcd;
        // seq = 0x0001
        buf[26] = 0x00;
        buf[27] = 0x01;

        assert!(is_echo_reply(&buf, 0xabcd, 0x0001));
        // Wrong id must not match
        assert!(!is_echo_reply(&buf, 0x1234, 0x0001));
        // Buffer too short to contain the IPv4 header must return false
        assert!(!is_echo_reply(&buf[..20], 0xabcd, 0x0001));
    }

    #[test]
    fn verify_id_and_seq_match_demuxes_correctly() {
        let make = |id: u16, seq: u16, ty: u8| {
            let mut buf = [0u8; 28];
            buf[20] = ty;
            buf[21] = 0;
            buf[24] = (id >> 8) as u8;
            buf[25] = (id & 0xff) as u8;
            buf[26] = (seq >> 8) as u8;
            buf[27] = (seq & 0xff) as u8;
            buf
        };

        let reply_a = make(0x0001, 0x0000, 0);
        let reply_b = make(0x0002, 0x0000, 0);

        assert!(is_echo_reply(&reply_a, 0x0001, 0x0000), "id=1 should match");
        assert!(
            !is_echo_reply(&reply_b, 0x0001, 0x0000),
            "id=2 should not match id=1"
        );
    }

    #[test]
    fn sweep_options_default_max_concurrent_is_256() {
        let opts = SweepOptions::default();
        assert_eq!(opts.max_concurrent, 256);
    }

    #[test]
    fn dead_probe_errors_do_not_include_permission_denied() {
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(
            !is_dead_probe_io_error(&e),
            "permission failures must surface instead of reporting every host dead"
        );
    }

    #[test]
    fn timeout_probe_errors_are_dead_hosts() {
        let e = io::Error::from(io::ErrorKind::TimedOut);
        assert!(is_dead_probe_io_error(&e));
    }

    #[test]
    fn sweep_probe_result_with_rtt_is_alive() {
        let ip = "192.168.50.6".parse().expect("ip");
        let rtt = Duration::from_millis(12);

        let probe = sweep_probe_from_result(ip, Ok(Some(rtt)));

        assert_eq!(probe.ip, ip);
        assert!(probe.alive);
        assert_eq!(probe.rtt, Some(rtt));
    }

    #[test]
    fn sweep_probe_result_without_rtt_is_dead() {
        let ip = "192.168.50.6".parse().expect("ip");

        let probe = sweep_probe_from_result(ip, Ok(None));

        assert_eq!(probe.ip, ip);
        assert!(!probe.alive);
        assert_eq!(probe.rtt, None);
    }

    #[test]
    fn sweep_probe_result_error_is_dead() {
        let ip = "192.168.50.6".parse().expect("ip");

        let probe = sweep_probe_from_result(ip, Err(anyhow::anyhow!("send failed")));

        assert_eq!(probe.ip, ip);
        assert!(!probe.alive);
        assert_eq!(probe.rtt, None);
    }
}
