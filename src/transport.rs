//! Private socket layer for mDNS traffic. Two sockets: one v4, one v6 (where available).
//!
//! `QueryOnly` mode skips the bind on 5353 and uses ephemeral source ports.
//! `Listen` and `Authoritative` bind 5353 with `SO_REUSEADDR + SO_REUSEPORT` and
//! join the multicast group on every non-loopback interface we find.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use socket2::{Domain, Protocol as SockProtocol, SockRef, Socket, Type};
use tokio::net::UdpSocket;

use crate::error::Result;
use crate::mode::Mode;

static IFACE_FILTER: OnceLock<Vec<String>> = OnceLock::new();

pub(crate) fn set_interface_filter(names: Vec<String>) {
    drop(IFACE_FILTER.set(names));
}

fn iface_allowed(name: &str) -> bool {
    match IFACE_FILTER.get() {
        Some(filter) if !filter.is_empty() => filter.iter().any(|n| n == name),
        _ => true,
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Destination {
    Multicast,
    #[allow(dead_code, reason = "reserved for directed mDNS responses")]
    Unicast(SocketAddr),
}

#[derive(Debug)]
pub(crate) struct Transport {
    pub(crate) mode: Mode,
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    v4_ifaces: Vec<Ipv4Addr>,
    v6_ifaces: Vec<u32>,
}

impl Transport {
    pub(crate) fn build(mode: Mode) -> Result<Self> {
        let (v4_ifaces, v6_ifaces) = list_interfaces()?;
        let v4 = build_v4_socket(mode, &v4_ifaces)?.map(Arc::new);
        let v6 = build_v6_socket(mode, &v6_ifaces)?.map(Arc::new);
        if v4.is_none() && v6.is_none() {
            return Err(crate::Error::NoInterface);
        }
        Ok(Self {
            mode,
            v4,
            v6,
            v4_ifaces,
            v6_ifaces,
        })
    }

    pub(crate) fn v4(&self) -> Option<Arc<UdpSocket>> {
        self.v4.clone()
    }

    pub(crate) fn is_local_addr(&self, ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => self.v4_ifaces.contains(&v4),
            // We track v6 by interface index, not address. For v6 conflict detection
            // a local-source filter is best-effort. Return false to be safe (will
            // log our own v6 announces as conflicts in the rare case we send any -
            // accept that v1 limitation).
            std::net::IpAddr::V6(_) => false,
        }
    }

    pub(crate) fn v6(&self) -> Option<Arc<UdpSocket>> {
        self.v6.clone()
    }

    pub(crate) async fn send_query(&self, payload: &[u8], dest: Destination) -> Result<()> {
        match dest {
            Destination::Multicast => {
                let mut sent = false;
                let mut last_err: Option<std::io::Error> = None;
                if let Some(s) = &self.v4 {
                    let addr = SocketAddr::new(IpAddr::V4(self.mode.group_v4()), self.mode.port());
                    for iface in &self.v4_ifaces {
                        let sock_ref = SockRef::from(s.as_ref());
                        if let Err(e) = sock_ref.set_multicast_if_v4(iface) {
                            tracing::debug!(error = %e, iface = %iface, "set_multicast_if_v4 failed before send");
                        }
                        match s.send_to(payload, addr).await {
                            Ok(_) => sent = true,
                            Err(e) => {
                                tracing::debug!(error = %e, iface = %iface, "v4 multicast send failed");
                                last_err = Some(e);
                            }
                        }
                    }
                }
                if let Some(s) = &self.v6 {
                    let addr = SocketAddr::new(IpAddr::V6(self.mode.group_v6()), self.mode.port());
                    for iface in &self.v6_ifaces {
                        let sock_ref = SockRef::from(s.as_ref());
                        if let Err(e) = sock_ref.set_multicast_if_v6(*iface) {
                            tracing::debug!(error = %e, iface_idx = *iface, "set_multicast_if_v6 failed before send");
                        }
                        match s.send_to(payload, addr).await {
                            Ok(_) => sent = true,
                            Err(e) => {
                                tracing::debug!(error = %e, iface_idx = *iface, "v6 multicast send failed");
                                last_err = Some(e);
                            }
                        }
                    }
                }
                if sent {
                    Ok(())
                } else {
                    Err(last_err
                        .unwrap_or_else(|| std::io::Error::other("no multicast socket"))
                        .into())
                }
            }
            Destination::Unicast(addr) => {
                let sock = match addr {
                    SocketAddr::V4(_) => self.v4.as_ref(),
                    SocketAddr::V6(_) => self.v6.as_ref(),
                };
                if let Some(s) = sock {
                    s.send_to(payload, addr).await?;
                }
                Ok(())
            }
        }
    }

    /// Wait for one inbound packet on whichever stack delivers first. Allocates a fresh
    /// buffer per call. Returns the truncated payload bytes.
    pub(crate) async fn recv_packet(&self) -> std::io::Result<Vec<u8>> {
        let v4 = self.v4.clone();
        let v6 = self.v6.clone();
        match (v4, v6) {
            (Some(s4), Some(s6)) => {
                let mut buf4 = vec![0u8; 9000];
                let mut buf6 = vec![0u8; 9000];
                tokio::select! {
                    r = s4.recv_from(&mut buf4) => {
                        let (n, _) = r?;
                        buf4.truncate(n);
                        Ok(buf4)
                    }
                    r = s6.recv_from(&mut buf6) => {
                        let (n, _) = r?;
                        buf6.truncate(n);
                        Ok(buf6)
                    }
                }
            }
            (Some(s), None) | (None, Some(s)) => {
                let mut buf = vec![0u8; 9000];
                let (n, _) = s.recv_from(&mut buf).await?;
                buf.truncate(n);
                Ok(buf)
            }
            (None, None) => Err(std::io::Error::other("no socket")),
        }
    }
}

fn list_interfaces() -> Result<(Vec<Ipv4Addr>, Vec<u32>)> {
    let ifaces = get_if_addrs::get_if_addrs()?;
    let mut v4 = Vec::with_capacity(ifaces.len());
    let mut v6 = Vec::with_capacity(ifaces.len());
    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        if !iface_allowed(&iface.name) {
            continue;
        }
        match iface.ip() {
            IpAddr::V4(a) => v4.push(a),
            IpAddr::V6(a) if a.is_unicast_link_local() => {
                if let Some(idx) = interface_index_for_v6(&iface.name) {
                    v6.push(idx);
                }
            }
            IpAddr::V6(_) => {}
        }
    }
    Ok((v4, v6))
}

fn interface_index_for_v6(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name).ok()
}

fn build_v4_socket(mode: Mode, ifaces: &[Ipv4Addr]) -> Result<Option<UdpSocket>> {
    let Some(first) = ifaces.first() else {
        return Ok(None);
    };
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_multicast_loop_v4(true)?;
    sock.set_nonblocking(true)?;
    if let Err(e) = sock.set_multicast_if_v4(first) {
        tracing::debug!(error = %e, iface = %first, "set_multicast_if_v4 failed, using kernel default");
    }

    if mode.binds_port() {
        let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), mode.port());
        sock.bind(&bind.into())?;
        for iface in ifaces {
            if let Err(e) = sock.join_multicast_v4(&mode.group_v4(), iface) {
                tracing::debug!(error = %e, iface = %iface, "join_multicast_v4 failed, skipping");
            }
        }
    } else {
        let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        sock.bind(&bind.into())?;
    }

    let std_sock: std::net::UdpSocket = sock.into();
    Ok(Some(UdpSocket::from_std(std_sock)?))
}

fn build_v6_socket(mode: Mode, ifaces: &[u32]) -> Result<Option<UdpSocket>> {
    let Some(first) = ifaces.first().copied() else {
        return Ok(None);
    };
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(SockProtocol::UDP))?;
    sock.set_only_v6(true)?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_multicast_loop_v6(true)?;
    sock.set_nonblocking(true)?;
    if let Err(e) = sock.set_multicast_if_v6(first) {
        tracing::debug!(error = %e, iface_idx = first, "set_multicast_if_v6 failed, using kernel default");
    }

    if mode.binds_port() {
        let bind: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), mode.port());
        sock.bind(&bind.into())?;
        for idx in ifaces {
            if let Err(e) = sock.join_multicast_v6(&mode.group_v6(), *idx) {
                tracing::debug!(error = %e, iface_idx = *idx, "join_multicast_v6 failed, skipping");
            }
        }
    } else {
        let bind: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        sock.bind(&bind.into())?;
    }

    let std_sock: std::net::UdpSocket = sock.into();
    Ok(Some(UdpSocket::from_std(std_sock)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_query_only_succeeds_without_bind() {
        let t = Transport::build(Mode::QueryOnly);
        assert!(t.is_ok(), "QueryOnly should always succeed: {t:?}");
    }

    #[tokio::test]
    async fn build_custom_mode_uses_custom_port() {
        let m = Mode::Custom {
            group_v4: Ipv4Addr::new(239, 255, 99, 99),
            group_v6: Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0, 0xabcd),
            port: 15353,
        };
        let t = Transport::build(m);
        assert!(t.is_ok(), "Custom should bind unused port: {t:?}");
    }
}
