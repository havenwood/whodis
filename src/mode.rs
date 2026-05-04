//! Transport mode selection.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    QueryOnly,
    Listen,
    Authoritative,
    Custom {
        group_v4: Ipv4Addr,
        group_v6: Ipv6Addr,
        port: u16,
    },
}

impl Mode {
    #[must_use]
    pub const fn group_v4(self) -> Ipv4Addr {
        match self {
            Self::Custom { group_v4, .. } => group_v4,
            _ => MDNS_GROUP_V4,
        }
    }

    #[must_use]
    pub const fn group_v6(self) -> Ipv6Addr {
        match self {
            Self::Custom { group_v6, .. } => group_v6,
            _ => MDNS_GROUP_V6,
        }
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::Custom { port, .. } => port,
            _ => MDNS_PORT,
        }
    }

    #[must_use]
    pub const fn binds_port(self) -> bool {
        matches!(
            self,
            Self::Listen | Self::Authoritative | Self::Custom { .. }
        )
    }

    #[must_use]
    pub const fn sends_responses(self) -> bool {
        matches!(self, Self::Authoritative | Self::Custom { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_standard_mdns_constants() {
        assert_eq!(Mode::QueryOnly.port(), 5353);
        assert_eq!(Mode::Listen.group_v4(), MDNS_GROUP_V4);
        assert_eq!(Mode::Authoritative.group_v6(), MDNS_GROUP_V6);
    }

    #[test]
    fn custom_overrides_all_three() {
        let m = Mode::Custom {
            group_v4: Ipv4Addr::new(239, 255, 99, 99),
            group_v6: Ipv6Addr::LOCALHOST,
            port: 15353,
        };
        assert_eq!(m.port(), 15353);
        assert_eq!(m.group_v4(), Ipv4Addr::new(239, 255, 99, 99));
    }

    #[test]
    fn query_only_does_not_bind() {
        assert!(!Mode::QueryOnly.binds_port());
        assert!(Mode::Listen.binds_port());
        assert!(Mode::Authoritative.binds_port());
    }

    #[test]
    fn only_authoritative_sends_responses() {
        assert!(!Mode::QueryOnly.sends_responses());
        assert!(!Mode::Listen.sends_responses());
        assert!(Mode::Authoritative.sends_responses());
    }
}
