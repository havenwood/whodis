//! LLMNR (RFC 4795) wire layer.
//!
//! LLMNR is essentially DNS over UDP/5355 to a link-local multicast
//! group. We reuse hickory-proto for message encoding; the only
//! protocol-level difference for our purposes is the destination
//! group + port and the C bit handling on conflict-aware queries
//! (which we don't send).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::mode::Mode;

pub const LLMNR_PORT: u16 = 5355;
pub const LLMNR_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
pub const LLMNR_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3);

#[must_use]
pub fn llmnr_mode() -> Mode {
    Mode::Custom {
        group_v4: LLMNR_GROUP_V4,
        group_v6: LLMNR_GROUP_V6,
        port: LLMNR_PORT,
    }
}

#[must_use]
pub fn is_llmnr_dest(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4 == LLMNR_GROUP_V4,
        IpAddr::V6(v6) => v6 == LLMNR_GROUP_V6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llmnr_mode_uses_canonical_group_and_port() {
        let Mode::Custom {
            group_v4,
            group_v6,
            port,
        } = llmnr_mode()
        else {
            unreachable!("llmnr_mode constructs Mode::Custom directly")
        };
        assert_eq!(group_v4, LLMNR_GROUP_V4);
        assert_eq!(group_v6, LLMNR_GROUP_V6);
        assert_eq!(port, LLMNR_PORT);
    }
}
