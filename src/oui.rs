//! OUI vendor lookup backed by a compile-time-generated static table.

include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

/// Look up the IEEE-assigned vendor name for the first three octets of a MAC address.
///
/// Returns `None` for locally-administered or unassigned OUIs.
#[must_use]
pub(crate) fn lookup(mac: [u8; 6]) -> Option<&'static str> {
    let [o0, o1, o2, ..] = mac;
    let key = (u32::from(o0) << 16) | (u32::from(o1) << 8) | u32::from(o2);
    let idx = OUI_TABLE.partition_point(|(k, _)| *k < key);
    if let Some(&(k, name)) = OUI_TABLE.get(idx)
        && k == key
    {
        return Some(name);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_finds_known_apple_oui() {
        // a4:83:e7 is "Apple, Inc." per IEEE MA-L registry
        let mac = [0xa4, 0x83, 0xe7, 0x00, 0x00, 0x00];
        let vendor = lookup(mac);
        assert_eq!(vendor, Some("Apple, Inc."));
    }

    #[test]
    fn lookup_returns_none_for_locally_administered_mac() {
        // Bit 1 of the first octet set means locally administered; not in IEEE registry
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(lookup(mac).is_none());
    }

    #[test]
    fn lookup_returns_none_for_unassigned_oui() {
        // FF:FF:FF is not an assigned OUI (broadcast / reserved range)
        let mac = [0xff, 0xff, 0xff, 0x00, 0x00, 0x00];
        assert!(lookup(mac).is_none());
    }
}
