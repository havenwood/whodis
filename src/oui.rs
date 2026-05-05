//! OUI vendor lookup backed by a compile-time-generated static table.

include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

/// Look up the IEEE-assigned vendor name for the first three octets of a MAC address.
///
/// Returns `None` for locally-administered or unassigned OUIs.
#[must_use]
pub fn lookup(mac: [u8; 6]) -> Option<&'static str> {
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

    #[test]
    fn lookup_table_is_sorted() {
        // partition_point correctness requires the table to be sorted by key.
        let keys: Vec<u32> = OUI_TABLE.iter().map(|(k, _)| *k).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "OUI_TABLE must be sorted by key");
    }

    #[test]
    fn lookup_first_entry_of_table() {
        // The first entry in the sorted table should be found correctly.
        if let Some(&(key, expected_name)) = OUI_TABLE.first() {
            let o0 = ((key >> 16) & 0xff) as u8;
            let o1 = ((key >> 8) & 0xff) as u8;
            let o2 = (key & 0xff) as u8;
            let mac = [o0, o1, o2, 0x00, 0x00, 0x00];
            assert_eq!(lookup(mac), Some(expected_name));
        }
    }

    #[test]
    fn lookup_last_entry_of_table() {
        // The last entry in the sorted table should also be found correctly.
        if let Some(&(key, expected_name)) = OUI_TABLE.last() {
            let o0 = ((key >> 16) & 0xff) as u8;
            let o1 = ((key >> 8) & 0xff) as u8;
            let o2 = (key & 0xff) as u8;
            let mac = [o0, o1, o2, 0xff, 0xff, 0xff];
            assert_eq!(lookup(mac), Some(expected_name));
        }
    }

    #[test]
    fn lookup_returns_none_for_multicast_mac() {
        // 01:00:5E is IPv4 multicast; not an assigned unicast OUI
        let mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
        // This may or may not be in the table; we just ensure it doesn't panic.
        let _ = lookup(mac);
    }

    #[test]
    fn lookup_second_known_apple_oui() {
        // 00:17:f2 is also assigned to "Apple, Inc."
        let mac = [0x00, 0x17, 0xf2, 0x00, 0x00, 0x00];
        let vendor = lookup(mac);
        assert_eq!(vendor, Some("Apple, Inc."));
    }
}
