//! Well-known BLE service UUID name table.
//!
//! Bluetooth SIG assigns 16-bit UUIDs for standard GATT services. They
//! appear on the wire as full 128-bit UUIDs in the Bluetooth Base UUID
//! template `0000xxxx-0000-1000-8000-00805f9b34fb`. We translate the
//! 16-bit prefix to a human-readable label for the `probe --ble`
//! Pretty output and the GUI detail pane.
//!
//! Source: <https://www.bluetooth.com/specifications/assigned-numbers/>
//! (subset — only the most common services we actually see in the wild).

use uuid::Uuid;

/// Look up a well-known service UUID's human-readable label.
/// Returns `None` for vendor-specific UUIDs and unrecognized 16-bit IDs.
#[must_use]
pub fn well_known(uuid: Uuid) -> Option<&'static str> {
    short_id(uuid).and_then(label_for_short_id)
}

/// Extract the 16-bit short ID from a Bluetooth Base UUID, or return
/// `None` if the UUID isn't on the Bluetooth Base.
#[must_use]
pub fn short_id(uuid: Uuid) -> Option<u16> {
    const BASE_SUFFIX: u128 = 0x0000_1000_8000_0080_5f9b_34fb;
    const BASE_MASK: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff;
    let bits = uuid.as_u128();
    if (bits & BASE_MASK) != BASE_SUFFIX {
        return None;
    }
    let high = (bits >> 96) & 0xFFFF_FFFF;
    if (high >> 16) != 0 {
        // 32-bit short form, not the 16-bit short form we cover here.
        return None;
    }
    u16::try_from(high & 0xFFFF).ok()
}

const fn label_for_short_id(id: u16) -> Option<&'static str> {
    match id {
        0x1800 => Some("Generic Access"),
        0x1801 => Some("Generic Attribute"),
        0x180A => Some("Device Information"),
        0x180D => Some("Heart Rate"),
        0x180F => Some("Battery"),
        0x1810 => Some("Blood Pressure"),
        0x1812 => Some("HID"),
        0x1813 => Some("Scan Parameters"),
        0x1816 => Some("Cycling Speed and Cadence"),
        0x1818 => Some("Cycling Power"),
        0x181A => Some("Environmental Sensing"),
        0x181C => Some("User Data"),
        0x181D => Some("Weight Scale"),
        0x181E => Some("Bond Management"),
        0x1822 => Some("Pulse Oximeter"),
        0x1826 => Some("Fitness Machine"),
        0xFD6F => Some("Exposure Notification"),
        0xFE9F => Some("Google Find My Device"),
        0xFEAA => Some("Eddystone"),
        0xFEED => Some("Tile"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battery_short_id_resolves() {
        let battery: Uuid = "0000180f-0000-1000-8000-00805f9b34fb"
            .parse()
            .expect("uuid");
        assert_eq!(short_id(battery), Some(0x180F));
        assert_eq!(well_known(battery), Some("Battery"));
    }

    #[test]
    fn device_information_resolves() {
        let dev_info: Uuid = "0000180a-0000-1000-8000-00805f9b34fb"
            .parse()
            .expect("uuid");
        assert_eq!(well_known(dev_info), Some("Device Information"));
    }

    #[test]
    fn vendor_uuid_returns_none() {
        let vendor: Uuid = "abcdef01-2345-6789-abcd-ef0123456789"
            .parse()
            .expect("uuid");
        assert!(short_id(vendor).is_none());
        assert!(well_known(vendor).is_none());
    }

    #[test]
    fn unknown_short_id_returns_none() {
        let unknown: Uuid = "00001234-0000-1000-8000-00805f9b34fb"
            .parse()
            .expect("uuid");
        assert_eq!(short_id(unknown), Some(0x1234));
        assert!(well_known(unknown).is_none());
    }
}
