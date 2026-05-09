//! Vendor / product / `DeviceClass` classification from a [`BleAdvertisement`].

use crate::ble::continuity::ContinuityPayload;
use crate::ble::types::{BleAdvertisement, DeviceClass};

/// Look up the vendor name from the manufacturer data company IDs.
/// Returns the first known vendor, or `None` if no entries match.
#[must_use]
pub fn vendor(ad: &BleAdvertisement) -> Option<String> {
    for company_id in ad.manufacturer_data.keys() {
        if let Some(name) = vendor_for_company_id(*company_id) {
            return Some(name.to_string());
        }
    }
    None
}

const fn vendor_for_company_id(id: u16) -> Option<&'static str> {
    match id {
        0x004C => Some("Apple, Inc."),
        0x0006 => Some("Microsoft"),
        0x0075 => Some("Samsung Electronics"),
        0x00E0 => Some("Google"),
        0x0087 => Some("Garmin International"),
        0x0157 => Some("Anhui Huami"),
        _ => None,
    }
}

/// Look up the product name from a `ProximityPair` model ID.
/// Returns `None` if there's no matching `ProximityPair` payload or the
/// model ID isn't in our table.
#[must_use]
pub fn product(payloads: &[ContinuityPayload]) -> Option<String> {
    for p in payloads {
        if let ContinuityPayload::ProximityPair {
            model_id: Some(id), ..
        } = p
            && let Some(name) = product_for_model_id(*id)
        {
            return Some(name.to_string());
        }
    }
    None
}

const fn product_for_model_id(id: u16) -> Option<&'static str> {
    match id {
        0x0220 => Some("AirPods (1st gen)"),
        0x0F20 => Some("AirPods (2nd gen)"),
        0x1320 => Some("AirPods (3rd gen)"),
        0x0E20 => Some("AirPods Pro"),
        0x1420 => Some("AirPods Pro (2nd gen)"),
        0x0A20 => Some("AirPods Max"),
        0x0520 => Some("Beats Solo3"),
        _ => None,
    }
}

/// Classify the [`DeviceClass`] from all available signals.
#[must_use]
pub fn device_class(ad: &BleAdvertisement, payloads: &[ContinuityPayload]) -> DeviceClass {
    // Continuity-driven signals (highest confidence)
    for p in payloads {
        match p {
            ContinuityPayload::FindMy { .. } => return DeviceClass::Tag,
            ContinuityPayload::ProximityPair { .. } => return DeviceClass::Earbuds,
            _ => {}
        }
    }

    // local_name substring matching (case-insensitive)
    if let Some(name) = ad.local_name.as_ref().map(|s| s.to_ascii_lowercase()) {
        if name.contains("iphone") {
            return DeviceClass::Phone;
        }
        if name.contains("ipad") {
            return DeviceClass::Tablet;
        }
        if name.contains("macbook") || name.contains("imac") || name.contains("mac mini") {
            return DeviceClass::Laptop;
        }
        if name.contains("watch") {
            return DeviceClass::Watch;
        }
        if name.contains("airpods") || name.contains("beats") {
            return DeviceClass::Earbuds;
        }
        if name.contains("airtag") {
            return DeviceClass::Tag;
        }
        if name.contains("homepod") || name.contains("apple tv") {
            return DeviceClass::SmartHome;
        }
    }

    DeviceClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::types::PeripheralId;
    use std::collections::BTreeMap;
    use std::time::SystemTime;

    fn ad_with(local_name: Option<&str>, mfr: BTreeMap<u16, Vec<u8>>) -> BleAdvertisement {
        BleAdvertisement {
            peripheral_id: PeripheralId::new("test"),
            address_type: None,
            rssi: -50,
            local_name: local_name.map(String::from),
            manufacturer_data: mfr,
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn vendor_apple_from_004c() {
        let ad = ad_with(None, std::iter::once((0x004C, vec![0u8; 4])).collect());
        assert_eq!(vendor(&ad).as_deref(), Some("Apple, Inc."));
    }

    #[test]
    fn vendor_unknown_company_id_returns_none() {
        let ad = ad_with(None, std::iter::once((0xFFFF, vec![])).collect());
        assert!(vendor(&ad).is_none());
    }

    #[test]
    fn product_airpods_pro() {
        let payloads = vec![ContinuityPayload::ProximityPair {
            model_id: Some(0x0E20),
            raw: vec![],
        }];
        assert_eq!(product(&payloads).as_deref(), Some("AirPods Pro"));
    }

    #[test]
    fn product_no_proximity_pair_returns_none() {
        assert!(product(&[]).is_none());
    }

    #[test]
    fn device_class_findmy_payload_implies_tag() {
        let ad = ad_with(None, BTreeMap::new());
        let payloads = vec![ContinuityPayload::FindMy { raw: vec![] }];
        assert_eq!(device_class(&ad, &payloads), DeviceClass::Tag);
    }

    #[test]
    fn device_class_iphone_local_name_implies_phone() {
        let ad = ad_with(Some("Shannon's iPhone"), BTreeMap::new());
        assert_eq!(device_class(&ad, &[]), DeviceClass::Phone);
    }

    #[test]
    fn device_class_unknown_default() {
        let ad = ad_with(Some("RandomThing"), BTreeMap::new());
        assert_eq!(device_class(&ad, &[]), DeviceClass::Unknown);
    }

    #[test]
    fn device_class_proximity_pair_beats_local_name() {
        // ProximityPair takes precedence over local_name heuristic.
        let ad = ad_with(Some("iPhone"), BTreeMap::new());
        let payloads = vec![ContinuityPayload::ProximityPair {
            model_id: None,
            raw: vec![],
        }];
        assert_eq!(device_class(&ad, &payloads), DeviceClass::Earbuds);
    }
}
