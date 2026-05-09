//! Capture a live BLE peripheral's advertising profile and emit a portable TOML document.
//!
//! The TOML is a hand-off artifact for an external radio — macOS `CBPeripheralManager`
//! filters third-party manufacturer data, so whodis cannot replay BLE locally. Optionally
//! includes a GATT service map captured from a connected peripheral.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ble::types::{AddressType, PeripheralId};

/// Captured BLE peripheral profile: passive advertisement + optional GATT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleClone {
    pub advertisement: BleCloneAdvertisement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gatt: Option<BleCloneGatt>,
}

/// Snapshot of one merged BLE advertisement — the richest combination of
/// fields seen across the scan window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneAdvertisement {
    pub peripheral_id: PeripheralId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_type: Option<AddressType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_power: Option<i8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_uuids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub manufacturer_data: BTreeMap<u16, Vec<u8>>,
}

/// GATT service map captured from a connected peripheral.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneGatt {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<BleCloneService>,
    /// Best-effort: errors during connect / discover / read land here
    /// instead of failing the whole clone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneService {
    pub uuid: Uuid,
    pub characteristics: Vec<BleCloneCharacteristic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleCloneCharacteristic {
    pub uuid: Uuid,
    pub properties: Vec<String>,
    /// Captured value, hex-encoded with a `0x` prefix. None if the
    /// characteristic has no `read` property or the read failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_value: Option<String>,
}

impl BleClone {
    /// Format as TOML for replay by an external BLE radio (`BlueZ` / `nRF`).
    /// Output is deterministic so tests can pin the exact bytes.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut s = String::new();
        let _r = writeln!(
            s,
            "# Cloned from BLE peripheral {}",
            self.advertisement.peripheral_id
        );
        let _r = writeln!(
            s,
            "# Replay with an external BLE radio (BlueZ, nRF). macOS does not"
        );
        let _r = writeln!(
            s,
            "# expose the manufacturer-data slot to third-party advertisers."
        );
        let _r = writeln!(s);

        let _r = writeln!(s, "[advertisement]");
        let _r = writeln!(
            s,
            "peripheral_id = {}",
            quote(self.advertisement.peripheral_id.as_str())
        );
        if let Some(name) = self.advertisement.local_name.as_deref() {
            let _r = writeln!(s, "local_name = {}", quote(name));
        }
        if let Some(addr) = self.advertisement.address_type {
            let _r = writeln!(s, "address_type = {}", quote(&format!("{addr:?}")));
        }
        if let Some(tx) = self.advertisement.tx_power {
            let _r = writeln!(s, "tx_power = {tx}");
        }
        if !self.advertisement.service_uuids.is_empty() {
            let quoted: Vec<String> = self
                .advertisement
                .service_uuids
                .iter()
                .map(|u| quote(&u.to_string()))
                .collect();
            let _r = writeln!(s, "service_uuids = [{}]", quoted.join(", "));
        }
        let _r = writeln!(s);

        for (company_id, data) in &self.advertisement.manufacturer_data {
            let _r = writeln!(s, "[[advertisement.manufacturer_data]]");
            let _r = writeln!(s, "company_id = {company_id:#06x}");
            let _r = writeln!(s, "data = {}", quote(&hex_blob(data)));
            let _r = writeln!(s);
        }

        if let Some(gatt) = &self.gatt {
            for service in &gatt.services {
                let _r = writeln!(s, "[[gatt.service]]");
                let _r = writeln!(s, "uuid = {}", quote(&service.uuid.to_string()));
                let _r = writeln!(s);
                for c in &service.characteristics {
                    let _r = writeln!(s, "[[gatt.service.characteristic]]");
                    let _r = writeln!(s, "uuid = {}", quote(&c.uuid.to_string()));
                    let props: Vec<String> = c.properties.iter().map(|p| quote(p)).collect();
                    let _r = writeln!(s, "properties = [{}]", props.join(", "));
                    if let Some(v) = c.last_value.as_deref() {
                        let _r = writeln!(s, "last_value = {}", quote(v));
                    }
                    let _r = writeln!(s);
                }
            }
            for err in &gatt.errors {
                let _r = writeln!(s, "[[gatt.errors]]");
                let _r = writeln!(s, "message = {}", quote(err));
                let _r = writeln!(s);
            }
        }

        s
    }
}

fn quote(s: &str) -> String {
    crate::name_util::toml_quote(s)
}

fn hex_blob(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        let _r = write!(out, "{b:02x}");
    }
    out
}

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::ble::scan::{BleEventSource, Scanner};
use crate::ble::types::BleAdvertisement;
use crate::error::{Error, Result};

/// Run a scan over `source` for `duration`, collecting ads matching `target`.
///
/// Returns a `BleClone` with merged advertisement, or `Err(Error::NoRecords)` if no ads match.
pub async fn clone_peripheral_from_source(
    target: PeripheralId,
    source: Box<dyn BleEventSource>,
    duration: Duration,
    cancel: CancellationToken,
) -> Result<BleClone> {
    let collected: Arc<Mutex<Vec<BleAdvertisement>>> = Arc::new(Mutex::new(Vec::new()));
    let collected_for_cb = collected.clone();
    let target_for_cb = target.clone();

    let scan_cancel = CancellationToken::new();
    let scan_cancel_for_run = scan_cancel.clone();
    let scan_handle = tokio::spawn(async move {
        let scanner = Scanner::new_boxed(source).on_event(move |ad| {
            if ad.peripheral_id == target_for_cb
                && let Ok(mut g) = collected_for_cb.lock()
            {
                g.push(ad);
            }
        });
        scanner.run(scan_cancel_for_run).await
    });

    tokio::select! {
        () = cancel.cancelled() => {}
        () = tokio::time::sleep(duration) => {}
    }
    scan_cancel.cancel();
    drop(tokio::time::timeout(Duration::from_millis(500), scan_handle).await);

    let ads: Vec<BleAdvertisement> = {
        let guard = collected.lock().map_err(|e| Error::BleScan {
            reason: format!("collected mutex poisoned: {e}"),
        })?;
        guard.clone()
    };
    if ads.is_empty() {
        return Err(Error::NoRecords {
            target: target.as_str().to_string(),
            timeout: duration,
        });
    }

    Ok(BleClone {
        advertisement: merge_ads(&target, &ads),
        gatt: None,
    })
}

fn merge_ads(target: &PeripheralId, ads: &[BleAdvertisement]) -> BleCloneAdvertisement {
    let mut out = BleCloneAdvertisement {
        peripheral_id: target.clone(),
        local_name: None,
        address_type: None,
        tx_power: None,
        service_uuids: Vec::new(),
        manufacturer_data: BTreeMap::new(),
    };
    for ad in ads {
        if out.local_name.is_none() {
            out.local_name.clone_from(&ad.local_name);
        }
        if out.address_type.is_none() {
            out.address_type = ad.address_type;
        }
        if out.tx_power.is_none() {
            out.tx_power = ad.tx_power;
        }
        for u in &ad.service_uuids {
            if !out.service_uuids.contains(u) {
                out.service_uuids.push(*u);
            }
        }
        for (cid, data) in &ad.manufacturer_data {
            out.manufacturer_data.insert(*cid, data.clone());
        }
    }
    out
}

/// GATT enrichment options. Defaults: 5s connect, 5s discover.
#[derive(Debug, Clone, Copy)]
pub struct GattOptions {
    pub connect_timeout: Duration,
    pub discover_timeout: Duration,
}

impl Default for GattOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            discover_timeout: Duration::from_secs(5),
        }
    }
}

/// Connect to the peripheral, discover services, read every readable characteristic.
///
/// Errors are collected into `gatt.errors`; the clone is mutated in place. Returns `Ok(())`
/// even on per-step failures so the caller still gets a partial clone.
pub async fn enrich_with_gatt(
    clone: &mut BleClone,
    central: &btleplug::platform::Adapter,
    opts: GattOptions,
) -> Result<()> {
    use btleplug::api::{Central, CharPropFlags, Peripheral as _};

    let mut gatt = BleCloneGatt::default();
    let target_id = clone.advertisement.peripheral_id.clone();

    let peripherals = central.peripherals().await.map_err(|e| Error::BleScan {
        reason: format!("listing peripherals: {e}"),
    })?;
    let peripheral = peripherals
        .into_iter()
        .find(|p| PeripheralId::new(p.id().to_string().as_str()) == target_id);

    let Some(p) = peripheral else {
        gatt.errors
            .push(format!("peripheral {target_id} not found in adapter cache"));
        clone.gatt = Some(gatt);
        return Ok(());
    };

    if let Err(e) = p.connect_with_timeout(opts.connect_timeout).await {
        gatt.errors.push(format!("connect: {e}"));
        clone.gatt = Some(gatt);
        return Ok(());
    }

    if let Err(e) = p
        .discover_services_with_timeout(opts.discover_timeout)
        .await
    {
        gatt.errors.push(format!("discover_services: {e}"));
        drop(p.disconnect().await);
        clone.gatt = Some(gatt);
        return Ok(());
    }

    for service in p.services() {
        let mut svc = BleCloneService {
            uuid: service.uuid,
            characteristics: Vec::new(),
        };
        for c in &service.characteristics {
            let props = format_props(c.properties);
            let last_value = if c.properties.contains(CharPropFlags::READ) {
                match p.read(c).await {
                    Ok(bytes) => Some(hex_blob(&bytes)),
                    Err(e) => {
                        gatt.errors.push(format!("read {}: {e}", c.uuid));
                        None
                    }
                }
            } else {
                None
            };
            svc.characteristics.push(BleCloneCharacteristic {
                uuid: c.uuid,
                properties: props,
                last_value,
            });
        }
        gatt.services.push(svc);
    }

    drop(p.disconnect().await);
    clone.gatt = Some(gatt);
    Ok(())
}

fn format_props(flags: btleplug::api::CharPropFlags) -> Vec<String> {
    use btleplug::api::CharPropFlags;
    let mut out = Vec::new();
    let pairs = [
        (CharPropFlags::BROADCAST, "broadcast"),
        (CharPropFlags::READ, "read"),
        (
            CharPropFlags::WRITE_WITHOUT_RESPONSE,
            "write_without_response",
        ),
        (CharPropFlags::WRITE, "write"),
        (CharPropFlags::NOTIFY, "notify"),
        (CharPropFlags::INDICATE, "indicate"),
        (
            CharPropFlags::AUTHENTICATED_SIGNED_WRITES,
            "auth_signed_write",
        ),
        (CharPropFlags::EXTENDED_PROPERTIES, "extended_properties"),
    ];
    for (flag, name) in pairs {
        if flags.contains(flag) {
            out.push(name.to_string());
        }
    }
    out
}

#[cfg(test)]
mod gatt_helper_tests {
    use super::*;

    #[test]
    fn format_props_emits_canonical_names() {
        use btleplug::api::CharPropFlags;
        let f = CharPropFlags::READ | CharPropFlags::NOTIFY;
        let names = format_props(f);
        assert_eq!(names, vec!["read".to_string(), "notify".to_string()]);
    }

    #[test]
    fn format_props_empty_when_no_flags() {
        use btleplug::api::CharPropFlags;
        let names = format_props(CharPropFlags::empty());
        assert!(names.is_empty(), "got {names:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_toml_emits_minimal_advertisement() {
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("8EF96E6B-4729-AAAA"),
                local_name: Some("Shannon's iPhone".into()),
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: BTreeMap::new(),
            },
            gatt: None,
        };
        let toml = c.to_toml();
        assert!(toml.contains("[advertisement]"), "missing section: {toml}");
        assert!(
            toml.contains(r#"peripheral_id = "8EF96E6B-4729-AAAA""#),
            "missing id: {toml}"
        );
        assert!(
            toml.contains(r#"local_name = "Shannon's iPhone""#),
            "missing name: {toml}"
        );
        assert!(!toml.contains("[gatt"), "should omit gatt: {toml}");
    }

    #[test]
    fn to_toml_emits_manufacturer_data_with_hex_blob() {
        let mut mfr = BTreeMap::new();
        mfr.insert(0x004C, vec![0x10, 0x05, 0x42, 0x78, 0x90, 0x6c]);
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("p1"),
                local_name: None,
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: mfr,
            },
            gatt: None,
        };
        let toml = c.to_toml();
        assert!(
            toml.contains("[[advertisement.manufacturer_data]]"),
            "missing mfr table: {toml}"
        );
        assert!(toml.contains("company_id = 0x004c"), "missing id: {toml}");
        assert!(
            toml.contains(r#"data = "0x10054278906c""#),
            "expected canonical hex blob in: {toml}"
        );
    }

    #[test]
    fn to_toml_emits_gatt_section_when_present() {
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("p1"),
                local_name: None,
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: BTreeMap::new(),
            },
            gatt: Some(BleCloneGatt {
                services: vec![BleCloneService {
                    uuid: Uuid::parse_str("0000180f-0000-1000-8000-00805f9b34fb")
                        .expect("valid uuid"),
                    characteristics: vec![BleCloneCharacteristic {
                        uuid: Uuid::parse_str("00002a19-0000-1000-8000-00805f9b34fb")
                            .expect("valid uuid"),
                        properties: vec!["read".into(), "notify".into()],
                        last_value: Some("0x64".into()),
                    }],
                }],
                errors: vec![],
            }),
        };
        let toml = c.to_toml();
        assert!(toml.contains("[[gatt.service]]"), "missing svc: {toml}");
        assert!(
            toml.contains("[[gatt.service.characteristic]]"),
            "missing char: {toml}"
        );
        assert!(
            toml.contains(r#"properties = ["read", "notify"]"#),
            "{toml}"
        );
        assert!(toml.contains(r#"last_value = "0x64""#), "{toml}");
    }

    #[test]
    fn to_toml_emits_errors_section_when_present() {
        let c = BleClone {
            advertisement: BleCloneAdvertisement {
                peripheral_id: PeripheralId::new("p1"),
                local_name: None,
                address_type: None,
                tx_power: None,
                service_uuids: vec![],
                manufacturer_data: BTreeMap::new(),
            },
            gatt: Some(BleCloneGatt {
                services: vec![],
                errors: vec!["connect timed out after 5s".into()],
            }),
        };
        let toml = c.to_toml();
        assert!(toml.contains("[[gatt.errors]]"), "missing errors: {toml}");
        assert!(
            toml.contains(r#"message = "connect timed out after 5s""#),
            "{toml}"
        );
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use std::time::SystemTime;

    fn ad(id: &str, name: Option<&str>, tx: Option<i8>) -> BleAdvertisement {
        BleAdvertisement {
            peripheral_id: PeripheralId::new(id),
            address_type: None,
            rssi: -50,
            local_name: name.map(str::to_string),
            manufacturer_data: BTreeMap::new(),
            service_uuids: vec![],
            tx_power: tx,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn merge_takes_first_non_empty_local_name() {
        let target = PeripheralId::new("p1");
        let ads = vec![ad("p1", None, None), ad("p1", Some("iPhone"), None)];
        let m = merge_ads(&target, &ads);
        assert_eq!(m.local_name.as_deref(), Some("iPhone"));
    }

    #[test]
    fn merge_unions_service_uuids_dedup() {
        let target = PeripheralId::new("p1");
        let u1 = Uuid::parse_str("0000180f-0000-1000-8000-00805f9b34fb").expect("uuid");
        let u2 = Uuid::parse_str("0000180a-0000-1000-8000-00805f9b34fb").expect("uuid");
        let mut a = ad("p1", None, None);
        a.service_uuids = vec![u1];
        let mut b = ad("p1", None, None);
        b.service_uuids = vec![u1, u2];
        let m = merge_ads(&target, &[a, b]);
        assert_eq!(m.service_uuids, vec![u1, u2]);
    }

    #[test]
    fn merge_manufacturer_data_last_write_wins_per_cid() {
        let target = PeripheralId::new("p1");
        let mut a = ad("p1", None, None);
        a.manufacturer_data.insert(0x004C, vec![1, 2, 3]);
        let mut b = ad("p1", None, None);
        b.manufacturer_data.insert(0x004C, vec![4, 5, 6, 7]);
        let m = merge_ads(&target, &[a, b]);
        assert_eq!(m.manufacturer_data.get(&0x004C), Some(&vec![4, 5, 6, 7]));
    }
}
