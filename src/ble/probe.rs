//! Targeted ad collection for one peripheral.
//!
//! [`probe_peripheral`] runs a [`crate::ble::scan::Scanner`] over the
//! supplied source, filtering to ads that match `target_id`, until either
//! `duration` elapses or `cancel` fires. After collection, the merged ad
//! set is run through Continuity decode and fingerprint classification
//! to produce one [`BleDevice`] summary.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::ble::continuity::{self, ContinuityPayload};
use crate::ble::fingerprint;
use crate::ble::scan::{BleEventSource, Scanner};
use crate::ble::types::{AirDropMode, BleAdvertisement, BleDevice, PeripheralId, RssiSample};
use crate::error::{Error, Result};

/// Run a scan for `duration`, collecting only advertisements that match
/// `target_id`. After the duration elapses (or `cancel` fires), classify
/// the collected ads into one [`BleDevice`] summary.
///
/// Returns `Ok(None)` if no ads matched `target_id`.
pub async fn probe_peripheral(
    target_id: PeripheralId,
    source: Box<dyn BleEventSource>,
    duration: Duration,
    cancel: CancellationToken,
) -> Result<Option<BleDevice>> {
    let collected: Arc<Mutex<Vec<BleAdvertisement>>> = Arc::new(Mutex::new(Vec::new()));
    let collected_for_cb = collected.clone();
    let target_for_cb = target_id.clone();

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

    let ads_snapshot: Vec<BleAdvertisement> = {
        let guard = collected.lock().map_err(|e| Error::BleScan {
            reason: format!("collected mutex poisoned: {e}"),
        })?;
        guard.clone()
    };

    if ads_snapshot.is_empty() {
        return Ok(None);
    }

    let merged_ad = merge_ads(&ads_snapshot);
    let mut all_payloads: Vec<ContinuityPayload> = Vec::new();
    for ad in &ads_snapshot {
        if let Some(apple) = ad.manufacturer_data.get(&0x004C) {
            all_payloads.extend(continuity::decode(apple));
        }
    }
    let vendor = fingerprint::vendor(&merged_ad);
    let product = fingerprint::product(&all_payloads);
    let device_class = fingerprint::device_class(&merged_ad, &all_payloads);
    let airdrop_mode = airdrop_mode_from_payloads(&all_payloads);
    let first_seen = ads_snapshot
        .iter()
        .map(|a| a.timestamp)
        .min()
        .unwrap_or(merged_ad.timestamp);
    let last_seen = ads_snapshot
        .iter()
        .map(|a| a.timestamp)
        .max()
        .unwrap_or(merged_ad.timestamp);
    let rssi_samples: Vec<RssiSample> = ads_snapshot
        .iter()
        .map(|a| RssiSample {
            rssi: a.rssi,
            at: a.timestamp,
        })
        .collect();
    let observation_count = ads_snapshot.len();

    let BleAdvertisement {
        local_name,
        address_type,
        tx_power,
        service_uuids,
        manufacturer_data,
        ..
    } = merged_ad;

    Ok(Some(BleDevice {
        peripheral_id: target_id,
        vendor,
        product,
        device_class,
        continuity: all_payloads,
        airdrop_mode,
        local_name,
        address_type,
        tx_power,
        service_uuids,
        manufacturer_data,
        rssi_samples,
        observation_count,
        first_seen,
        last_seen,
    }))
}

fn merge_ads(ads: &[BleAdvertisement]) -> BleAdvertisement {
    let mut base = ads.last().cloned().unwrap_or_else(|| BleAdvertisement {
        peripheral_id: PeripheralId::new(""),
        address_type: None,
        rssi: 0,
        local_name: None,
        manufacturer_data: std::collections::BTreeMap::new(),
        service_uuids: vec![],
        tx_power: None,
        timestamp: std::time::SystemTime::UNIX_EPOCH,
    });
    let mut merged_mfr = base.manufacturer_data.clone();
    for ad in ads {
        for (k, v) in &ad.manufacturer_data {
            merged_mfr.entry(*k).or_insert_with(|| v.clone());
        }
        for uuid in &ad.service_uuids {
            if !base.service_uuids.contains(uuid) {
                base.service_uuids.push(*uuid);
            }
        }
        if base.local_name.is_none() {
            base.local_name.clone_from(&ad.local_name);
        }
    }
    base.manufacturer_data = merged_mfr;
    base
}

fn airdrop_mode_from_payloads(payloads: &[ContinuityPayload]) -> Option<AirDropMode> {
    for p in payloads {
        if let ContinuityPayload::AirDropPair { mode, .. } = p {
            return Some(*mode);
        }
    }
    None
}
