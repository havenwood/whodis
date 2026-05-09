//! Integration test: BLE clone captures ads from a synthetic source.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use whodis::ble::clone_peripheral_from_source;
use whodis::ble::scan::BleEventSource;
use whodis::ble::{BleAdvertisement, PeripheralId};

#[tokio::test(flavor = "multi_thread")]
async fn clone_captures_target_ads_and_merges_fields() {
    let (tx, rx) = tokio::sync::mpsc::channel::<BleAdvertisement>(16);
    let source = ReceiverSource::new(rx);

    let target = PeripheralId::new("target-1");

    let cancel = CancellationToken::new();
    let cancel_for_run = cancel.clone();
    let target_for_run = target.clone();
    let handle = tokio::spawn(async move {
        clone_peripheral_from_source(
            target_for_run,
            Box::new(source),
            Duration::from_millis(500),
            cancel_for_run,
        )
        .await
    });

    let ad_a = BleAdvertisement {
        peripheral_id: target.clone(),
        address_type: None,
        rssi: -50,
        local_name: None,
        manufacturer_data: {
            let mut m = BTreeMap::new();
            m.insert(0x004C, vec![0x10, 0x05]);
            m
        },
        service_uuids: vec![],
        tx_power: None,
        timestamp: SystemTime::UNIX_EPOCH,
    };
    let ad_b = BleAdvertisement {
        peripheral_id: target.clone(),
        address_type: None,
        rssi: -60,
        local_name: Some("Shannon's iPhone".into()),
        manufacturer_data: BTreeMap::new(),
        service_uuids: vec![],
        tx_power: Some(8),
        timestamp: SystemTime::UNIX_EPOCH,
    };
    let ad_other = BleAdvertisement {
        peripheral_id: PeripheralId::new("other-1"),
        address_type: None,
        rssi: -70,
        local_name: Some("Other".into()),
        manufacturer_data: BTreeMap::new(),
        service_uuids: vec![],
        tx_power: Some(0),
        timestamp: SystemTime::UNIX_EPOCH,
    };
    tx.send(ad_a).await.expect("send a");
    tx.send(ad_b).await.expect("send b");
    tx.send(ad_other).await.expect("send other");
    drop(tx);

    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("timeout")
        .expect("join")
        .expect("clone ok");

    assert_eq!(result.advertisement.peripheral_id, target);
    assert_eq!(
        result.advertisement.local_name.as_deref(),
        Some("Shannon's iPhone"),
        "expected local_name from ad_b"
    );
    assert_eq!(result.advertisement.tx_power, Some(8));
    assert!(
        result.advertisement.manufacturer_data.contains_key(&0x004C),
        "expected Apple mfr data from ad_a"
    );
    assert!(result.gatt.is_none(), "no GATT requested");

    let toml = result.to_toml();
    assert!(
        toml.contains(r#"local_name = "Shannon's iPhone""#),
        "{toml}"
    );
    assert!(
        toml.contains("[[advertisement.manufacturer_data]]"),
        "{toml}"
    );
}

struct ReceiverSource {
    inner: ReceiverStream<BleAdvertisement>,
}

impl ReceiverSource {
    fn new(rx: tokio::sync::mpsc::Receiver<BleAdvertisement>) -> Self {
        Self {
            inner: ReceiverStream::new(rx),
        }
    }
}

impl BleEventSource for ReceiverSource {
    fn stream(self: Box<Self>) -> Pin<Box<dyn Stream<Item = BleAdvertisement> + Send>> {
        Box::pin(self.inner)
    }
}
