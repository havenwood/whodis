//! Integration test: `probe_peripheral` classifies a collection of ads.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use whodis::ble::probe::probe_peripheral;
use whodis::ble::scan::BleEventSource;
use whodis::ble::{BleAdvertisement, DeviceClass, PeripheralId};

#[tokio::test(flavor = "multi_thread")]
async fn probe_classifies_iphone_with_continuity_data() {
    let (tx, rx) = tokio::sync::mpsc::channel::<BleAdvertisement>(8);
    let source = ReceiverStreamSource::new(rx);
    let target = PeripheralId::new("target-id");

    let mut ad = make_ad(target.clone(), Some("Shannon's iPhone"));
    ad.manufacturer_data
        .insert(0x004C, vec![0x10, 0x05, 0x57, 0x18, 0x00, 0x00, 0x00]);
    tx.send(ad).await.expect("send");

    let other = make_ad(PeripheralId::new("not-target"), None);
    tx.send(other).await.expect("send");

    let mut ad2 = make_ad(target.clone(), Some("Shannon's iPhone"));
    ad2.manufacturer_data
        .insert(0x004C, vec![0x10, 0x05, 0x47, 0x10, 0x00, 0x00, 0x00]);
    tx.send(ad2).await.expect("send");

    drop(tx);

    let cancel = CancellationToken::new();
    let device = probe_peripheral(
        target.clone(),
        Box::new(source),
        Duration::from_secs(2),
        cancel,
    )
    .await
    .expect("probe ok")
    .expect("expected one classified device");

    assert_eq!(device.peripheral_id, target);
    assert_eq!(device.vendor.as_deref(), Some("Apple, Inc."));
    assert_eq!(device.device_class, DeviceClass::Phone);
    assert!(!device.continuity.is_empty());
}

fn make_ad(id: PeripheralId, local_name: Option<&str>) -> BleAdvertisement {
    BleAdvertisement {
        peripheral_id: id,
        address_type: None,
        rssi: -55,
        local_name: local_name.map(String::from),
        manufacturer_data: BTreeMap::new(),
        service_uuids: vec![],
        tx_power: None,
        timestamp: SystemTime::UNIX_EPOCH,
    }
}

struct ReceiverStreamSource {
    inner: ReceiverStream<BleAdvertisement>,
}

impl ReceiverStreamSource {
    fn new(rx: tokio::sync::mpsc::Receiver<BleAdvertisement>) -> Self {
        Self {
            inner: ReceiverStream::new(rx),
        }
    }
}

impl BleEventSource for ReceiverStreamSource {
    fn stream(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn tokio_stream::Stream<Item = BleAdvertisement> + Send>> {
        Box::pin(self.inner)
    }
}
