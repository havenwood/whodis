//! Integration test: BLE Watcher emits anomalies from synthetic ads.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use whodis::ble::scan::BleEventSource;
use whodis::ble::watch::Watcher;
use whodis::ble::{BleAdvertisement, BleAnomaly, PeripheralId};

#[tokio::test(flavor = "multi_thread")]
async fn watcher_emits_arrived_and_classification_for_iphone_ad() {
    let (tx, rx) = tokio::sync::mpsc::channel::<BleAdvertisement>(8);
    let source = ReceiverSource::new(rx);

    let captured: Arc<Mutex<Vec<BleAnomaly>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_cb = captured.clone();
    let cancel = CancellationToken::new();
    let cancel_for_run = cancel.clone();

    let watcher = Watcher::new(source).on_anomaly(move |a| {
        if let Ok(mut g) = captured_for_cb.lock() {
            g.push(a);
        }
    });

    let handle = tokio::spawn(async move { watcher.run(cancel_for_run).await });

    let ad = BleAdvertisement {
        peripheral_id: PeripheralId::new("p1"),
        address_type: None,
        rssi: -50,
        local_name: Some("Shannon's iPhone".into()),
        manufacturer_data: BTreeMap::new(),
        service_uuids: vec![],
        tx_power: None,
        timestamp: SystemTime::UNIX_EPOCH,
    };
    tx.send(ad).await.expect("send");

    tokio::time::sleep(Duration::from_millis(150)).await;
    cancel.cancel();
    drop(tx);
    drop(tokio::time::timeout(Duration::from_secs(1), handle).await);

    let kinds: Vec<&str> = {
        let g = captured.lock().expect("lock");
        g.iter()
            .map(|a| match a {
                BleAnomaly::DevicePresence { .. } => "presence",
                BleAnomaly::AirDropEveryoneMode { .. } => "airdrop",
                BleAnomaly::LockStateChange { .. } => "lock",
                BleAnomaly::DeviceClassClassification { .. } => "class",
                BleAnomaly::UnknownContinuityType { .. } => "unknown",
                BleAnomaly::ProximityChange { .. } => "proximity",
            })
            .collect()
    };
    assert!(
        kinds.contains(&"presence"),
        "expected DevicePresence, got {kinds:?}"
    );
    assert!(
        kinds.contains(&"class"),
        "expected DeviceClassClassification, got {kinds:?}"
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
    fn stream(self: Box<Self>) -> std::pin::Pin<Box<dyn Stream<Item = BleAdvertisement> + Send>> {
        Box::pin(self.inner)
    }
}
