//! Integration test: scan dispatcher emits captured ads through the renderer.
//! Uses the public Scanner API directly with a synthetic event source -- does
//! not exercise CLI parsing or `BtleplugSource`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use whodis::ble::scan::{BleEventSource, Scanner};
use whodis::ble::{BleAdvertisement, PeripheralId};

#[tokio::test(flavor = "multi_thread")]
async fn scanner_with_synthetic_source_captures_three_ads() {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    for i in 0..3_i16 {
        let ad = BleAdvertisement {
            peripheral_id: PeripheralId::new(format!("p-{i}")),
            address_type: None,
            rssi: -40 - i,
            local_name: None,
            manufacturer_data: BTreeMap::new(),
            service_uuids: vec![],
            tx_power: None,
            timestamp: SystemTime::UNIX_EPOCH,
        };
        tx.send(ad).await.expect("send");
    }
    drop(tx);

    let captured: Arc<Mutex<Vec<BleAdvertisement>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_cb = captured.clone();

    let cancel = CancellationToken::new();
    let scanner = Scanner::new(ReceiverSource::new(rx)).on_event(move |ad| {
        if let Ok(mut g) = captured_for_cb.lock() {
            g.push(ad);
        }
    });
    let _join = tokio::time::timeout(Duration::from_secs(2), scanner.run(cancel)).await;
    let count = {
        let g = captured.lock().expect("lock");
        g.len()
    };
    assert_eq!(count, 3);
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
    fn stream(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn tokio_stream::Stream<Item = BleAdvertisement> + Send>> {
        Box::pin(self.inner)
    }
}
