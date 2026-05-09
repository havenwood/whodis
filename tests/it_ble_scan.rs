//! Integration test: Scanner consumes a synthetic [`BleEventSource`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use whodis::ble::scan::{BleEventSource, Scanner};
use whodis::ble::{BleAdvertisement, PeripheralId};

#[tokio::test(flavor = "multi_thread")]
async fn scanner_emits_received_advertisements() {
    let (tx, rx) = tokio::sync::mpsc::channel::<BleAdvertisement>(16);
    let source = ReceiverStreamSource::new(rx);

    let captured: Arc<Mutex<Vec<BleAdvertisement>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_cb = captured.clone();
    let cancel = CancellationToken::new();
    let cancel_for_run = cancel.clone();

    let handle = tokio::spawn(async move {
        let scanner = Scanner::new(source).on_event(move |ad| {
            if let Ok(mut g) = captured_for_cb.lock() {
                g.push(ad);
            }
        });
        scanner.run(cancel_for_run).await
    });

    tx.send(make_ad("aaa")).await.expect("send");
    tx.send(make_ad("bbb")).await.expect("send");

    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    drop(tx);
    let _join = tokio::time::timeout(Duration::from_secs(1), handle).await;

    let (len, first_id, second_id) = {
        let g = captured.lock().expect("lock");
        let first = g.first().expect("first").peripheral_id.as_str().to_owned();
        let second = g.get(1).expect("second").peripheral_id.as_str().to_owned();
        (g.len(), first, second)
    };
    assert_eq!(len, 2);
    assert_eq!(first_id, "aaa");
    assert_eq!(second_id, "bbb");
}

fn make_ad(id: &str) -> BleAdvertisement {
    BleAdvertisement {
        peripheral_id: PeripheralId::new(id),
        address_type: None,
        rssi: -50,
        local_name: None,
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
