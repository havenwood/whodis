//! BLE advertisement scan loop.
//!
//! [`BleEventSource`] abstracts the source of advertisement events so we
//! can plug in a real `btleplug` backend (Task 7) or a synthetic
//! [`tokio_stream::Stream`] for tests.
//!
//! [`Scanner::run`] drains the source, invokes the event callback per ad,
//! and exits cleanly on [`CancellationToken::cancel()`].

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::{Stream, StreamExt as _};
use tokio_util::sync::CancellationToken;

use crate::ble::types::BleAdvertisement;
use crate::error::Result;

/// Source of BLE advertisement events. Implementations: `BtleplugSource`
/// (Task 7, real radio via btleplug) and synthetic test sources backed
/// by `tokio_stream::Stream`.
pub trait BleEventSource: Send + 'static {
    fn stream(self: Box<Self>) -> Pin<Box<dyn Stream<Item = BleAdvertisement> + Send>>;
}

type EventCallback = Arc<dyn Fn(BleAdvertisement) + Send + Sync>;

/// Drives a [`BleEventSource`] and dispatches each ad through a callback.
pub struct Scanner {
    source: Box<dyn BleEventSource>,
    on_event: Option<EventCallback>,
}

impl Scanner {
    #[must_use]
    pub fn new<S: BleEventSource>(source: S) -> Self {
        Self {
            source: Box::new(source),
            on_event: None,
        }
    }

    #[must_use]
    pub fn new_boxed(source: Box<dyn BleEventSource>) -> Self {
        Self {
            source,
            on_event: None,
        }
    }

    #[must_use]
    pub fn on_event(mut self, cb: impl Fn(BleAdvertisement) + Send + Sync + 'static) -> Self {
        self.on_event = Some(Arc::new(cb));
        self
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<()> {
        let mut stream = self.source.stream();
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                next = stream.next() => match next {
                    None => return Ok(()),
                    Some(ad) => {
                        if let Some(cb) = self.on_event.as_ref() {
                            cb(ad);
                        }
                    }
                }
            }
        }
    }
}

// --- BtleplugSource ----------------------------------------------------------

use std::collections::BTreeMap;
use std::time::SystemTime;

use btleplug::api::{Central, CentralEvent, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager};

use crate::ble::types::{AddressType, PeripheralId};
use crate::error::Error;

/// btleplug-backed event source. Spawns a `Manager`, picks the first
/// adapter, starts a scan, and forwards `DeviceDiscovered` and
/// `DeviceUpdated` events as [`BleAdvertisement`] records.
pub struct BtleplugSource {
    adapter: Adapter,
}

impl BtleplugSource {
    /// Construct from the first available adapter. On macOS, an empty
    /// adapter list typically means TCC denied or hardware off -- we
    /// surface that as [`Error::BlePermissionDenied`] with a System
    /// Settings hint.
    pub async fn new() -> crate::error::Result<Self> {
        let manager = Manager::new().await.map_err(|e| Error::BleAdapter {
            reason: e.to_string(),
        })?;
        let adapters = manager.adapters().await.map_err(|e| Error::BleAdapter {
            reason: e.to_string(),
        })?;
        let Some(adapter) = adapters.into_iter().next() else {
            return Err(Error::BlePermissionDenied);
        };
        Ok(Self { adapter })
    }
}

impl BleEventSource for BtleplugSource {
    #[allow(
        tail_expr_drop_order,
        reason = "async_stream macro generates temporaries with btleplug destructors; drop order is harmless"
    )]
    fn stream(self: Box<Self>) -> Pin<Box<dyn Stream<Item = BleAdvertisement> + Send>> {
        Box::pin(async_stream::stream! {
            if let Err(e) = self.adapter.start_scan(ScanFilter::default()).await {
                tracing::error!(error = %e, "BLE start_scan failed");
                return;
            }
            let events_result = self.adapter.events().await;
            let mut events = match events_result {
                Ok(evts) => evts,
                Err(e) => {
                    tracing::error!(error = %e, "BLE events() failed");
                    return;
                }
            };
            while let Some(event) = futures::StreamExt::next(&mut events).await {
                let (CentralEvent::DeviceDiscovered(id)
                | CentralEvent::DeviceUpdated(id)
                | CentralEvent::ManufacturerDataAdvertisement { id, .. }
                | CentralEvent::ServicesAdvertisement { id, .. }) = event
                else {
                    continue;
                };
                let peripheral_result = self.adapter.peripheral(&id).await;
                let Ok(peripheral) = peripheral_result else {
                    continue;
                };
                let props_result = peripheral.properties().await;
                let Ok(Some(props)) = props_result else {
                    continue;
                };
                yield props_to_ad(&id, &props);
            }
            drop(self.adapter.stop_scan().await);
        })
    }
}

fn props_to_ad(
    id: &btleplug::platform::PeripheralId,
    props: &btleplug::api::PeripheralProperties,
) -> BleAdvertisement {
    use btleplug::api::AddressType as BtAddressType;

    let manufacturer_data: BTreeMap<u16, Vec<u8>> = props
        .manufacturer_data
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let service_uuids: Vec<uuid::Uuid> = props.services.clone();
    let address_type = props.address_type.map(|t| match t {
        BtAddressType::Public => AddressType::Public,
        BtAddressType::Random => AddressType::RandomStatic,
    });

    BleAdvertisement {
        peripheral_id: PeripheralId::new(id.to_string()),
        address_type,
        rssi: props.rssi.unwrap_or_default(),
        local_name: props.local_name.clone(),
        manufacturer_data,
        service_uuids,
        tx_power: props.tx_power_level.and_then(|v| i8::try_from(v).ok()),
        timestamp: SystemTime::now(),
    }
}
