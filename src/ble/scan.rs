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
