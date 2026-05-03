//! whodis: mDNS / Bonjour recon and spoof toolkit.
//!
//! See the [crate README](https://github.com/havenwood/whodis) for usage.

#![doc(html_root_url = "https://docs.rs/whodis")]

mod auth;
mod error;
mod mode;
#[allow(dead_code, reason = "consumed by cli module in Task 12")]
mod output;
mod transport;
mod types;

pub mod browse;
pub mod fingerprint;
pub mod flood;
pub mod probe;
pub mod spoof;

pub use auth::Authorization;
pub use error::{Error, Result};
pub use mode::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, Mode};
pub use types::{Device, Fingerprint, HostAnswer, Instance, Protocol, ServiceType};
