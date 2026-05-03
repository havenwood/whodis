//! whodis: mDNS / Bonjour recon and spoof toolkit.
//!
//! See the [crate README](https://github.com/havenwood/whodis) for usage.

#![doc(html_root_url = "https://docs.rs/whodis")]

mod error;
mod types;

pub use error::{Error, Result};
pub use types::{Device, Fingerprint, HostAnswer, Instance, Protocol, ServiceType};
