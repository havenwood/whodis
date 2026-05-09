//! whodis: mDNS / Bonjour recon and spoof toolkit.
//!
//! See the [crate README](https://github.com/havenwood/whodis) for usage.

#![doc(html_root_url = "https://docs.rs/whodis")]

pub mod arp;
mod auth;
pub mod capture;
mod cli;
pub mod clone;
pub(crate) mod dns_sd;
mod error;
mod hickory_compat;
mod mode;
mod name_util;
pub mod oui;
mod output;
pub mod relay;
pub mod report;
pub mod scope;
pub mod spoof_table;
pub mod spoof_verify;
mod transport;
mod types;

pub mod spoof_template;
pub mod sweep;

pub mod browse;
pub mod detect;
pub mod fingerprint;
pub mod flood;
pub mod probe;
pub mod spoof;
pub mod ssdp;
pub mod ssdp_table;

pub use auth::Authorization;
pub use cli::{Cli, Cmd, FloodCmd, run};
pub use error::{Error, Result};
pub use mode::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, Mode};
pub use spoof_verify::{SpoofVerifyOptions, SpoofVerifyResult, spoof_verify};
pub use sweep::{SweepOptions, SweepProbe};
pub use types::{
    Device, Fingerprint, HostAnswer, Instance, NeighborEntry, Protocol, ServiceType, SweepResult,
};
