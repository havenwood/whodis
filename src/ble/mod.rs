//! BLE (Bluetooth Low Energy) recon: passive advertisement scan,
//! Apple Continuity packet decode, device-class fingerprinting.
//!
//! macOS-first via `btleplug 0.12` wrapping `CoreBluetooth`. Linux
//! works through the same crate (`BlueZ` backend).

pub mod continuity;
pub mod fingerprint;
pub mod probe;
pub mod scan;
pub mod service_uuids;
pub mod types;

pub use types::{
    AddressType, AirDropMode, BleAdvertisement, BleDevice, DeviceClass, PeripheralId, RssiSample,
};
