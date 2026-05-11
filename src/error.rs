//! Crate-wide error type.

use std::io;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("transport: {0}")]
    Transport(#[from] io::Error),

    #[error("dns: {0}")]
    Dns(#[from] hickory_proto::ProtoError),

    #[error("authorization blocked op {op} for target {target}")]
    Authorization { op: &'static str, target: String },

    #[error("credcap error: {reason}")]
    Credcap { reason: String },

    #[error("timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("no usable network interface found")]
    NoInterface,

    #[error("invalid service type: {0}")]
    InvalidServiceType(String),

    #[error("inventory error: {reason}")]
    Inventory { reason: String },

    #[error("no records observed for {target} on the LAN within {}s", timeout.as_secs())]
    NoRecords {
        target: String,
        timeout: std::time::Duration,
    },

    #[error("name resolution protocol error: {reason}")]
    NameRes { reason: String },

    #[error("spoof verify failed: {reason}")]
    SpoofVerify { reason: String },

    #[error("BLE adapter unavailable: {reason}")]
    BleAdapter { reason: String },

    #[error(
        "BLE permission denied — grant Bluetooth access in System Settings > Privacy & Security > Bluetooth"
    )]
    BlePermissionDenied,

    #[error("BLE scan error: {reason}")]
    BleScan { reason: String },

    #[error("invalid CLI usage: {reason}")]
    Cli { reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timeout_message_includes_duration() {
        let e = Error::Timeout(Duration::from_secs(3));
        assert!(format!("{e}").contains("3s"), "got {e}");
    }

    #[test]
    fn authorization_message_includes_op_and_target() {
        let e = Error::Authorization {
            op: "spoof",
            target: "192.168.1.1".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("spoof"), "got {s}");
        assert!(s.contains("192.168.1.1"), "got {s}");
    }
}
