//! Apple Continuity (manufacturer data `0x004C`) TLV decoder.
//!
//! Each byte stream is a sequence of `(type: u8, length: u8, payload: [u8; length])`
//! records. Unknown types are preserved as [`ContinuityPayload::Unknown`] so the
//! watch state machine can flag protocol evolution.

use serde::{Deserialize, Serialize};

use crate::ble::types::AirDropMode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContinuityPayload {
    NearbyInfo {
        status_flags: u8,
        action_code: u8,
        wake_status: u8,
        raw: Vec<u8>,
    },
    HandoffSeed {
        raw: Vec<u8>,
    },
    AirDropPair {
        mode: AirDropMode,
        raw: Vec<u8>,
    },
    FindMy {
        raw: Vec<u8>,
    },
    ProximityPair {
        model_id: Option<u16>,
        raw: Vec<u8>,
    },
    Unknown {
        ty: u8,
        raw: Vec<u8>,
    },
}

/// Decode a `0x004C` manufacturer-data byte stream into a list of [`ContinuityPayload`]s.
/// Stops cleanly on truncation; does not panic on malformed input.
#[must_use]
pub fn decode(bytes: &[u8]) -> Vec<ContinuityPayload> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor + 2 <= bytes.len() {
        let Some(ty) = bytes.get(cursor) else { break };
        let Some(len_byte) = bytes.get(cursor + 1) else {
            break;
        };
        let len = usize::from(*len_byte);
        let payload_start = cursor + 2;
        let payload_end = payload_start + len;
        if payload_end > bytes.len() {
            break;
        }
        let raw = bytes
            .get(payload_start..payload_end)
            .unwrap_or_default()
            .to_vec();
        out.push(decode_one(*ty, raw));
        cursor = payload_end;
    }
    out
}

fn decode_one(ty: u8, raw: Vec<u8>) -> ContinuityPayload {
    match ty {
        0x05 => decode_airdrop_pair(raw),
        0x07 => ContinuityPayload::HandoffSeed { raw },
        0x0F | 0x10 => decode_nearby_info(raw),
        0x12 => ContinuityPayload::FindMy { raw },
        0x16 => decode_proximity_pair(raw),
        _ => ContinuityPayload::Unknown { ty, raw },
    }
}

fn decode_airdrop_pair(raw: Vec<u8>) -> ContinuityPayload {
    // Byte 0 status/version flag. Low two bits encode receive mode:
    //   0b10 = Everyone, 0b01 = ContactsOnly, 0b00 = Off (best-effort).
    let mode = match raw.first().copied().unwrap_or(0) & 0b0000_0011 {
        0b0000_0010 => AirDropMode::Everyone,
        0b0000_0001 => AirDropMode::ContactsOnly,
        _ => AirDropMode::Off,
    };
    ContinuityPayload::AirDropPair { mode, raw }
}

fn decode_nearby_info(raw: Vec<u8>) -> ContinuityPayload {
    // Byte 0: status_flags. High nibble = action code, low nibble = status bits.
    // Byte 1: wake_status (lock-state inference uses this; v1 only stores it).
    let status_flags = raw.first().copied().unwrap_or(0);
    let action_code = (status_flags >> 4) & 0x0F;
    let wake_status = raw.get(1).copied().unwrap_or(0);
    ContinuityPayload::NearbyInfo {
        status_flags,
        action_code,
        wake_status,
        raw,
    }
}

fn decode_proximity_pair(raw: Vec<u8>) -> ContinuityPayload {
    // Bytes 1..3: model_id (big-endian u16). Byte 0 is a status flag.
    let model_id = raw
        .get(1..3)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_be_bytes);
    ContinuityPayload::ProximityPair { model_id, raw }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_decodes_to_empty_vec() {
        assert!(decode(&[]).is_empty());
    }

    #[test]
    fn truncated_record_stops_cleanly() {
        // Type 0x05 says length 0x10 (16 bytes) but only 4 follow.
        let bytes = vec![0x05, 0x10, 0x01, 0x02, 0x03, 0x04];
        let out = decode(&bytes);
        assert!(out.is_empty(), "should stop on truncation, got {out:?}");
    }

    #[test]
    fn unknown_type_preserved() {
        // Type 0xFF length 0x02 payload [0xAA, 0xBB]
        let out = decode(&[0xFF, 0x02, 0xAA, 0xBB]);
        assert_eq!(out.len(), 1);
        let Some(ContinuityPayload::Unknown { ty, raw }) = out.first() else {
            unreachable!("decoded one Unknown record above");
        };
        assert_eq!(*ty, 0xFF);
        assert_eq!(raw, &vec![0xAA, 0xBB]);
    }

    #[test]
    fn nearby_info_decodes_status_and_wake() {
        // Type 0x10 length 0x05 payload [0x57, 0x18, 0x00, 0x00, 0x00]
        let out = decode(&[0x10, 0x05, 0x57, 0x18, 0x00, 0x00, 0x00]);
        assert_eq!(out.len(), 1);
        let Some(ContinuityPayload::NearbyInfo {
            status_flags,
            action_code,
            wake_status,
            ..
        }) = out.first()
        else {
            unreachable!("decoded one NearbyInfo record above");
        };
        assert_eq!(*status_flags, 0x57);
        assert_eq!(*action_code, 5);
        assert_eq!(*wake_status, 0x18);
    }

    #[test]
    fn airdrop_pair_decodes_everyone_mode() {
        // Type 0x05 length 0x12 first byte = 0x02 (Everyone bit set)
        let mut payload = vec![0x02];
        payload.extend_from_slice(&[0u8; 17]);
        let mut bytes = vec![0x05, 0x12];
        bytes.extend_from_slice(&payload);
        let out = decode(&bytes);
        let Some(ContinuityPayload::AirDropPair { mode, .. }) = out.first() else {
            unreachable!("decoded one AirDropPair record above");
        };
        assert_eq!(*mode, AirDropMode::Everyone);
    }

    #[test]
    fn proximity_pair_extracts_model_id() {
        // Type 0x16 length 0x06 payload [status, model_hi, model_lo, ...]
        let out = decode(&[0x16, 0x06, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00]);
        let Some(ContinuityPayload::ProximityPair { model_id, .. }) = out.first() else {
            unreachable!("decoded one ProximityPair record above");
        };
        assert_eq!(*model_id, Some(0x1234));
    }

    #[test]
    fn multiple_records_in_one_stream() {
        // 0x07 (handoff) length 4 + 0x12 (findmy) length 2
        let bytes = vec![0x07, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x02, 0xCA, 0xFE];
        let out = decode(&bytes);
        assert_eq!(out.len(), 2);
        assert!(matches!(
            out.first(),
            Some(ContinuityPayload::HandoffSeed { .. })
        ));
        assert!(matches!(out.get(1), Some(ContinuityPayload::FindMy { .. })));
    }
}
