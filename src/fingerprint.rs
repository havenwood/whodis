//! Identify known device classes from mDNS TXT records.
//!
//! Pure compute. No I/O. Signature matches are first-hit. The signature DB lives as a
//! `&'static [Sig]` (cheap), and `identify` clones the matching entry into an owned
//! `Fingerprint` so it can be serialized over JSONL without lifetime entanglements.

use crate::types::{Fingerprint, Instance};

#[derive(Debug)]
struct Sig {
    txt_key: &'static str,
    needle: &'static str,
    vendor: &'static str,
    product: &'static str,
    os_hint: Option<&'static str>,
    capabilities: &'static [&'static str],
}

impl Sig {
    fn to_fingerprint(&self) -> Fingerprint {
        Fingerprint {
            vendor: self.vendor.to_string(),
            product: self.product.to_string(),
            os_hint: self.os_hint.map(String::from),
            capabilities: self.capabilities.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

#[allow(clippy::too_many_lines, reason = "Signature DB definition")]
fn signatures() -> &'static [Sig] {
    static SIGS: &[Sig] = &[
        Sig {
            txt_key: "model",
            needle: "AppleTV",
            vendor: "Apple",
            product: "AppleTV",
            os_hint: Some("tvOS"),
            capabilities: &["airplay", "homekit"],
        },
        Sig {
            txt_key: "model",
            needle: "MacBookPro",
            vendor: "Apple",
            product: "MacBook Pro",
            os_hint: Some("macOS"),
            capabilities: &["airplay-receiver"],
        },
        Sig {
            txt_key: "model",
            needle: "MacBookAir",
            vendor: "Apple",
            product: "MacBook Air",
            os_hint: Some("macOS"),
            capabilities: &["airplay-receiver"],
        },
        Sig {
            txt_key: "am",
            needle: "AudioAccessory",
            vendor: "Apple",
            product: "HomePod",
            os_hint: Some("audioOS"),
            capabilities: &["airplay", "homekit", "siri"],
        },
        Sig {
            txt_key: "am",
            needle: "iPhone",
            vendor: "Apple",
            product: "iPhone",
            os_hint: Some("iOS"),
            capabilities: &["airplay-sender", "handoff"],
        },
        Sig {
            txt_key: "ty",
            needle: "HP LaserJet",
            vendor: "HP",
            product: "LaserJet",
            os_hint: None,
            capabilities: &["airprint", "ipp"],
        },
        Sig {
            txt_key: "ty",
            needle: "Brother",
            vendor: "Brother",
            product: "Printer",
            os_hint: None,
            capabilities: &["airprint", "ipp"],
        },
        Sig {
            txt_key: "md",
            needle: "Sonos",
            vendor: "Sonos",
            product: "Speaker",
            os_hint: None,
            capabilities: &["airplay", "spotify-connect"],
        },
        Sig {
            txt_key: "fn",
            needle: "Plex",
            vendor: "Plex",
            product: "Media Server",
            os_hint: None,
            capabilities: &["plex"],
        },
        Sig {
            txt_key: "CPath",
            needle: "/spotifyconnect",
            vendor: "Spotify",
            product: "Spotify Connect endpoint",
            os_hint: None,
            capabilities: &["spotify-connect"],
        },
        Sig {
            txt_key: "model",
            needle: "TimeCapsule",
            vendor: "Apple",
            product: "Time Capsule",
            os_hint: None,
            capabilities: &["afp", "smb", "backup"],
        },
        Sig {
            txt_key: "md",
            needle: "Tesla Model",
            vendor: "Tesla",
            product: "Vehicle",
            os_hint: None,
            capabilities: &["tesla"],
        },
        Sig {
            txt_key: "md",
            needle: "BSB002",
            vendor: "Philips",
            product: "Hue Bridge",
            os_hint: None,
            capabilities: &["hue", "homekit"],
        },
    ];
    SIGS
}

#[must_use]
pub fn identify(instance: &Instance) -> Option<Fingerprint> {
    for sig in signatures() {
        if let Some(value) = instance.txt.get(sig.txt_key)
            && let Ok(s) = std::str::from_utf8(value)
            && s.contains(sig.needle)
        {
            return Some(sig.to_fingerprint());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;

    use super::*;
    use crate::types::{Protocol, ServiceType};

    fn make_instance(pairs: &[(&str, &[u8])]) -> Instance {
        let mut txt = BTreeMap::new();
        for (k, v) in pairs {
            txt.insert((*k).to_string(), Bytes::copy_from_slice(v));
        }
        Instance {
            service_type: ServiceType::new("_x", Protocol::Tcp),
            instance_name: "x".into(),
            host: "x.local".into(),
            port: 0,
            addrs: Vec::new(),
            txt,
        }
    }

    #[test]
    fn appletv_model_matches() {
        let inst = make_instance(&[("model", b"AppleTV11,1")]);
        let fp = identify(&inst).expect("match");
        assert_eq!(fp.vendor, "Apple");
        assert_eq!(fp.product, "AppleTV");
    }

    #[test]
    fn homepod_via_am_field() {
        let inst = make_instance(&[("am", b"AudioAccessory5,1")]);
        let fp = identify(&inst).expect("match");
        assert_eq!(fp.product, "HomePod");
    }

    #[test]
    fn hp_printer_via_ty_field() {
        let inst = make_instance(&[("ty", b"HP LaserJet M283")]);
        let fp = identify(&inst).expect("match");
        assert_eq!(fp.vendor, "HP");
    }

    #[test]
    fn unknown_returns_none() {
        let inst = make_instance(&[("model", b"WhateverDevice")]);
        assert!(identify(&inst).is_none());
    }

    #[test]
    fn binary_txt_value_does_not_panic() {
        let inst = make_instance(&[("model", &[0xff, 0xfe, 0xfd])]);
        assert!(identify(&inst).is_none());
    }

    #[test]
    fn hue_bridge_via_md_field() {
        let inst = make_instance(&[("md", b"BSB002")]);
        let fp = identify(&inst).expect("match");
        assert_eq!(fp.product, "Hue Bridge");
    }
}
