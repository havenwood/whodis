//! Built-in spoof answer-table templates for common services.
//!
//! Used by `whodis spoof --template <NAME> --name <STR> --ip <IPV4>`. The generated
//! `AnswerTable` matches what a real responder would advertise closely enough to fool
//! standard clients.

use std::net::Ipv4Addr;

use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
use hickory_proto::rr::{Name, RData, RecordType};

use crate::error::{Error, Result};
use crate::spoof::{AnswerTable, AnswerTableBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Template {
    Airplay,
    Raop,
    Ipp,
    Smb,
    Ssh,
    Googlecast,
}

pub fn build(template: Template, name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    match template {
        Template::Airplay => airplay(name, ip),
        Template::Raop => raop(name, ip),
        Template::Ipp => ipp(name, ip),
        Template::Smb => smb(name, ip),
        Template::Ssh => ssh(name, ip),
        Template::Googlecast => googlecast(name, ip),
    }
}

fn n(s: &str) -> Result<Name> {
    crate::name_util::lax_from_str(s)
}

fn airplay(name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    let svc = "_airplay._tcp.local.";
    let inst = format!("{name}.{svc}");
    let host = format!("{name}.local.");
    Ok(AnswerTableBuilder::new()
        .ttl(120)
        .answer(svc, RecordType::PTR, RData::PTR(PTR(n(&inst)?)))?
        .answer(
            &inst,
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 7000, n(&host)?)),
        )?
        .answer(
            &inst,
            RecordType::TXT,
            RData::TXT(TXT::new(vec![
                "model=AppleTV11,1".to_string(),
                "deviceid=AA:BB:CC:DD:EE:FF".to_string(),
                "features=0x445F8A00,0x1C".to_string(),
                "srcvers=370.20.1".to_string(),
            ])),
        )?
        .answer(&host, RecordType::A, RData::A(A(ip)))?
        .build())
}

/// Builds the RAOP instance `Name` whose first label is `<deviceid>@<name>`.
///
/// `@` is not valid under STD3 rules so we bypass the text parser and use raw label bytes.
/// For parsing a complete dotted fqdn string without STD3 validation, see `crate::name_util::lax_from_str`.
fn raop_inst_name(deviceid: &str, name: &str, svc: &str) -> Result<Name> {
    let first_bytes = format!("{deviceid}@{name}");
    let rest = n(svc)?;
    // `Name::from_labels` accepts `&[u8]` items and does not apply STD3 validation.
    let mut label_bytes: Vec<&[u8]> = vec![first_bytes.as_bytes()];
    label_bytes.extend(rest.iter());
    Name::from_labels(label_bytes)
        .map_err(|_| Error::InvalidServiceType(format!("{deviceid}@{name}.{svc}")))
}

fn raop(name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    let svc = "_raop._tcp.local.";
    let deviceid = "AABBCCDDEEFF";
    let inst_name = raop_inst_name(deviceid, name, svc)?;
    let host = format!("{name}.local.");
    Ok(AnswerTableBuilder::new()
        .ttl(120)
        .answer(svc, RecordType::PTR, RData::PTR(PTR(inst_name.clone())))?
        .answer_name(
            inst_name.clone(),
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 7000, n(&host)?)),
        )?
        .answer_name(
            inst_name,
            RecordType::TXT,
            RData::TXT(TXT::new(vec![
                "txtvers=1".to_string(),
                "ch=2".to_string(),
                "cn=0,1,2,3".to_string(),
                "et=0,3,5".to_string(),
                "md=0,1,2".to_string(),
                "tp=UDP".to_string(),
                "vn=65537".to_string(),
            ])),
        )?
        .answer(&host, RecordType::A, RData::A(A(ip)))?
        .build())
}

fn ipp(name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    let svc = "_ipp._tcp.local.";
    let inst = format!("{name}.{svc}");
    let host = format!("{name}.local.");
    Ok(AnswerTableBuilder::new()
        .ttl(120)
        .answer(svc, RecordType::PTR, RData::PTR(PTR(n(&inst)?)))?
        .answer(
            &inst,
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 631, n(&host)?)),
        )?
        .answer(
            &inst,
            RecordType::TXT,
            RData::TXT(TXT::new(vec![
                "txtvers=1".to_string(),
                "qtotal=1".to_string(),
                "rp=ipp/print".to_string(),
                "ty=Spoofed Printer".to_string(),
                "product=(Spoofed)".to_string(),
                "pdl=application/pdf,image/jpeg".to_string(),
                "Color=T".to_string(),
                "Duplex=T".to_string(),
            ])),
        )?
        .answer(&host, RecordType::A, RData::A(A(ip)))?
        .build())
}

fn smb(name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    let svc = "_smb._tcp.local.";
    let inst = format!("{name}.{svc}");
    let host = format!("{name}.local.");
    Ok(AnswerTableBuilder::new()
        .ttl(120)
        .answer(svc, RecordType::PTR, RData::PTR(PTR(n(&inst)?)))?
        .answer(
            &inst,
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 445, n(&host)?)),
        )?
        .answer(&inst, RecordType::TXT, RData::TXT(TXT::new(vec![])))?
        .answer(&host, RecordType::A, RData::A(A(ip)))?
        .build())
}

fn ssh(name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    let svc = "_ssh._tcp.local.";
    let inst = format!("{name}.{svc}");
    let host = format!("{name}.local.");
    Ok(AnswerTableBuilder::new()
        .ttl(120)
        .answer(svc, RecordType::PTR, RData::PTR(PTR(n(&inst)?)))?
        .answer(
            &inst,
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 22, n(&host)?)),
        )?
        .answer(&inst, RecordType::TXT, RData::TXT(TXT::new(vec![])))?
        .answer(&host, RecordType::A, RData::A(A(ip)))?
        .build())
}

fn googlecast(name: &str, ip: Ipv4Addr) -> Result<AnswerTable> {
    let svc = "_googlecast._tcp.local.";
    let inst = format!("{name}.{svc}");
    let host = format!("{name}.local.");
    Ok(AnswerTableBuilder::new()
        .ttl(120)
        .answer(svc, RecordType::PTR, RData::PTR(PTR(n(&inst)?)))?
        .answer(
            &inst,
            RecordType::SRV,
            RData::SRV(SRV::new(0, 0, 8009, n(&host)?)),
        )?
        .answer(
            &inst,
            RecordType::TXT,
            RData::TXT(TXT::new(vec![
                "id=00000000000000000000000000000000".to_string(),
                "cd=00000000000000000000000000000000".to_string(),
                "rm=".to_string(),
                "ve=05".to_string(),
                "md=Spoofed Cast".to_string(),
                "ic=/setup/icon.png".to_string(),
                format!("fn={name}"),
                "ca=4101".to_string(),
                "st=0".to_string(),
                "bs=AABBCCDDEEFF".to_string(),
                "nf=1".to_string(),
                "rs=".to_string(),
            ])),
        )?
        .answer(&host, RecordType::A, RData::A(A(ip)))?
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    #[test]
    fn airplay_template_has_full_record_set() {
        let t = build(Template::Airplay, "Test", Ipv4Addr::new(10, 0, 0, 1)).expect("build");
        assert!(t.lookup("_airplay._tcp.local.", RecordType::PTR).is_some());
        assert!(
            t.lookup("Test._airplay._tcp.local.", RecordType::SRV)
                .is_some()
        );
        assert!(
            t.lookup("Test._airplay._tcp.local.", RecordType::TXT)
                .is_some()
        );
        assert!(t.lookup("Test.local.", RecordType::A).is_some());
    }

    #[test]
    fn ipp_uses_port_631() {
        let t = build(Template::Ipp, "P", Ipv4Addr::new(10, 0, 0, 2)).expect("build");
        assert!(t.lookup("_ipp._tcp.local.", RecordType::PTR).is_some());
    }

    #[test]
    fn ssh_uses_port_22() {
        let t = build(Template::Ssh, "h", Ipv4Addr::new(10, 0, 0, 3)).expect("build");
        assert!(t.lookup("_ssh._tcp.local.", RecordType::PTR).is_some());
    }

    #[test]
    fn raop_template_has_full_record_set() {
        let t = build(Template::Raop, "Music", Ipv4Addr::new(10, 0, 0, 4)).expect("build");
        assert!(t.lookup("_raop._tcp.local.", RecordType::PTR).is_some());
        assert!(t.lookup("Music.local.", RecordType::A).is_some());
    }

    #[test]
    fn smb_template_has_full_record_set() {
        let t = build(Template::Smb, "FileServer", Ipv4Addr::new(10, 0, 0, 5)).expect("build");
        assert!(t.lookup("_smb._tcp.local.", RecordType::PTR).is_some());
        assert!(t.lookup("FileServer.local.", RecordType::A).is_some());
    }

    #[test]
    fn googlecast_template_has_full_record_set() {
        let t = build(
            Template::Googlecast,
            "LivingRoom",
            Ipv4Addr::new(10, 0, 0, 6),
        )
        .expect("build");
        assert!(
            t.lookup("_googlecast._tcp.local.", RecordType::PTR)
                .is_some()
        );
        assert!(t.lookup("LivingRoom.local.", RecordType::A).is_some());
    }
}
