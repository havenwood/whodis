//! Compatibility shims for the Hickory 0.26 low-level public-field API.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record};

pub(crate) trait MessageExt {
    fn id(&self) -> u16;
    fn message_type(&self) -> MessageType;
    fn queries(&self) -> &[Query];
    fn answers(&self) -> &[Record];
    fn additionals(&self) -> &[Record];
    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self;
    fn set_op_code(&mut self, op_code: OpCode) -> &mut Self;
    fn set_recursion_desired(&mut self, recursion_desired: bool) -> &mut Self;
    fn set_authoritative(&mut self, authoritative: bool) -> &mut Self;
    fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self;
}

impl MessageExt for Message {
    fn id(&self) -> u16 {
        self.metadata.id
    }

    fn message_type(&self) -> MessageType {
        self.metadata.message_type
    }

    fn queries(&self) -> &[Query] {
        &self.queries
    }

    fn answers(&self) -> &[Record] {
        &self.answers
    }

    fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.metadata.message_type = message_type;
        self
    }

    fn set_op_code(&mut self, op_code: OpCode) -> &mut Self {
        self.metadata.op_code = op_code;
        self
    }

    fn set_recursion_desired(&mut self, recursion_desired: bool) -> &mut Self {
        self.metadata.recursion_desired = recursion_desired;
        self
    }

    fn set_authoritative(&mut self, authoritative: bool) -> &mut Self {
        self.metadata.authoritative = authoritative;
        self
    }

    fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self {
        self.metadata.response_code = response_code;
        self
    }
}

pub(crate) trait RecordExt {
    fn name(&self) -> &Name;
    fn ttl(&self) -> u32;
    fn data(&self) -> Option<&RData>;
    fn set_dns_class(&mut self, dns_class: DNSClass);
    fn set_mdns_cache_flush(&mut self, flag: bool);
}

impl RecordExt for Record {
    fn name(&self) -> &Name {
        &self.name
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }

    fn data(&self) -> Option<&RData> {
        Some(&self.data)
    }

    fn set_dns_class(&mut self, dns_class: DNSClass) {
        self.dns_class = dns_class;
    }

    fn set_mdns_cache_flush(&mut self, flag: bool) {
        self.mdns_cache_flush = flag;
    }
}

pub(crate) trait SrvExt {
    fn priority(&self) -> u16;
    fn weight(&self) -> u16;
    fn port(&self) -> u16;
    fn target(&self) -> &Name;
}

impl SrvExt for SRV {
    fn priority(&self) -> u16 {
        self.priority
    }

    fn weight(&self) -> u16 {
        self.weight
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn target(&self) -> &Name {
        &self.target
    }
}

pub(crate) trait TxtExt {
    fn iter(&self) -> std::slice::Iter<'_, Box<[u8]>>;
}

impl TxtExt for TXT {
    fn iter(&self) -> std::slice::Iter<'_, Box<[u8]>> {
        self.txt_data.iter()
    }
}
