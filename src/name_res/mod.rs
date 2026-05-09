//! LLMNR + NBT-NS protocol layer (Windows-side name resolution).
//!
//! This module sits parallel to `ssdp.rs` and provides probe / spoof
//! / watch primitives for LLMNR. NBT-NS lives next to it but is
//! shipped in a follow-up plan.

pub mod llmnr;
pub mod preset;
pub mod table;
