//! Apple Continuity (manufacturer data `0x004C`) TLV decoder. Filled in by Task 3.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    missing_copy_implementations,
    reason = "enum variants will be added in Task 3"
)]
pub enum ContinuityPayload {}
