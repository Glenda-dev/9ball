use glenda::cap::{CapPtr, Endpoint};

pub const MANIFEST_SLOT: CapPtr = CapPtr::from(15);
pub const MANIFEST_CAP: Endpoint = Endpoint::from(MANIFEST_SLOT);

pub const MANIFEST_ADDR: usize = 0x3000_0000;
