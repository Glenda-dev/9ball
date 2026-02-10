use glenda::cap::{CapPtr, Endpoint};

pub const INIT_SLOT: CapPtr = CapPtr::from(16);
pub const MANIFEST_SLOT: CapPtr = CapPtr::from(17);
pub const INIT_CAP: Endpoint = Endpoint::from(INIT_SLOT);
pub const MANIFEST_CAP: Endpoint = Endpoint::from(MANIFEST_SLOT);

pub const MANIFEST_ADDR: usize = 0x3000_0000;
