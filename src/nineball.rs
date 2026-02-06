use crate::Manifest;
use crate::log;
use alloc::collections::BTreeMap;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::protocol::init::ServiceStatus;

pub struct InitManager {
    pub running: bool,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub config: Manifest,
    pub services: BTreeMap<usize, ServiceStatus>,
}

impl InitManager {
    pub fn new(config: Manifest) -> Self {
        Self {
            running: false,
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            config: config,
            services: BTreeMap::new(),
        }
    }
    pub fn launch(&mut self) -> Result<(), Error> {
        for service in &self.config.services {
            log!("Launching service: {}", service.name);
        }
        Ok(())
    }
}
