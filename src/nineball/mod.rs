pub mod init;
pub mod server;

use crate::Manifest;
use crate::log;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::client::{ProcessClient, ResourceClient};
use glenda::error::Error;
use glenda::interface::InitService;
use glenda::protocol::init::ServiceStatus;

pub struct NineBallManager<'a> {
    pub running: bool,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub recv: CapPtr,
    pub config: Manifest,
    pub proc_client: &'a mut ProcessClient,
    pub res_client: &'a mut ResourceClient,
    pub services: BTreeMap<String, ServiceStatus>,
}

impl<'a> NineBallManager<'a> {
    pub fn new(proc_client: &'a mut ProcessClient, res_client: &'a mut ResourceClient) -> Self {
        Self {
            running: false,
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            recv: CapPtr::null(),
            config: Manifest::new(),
            services: BTreeMap::new(),
            proc_client,
            res_client,
        }
    }

    pub fn check_dependencies(&self, name: &str) -> bool {
        if let Some(service) = self.config.services.iter().find(|s| s.name == name) {
            for dep in &service.dependencies {
                if !self.services.contains_key(dep) {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    pub fn launch(&mut self) -> Result<(), Error> {
        let total_to_start = self.config.services.iter().filter(|s| s.auto_start).count();
        let mut started_count = 0;

        while started_count < total_to_start {
            let mut made_progress = false;

            let mut to_start = Vec::new();
            for service in &self.config.services {
                if service.auto_start && !self.services.contains_key(&service.name) {
                    if self.check_dependencies(&service.name) {
                        to_start.push(service.name.clone());
                    }
                }
            }

            for name in to_start {
                self.start_service(&name)?;
                started_count += 1;
                made_progress = true;
            }

            if !made_progress && started_count < total_to_start {
                log!(
                    "Error: Circular dependency or missing dependencies detected for auto-start services."
                );
                return Err(Error::InvalidConfig);
            }
        }
        Ok(())
    }
}
