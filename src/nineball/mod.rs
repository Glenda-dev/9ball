pub mod init;
pub mod server;

use crate::Manifest;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::client::{ProcessClient, ResourceClient};
use glenda::error::Error;
use glenda::interface::InitService;
use glenda::protocol::init::{ServiceState, ServiceStatus};

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
                if let Some(status) = self.services.get(dep) {
                    if status.running != ServiceState::Running {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    pub fn bootstrap(&mut self) -> Result<(), Error> {
        let mut made_progress = true;

        while made_progress {
            made_progress = false;
            let mut to_start = Vec::new();
            for service in &self.config.services {
                if service.auto_start {
                    let state = self.services.get(&service.name).map(|s| s.running);
                    let should_start = match state {
                        Some(ServiceState::Stopped)
                        | Some(ServiceState::Failed)
                        | Some(ServiceState::Exited)
                        | None => true,
                        _ => false,
                    };

                    if should_start && self.check_dependencies(&service.name) {
                        to_start.push(service.name.clone());
                    }
                }
            }

            for name in to_start {
                match self.start_service(&name) {
                    Ok(_) => made_progress = true,
                    Err(e) => {
                        error!("Bootstrap: Failed to start service {}: {:?}", name, e);
                        // Mark as Failed to avoid repeated attempts in this cycle
                        self.services.insert(
                            name.clone(),
                            ServiceStatus {
                                name: name.clone(),
                                running: ServiceState::Failed,
                                pid: 0,
                            },
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
