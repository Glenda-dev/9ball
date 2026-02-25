use crate::NineBallManager;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::{InitService, ProcessService};
use glenda::ipc::Badge;
use glenda::protocol::init::{ServiceState, ServiceStatus};

impl<'a> InitService for NineBallManager<'a> {
    fn start_service(&mut self, service_name: &str) -> Result<(), Error> {
        if let Some(status) = self.services.get(service_name) {
            if status.running == ServiceState::Running || status.running == ServiceState::Starting {
                warn!("Service '{}' is already running or starting", service_name);
                return Err(Error::AlreadyExists);
            }
        }

        if !self.check_dependencies(service_name) {
            error!("Cannot start service '{}': dependencies not met", service_name);
            return Err(Error::PermissionDenied); // Or a more specific error for dependencies
        }

        let entry =
            self.config.services.iter().find(|s| s.name == service_name).ok_or(Error::NotFound)?;

        log!("Launching service: {}", entry.name);
        let pid = self.proc_client.spawn(Badge::null(), &entry.name)?;
        self.services.insert(entry.name.clone(), ServiceStatus::new(entry.name.clone(), pid));
        Ok(())
    }

    fn stop_service(&mut self, service: &str) -> Result<(), Error> {
        let status = self.services.get(service).ok_or(Error::NotFound)?;
        let pid = status.pid;
        self.proc_client.kill(Badge::null(), pid)?;
        self.services.remove(service);
        Ok(())
    }

    fn restart_service(&mut self, service: &str) -> Result<(), Error> {
        self.stop_service(service)?;
        self.start_service(service)
    }

    fn reload_service(&mut self, service: &str) -> Result<(), Error> {
        // Simple reload: restart
        self.restart_service(service)
    }

    fn query_service(&self, service: &str) -> Result<ServiceStatus, Error> {
        self.services.get(service).cloned().ok_or(Error::NotFound)
    }

    fn report_service(&mut self, badge: Badge, status: ServiceState) -> Result<(), Error> {
        let pid = badge.bits();
        if let Some(service_status) = self.services.values_mut().find(|s| s.pid == pid) {
            let old_status = service_status.running;
            service_status.running = status;
            log!("Service {} transition: {:?} -> {:?}", service_status.name, old_status, status);

            match status {
                ServiceState::Running => {
                    self.bootstrap().ok();
                }
                ServiceState::Failed | ServiceState::Exited | ServiceState::Stopped => {
                    // Trigger reconciliation
                    self.bootstrap().ok();
                }
                _ => {}
            }
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    fn list_services(&self) -> Result<Vec<(String, ServiceStatus)>, Error> {
        Ok(self.services.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}
