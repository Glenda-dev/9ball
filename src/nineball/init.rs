use crate::NineBallManager;
use crate::log;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::{InitService, ProcessService};
use glenda::ipc::Badge;
use glenda::protocol::init::{ServiceState, ServiceStatus};

impl<'a> InitService for NineBallManager<'a> {
    fn start_service(&mut self, service: &str) -> Result<(), Error> {
        if self.services.contains_key(service) {
            return Err(Error::AlreadyExists);
        }

        if !self.check_dependencies(service) {
            return Err(Error::PermissionDenied); // Or a more specific error for dependencies
        }

        let service =
            self.config.services.iter().find(|s| s.name == service).ok_or(Error::NotFound)?;

        log!("Launching service: {}", service.name);
        let pid = self.proc_client.spawn(Badge::null(), &service.name)?;
        self.services.insert(service.name.clone(), ServiceStatus::new(service.name.clone(), pid));
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
            service_status.running = status;
            log!("Service {} reported status: {:?}", service_status.name, status);
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    fn list_services(&self) -> Result<Vec<(String, ServiceStatus)>, Error> {
        Ok(self.services.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}
