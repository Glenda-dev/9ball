use crate::InitManager;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::InitService;
use glenda::ipc::Badge;
use glenda::protocol::init::{ServiceState, ServiceStatus};

impl InitService for InitManager {
    fn start_service(&mut self, _service: String) -> Result<(), Error> {
        unimplemented!()
    }

    fn stop_service(&mut self, _service: String) -> Result<(), Error> {
        unimplemented!()
    }

    fn restart_service(&mut self, _service: String) -> Result<(), Error> {
        unimplemented!()
    }

    fn reload_service(&mut self, _service: String) -> Result<(), Error> {
        unimplemented!()
    }

    fn query_service(&self, _service: String) -> Result<ServiceStatus, Error> {
        unimplemented!()
    }

    fn report_service(&self, _pid: Badge, _status: ServiceState) -> Result<(), Error> {
        unimplemented!()
    }

    fn list_services(&self) -> Result<Vec<(String, ServiceStatus)>, Error> {
        unimplemented!()
    }
}
