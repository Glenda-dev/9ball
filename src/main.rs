#![no_std]
#![no_main]
#![allow(dead_code)]

#[macro_use]
extern crate glenda;

extern crate alloc;
use glenda::cap::CapType;
use glenda::cap::{ENDPOINT_CAP, ENDPOINT_SLOT, MONITOR_CAP, RECV_SLOT, REPLY_SLOT};
use glenda::client::{ProcessClient, ResourceClient};
use glenda::error::Error;
use glenda::interface::{ResourceService, SystemService};
use glenda::ipc::Badge;

mod config;
mod layout;
mod nineball;

pub use config::Manifest;
pub use nineball::NineBallManager;

#[unsafe(no_mangle)]
fn main() -> usize {
    glenda::console::init_logging("9ball");
    log!("Init System starting...");
    let mut proc_client = ProcessClient::new(MONITOR_CAP);
    let mut res_client = ResourceClient::new(MONITOR_CAP);
    res_client
        .alloc(Badge::null(), CapType::Endpoint, 0, ENDPOINT_SLOT)
        .expect("Failed to allocate endpoint cap for 9ball");
    let mut server = NineBallManager::new(&mut proc_client, &mut res_client);

    if let Err(e) = load_9ball(&mut server) {
        log!("Failed to load: {:?}", e);
        return 1;
    }
    server.run().expect("9Ball Init exited");
    1
}

fn load_9ball(server: &mut NineBallManager) -> Result<(), Error> {
    server.init()?;
    server.listen(ENDPOINT_CAP, REPLY_SLOT, RECV_SLOT)?;
    Ok(())
}
