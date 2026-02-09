#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda;

use glenda::cap::{MONITOR_CAP, REPLY_SLOT};
use glenda::error::Error;
use glenda::interface::SystemService;

mod config;
mod init;
mod nineball;
mod server;

pub use config::{Manifest, ServiceEntry};
pub use nineball::InitManager;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("{}9ball: {}{}", glenda::console::ANSI_BLUE, format_args!($($arg)*), glenda::console::ANSI_RESET);
    })
}

#[unsafe(no_mangle)]
fn main() -> usize {
    log!("Init System starting...");

    // 1. Load Manifest
    let manifest = config::load();

    // 2. Spawn services

    let mut server = InitManager::new(manifest);

    if let Err(e) = load_9ball(&mut server) {
        log!("Failed to load: {:?}", e);
        return 1;
    }
    server.run().expect("9Ball Init exited");
    1
}

fn load_9ball(server: &mut InitManager) -> Result<(), Error> {
    server.listen(MONITOR_CAP, REPLY_SLOT)?;
    server.init()?;
    Ok(())
}
