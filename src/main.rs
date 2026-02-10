#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
use glenda;
use glenda::cap::REPLY_SLOT;
use glenda::error::Error;
use glenda::interface::SystemService;
use layout::INIT_CAP;

mod config;
mod layout;
mod nineball;

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

    let mut server = InitManager::new();

    if let Err(e) = load_9ball(&mut server) {
        panic!("Failed to load 9ball: {:?}", e);
    }
    server.run().expect("9Ball Init exited");
    1
}

fn load_9ball(server: &mut InitManager) -> Result<(), Error> {
    server.init()?;
    server.listen(INIT_CAP, REPLY_SLOT)?;
    Ok(())
}
