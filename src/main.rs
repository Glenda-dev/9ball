#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("9ball: {}", format_args!($($arg)*));
    })
}

#[unsafe(no_mangle)]
fn main() -> usize {
    log!("Hello from 9ball!");
    0
}
