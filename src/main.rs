#![no_std]
#![no_main]

extern crate alloc;

use libglenda::bootinfo::{BootInfo, BOOTINFO_VA, INITRD_VA, CONSOLE_CAP};
use libglenda::initrd::Initrd;
use libglenda::println;
use libglenda::cap::CapPtr;

#[unsafe(no_mangle)]
fn main() -> ! {
    // Initialize logging
    libglenda::log::init(CapPtr(CONSOLE_CAP));

    println!("Hello from 9ball (Root Task)!");

    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    println!("BootInfo Magic: {:#x}", bootinfo.magic);
    println!("Initrd PAddr: {:#x}, Size: {}", bootinfo.initrd_paddr, bootinfo.initrd_size);

    if bootinfo.initrd_size > 0 {
        let initrd_slice = unsafe {
            core::slice::from_raw_parts(INITRD_VA as *const u8, bootinfo.initrd_size)
        };

        match Initrd::new(initrd_slice) {
            Ok(initrd) => {
                println!("Initrd parsed successfully. Entries: {}", initrd.entries.len());
                for entry in &initrd.entries {
                    println!(" - {}: size={}, offset={}", entry.name, entry.size, entry.offset);
                }
            }
            Err(e) => println!("Failed to parse initrd: {}", e),
        }
    } else {
        println!("No initrd found.");
    }

    loop {}
}
