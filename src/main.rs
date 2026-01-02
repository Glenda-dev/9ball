#![no_std]
#![no_main]

extern crate alloc;

use glenda::bootinfo::{BOOTINFO_VA, BootInfo, CONSOLE_CAP, INITRD_CAP, INITRD_VA};
use glenda::cap::CapPtr;
use glenda::initrd::Initrd;
use glenda::log;
use glenda::println;

#[unsafe(no_mangle)]
fn main() -> ! {
    // Initialize logging
    log::init(CapPtr(CONSOLE_CAP));

    println!("Hello from 9ball (Root Task)!");

    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    println!("BootInfo Magic: {:#x}", bootinfo.magic);

    // Map Initrd Frame
    // VSpace Cap is at slot 1 (VSPACE_SLOT)
    let vspace = CapPtr(1);
    let initrd_frame = CapPtr(INITRD_CAP);

    // Rights: READ (1) | WRITE (2) = 3
    let ret = vspace.pagetable_map(initrd_frame, INITRD_VA, 3);
    if ret != 0 {
        println!("Failed to map initrd: error code {}", ret);
    } else {
        println!("Initrd mapped at {:#x}", INITRD_VA);

        // Read total size from header (offset 8)
        let total_size_ptr = (INITRD_VA + 8) as *const u32;
        let total_size = unsafe { *total_size_ptr } as usize;
        println!("Initrd Total Size: {}", total_size);

        if total_size > 0 {
            let initrd_slice =
                unsafe { core::slice::from_raw_parts(INITRD_VA as *const u8, total_size) };

            match Initrd::new(initrd_slice) {
                Ok(initrd) => {
                    println!("Initrd parsed successfully. Entries: {}", initrd.entries.len());
                    for entry in &initrd.entries {
                        println!(" - {}: size={}, offset={}", entry.name, entry.size, entry.offset);
                    }
                }
                Err(e) => println!("Failed to parse initrd: {}", e),
            }
        }
    }

    loop {}
}
