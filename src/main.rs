#![no_std]
#![no_main]

extern crate alloc;

use glenda::cap::pagetable::perms;
use glenda::cap::{CapPtr, CapType, rights};
use glenda::console;
use glenda::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use glenda::initrd::Initrd;
use glenda::ipc::{MsgTag, UTCB};
use glenda::manifest::Manifest;
use glenda::mem::{STACK_SIZE, STACK_VA, TRAPFRAME_VA, UTCB_VA};
use glenda::protocol::factotum as protocol;

mod bootinfo;
mod layout;
mod manager;

use bootinfo::BootInfo;
use layout::{BOOTINFO_VA, CONSOLE_SLOT, INITRD_SLOT, INITRD_VA};
use manager::ResourceManager;

use crate::layout::MONITOR_SLOT;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("9ball: {}", format_args!($($arg)*));
    })
}

// TODO: Refactor this
#[unsafe(no_mangle)]
fn main() -> ! {
    // Initialize logging
    console::init(CapPtr(CONSOLE_SLOT));

    log!("Hello from 9ball (Root Task)!");

    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    print_bootinfo(&bootinfo);

    let total_size_ptr = (INITRD_VA + 8) as *const u32;
    let total_size = unsafe { *total_size_ptr } as usize;

    let initrd_slice = unsafe { core::slice::from_raw_parts(INITRD_VA as *const u8, total_size) };
    let initrd = Initrd::new(initrd_slice).expect("Failed to parse initrd");

    // 1. Init Manager
    let mut rm = ResourceManager::new(bootinfo);

    let manifest = parse_manifest(&initrd);

    // 2. Start Factotum
    let f_endpoint = start_factotum(&mut rm, &initrd, &manifest);

    // 3. Start other components via Factotum
    spawn_services(f_endpoint, &manifest);

    // 4. Enter Monitor Loop
    monitor(CapPtr(MONITOR_SLOT)); // 9ball's own endpoint
}

fn print_bootinfo(bootinfo: &BootInfo) {
    log!("BootInfo Magic: {:#x}", bootinfo.magic);
    log!("BootInfo DTB: Address = {:#x}, Size = {}", bootinfo.dtb_paddr, bootinfo.dtb_size);
    log!("BootInfo MMIO: {:?} - {:?}", bootinfo.mmio.start, bootinfo.mmio.end);
    log!("BootInfo Untypes: {:?} - {:?}", bootinfo.untyped.start, bootinfo.untyped.end);
    log!("BootInfo IRQS: {:?} - {:?}", bootinfo.irq.start, bootinfo.irq.end);
}

fn parse_manifest(initrd: &Initrd) -> Manifest {
    // Find Manifest
    let manifest = if let Some(data) = initrd.get_file("manifest") {
        Manifest::parse(data)
    } else {
        panic!("Manifest not found in initrd")
    };
    log!(
        "Load manifest with {} services and {} drivers",
        manifest.service.len(),
        manifest.driver.len()
    );
    manifest
}

fn start_factotum(rm: &mut ResourceManager, initrd: &Initrd, manifest: &Manifest) -> CapPtr {
    // 1. Find Factotum
    let factotum_data = initrd.get_file("factotum").expect("Factotum not found in initrd");

    log!("Found Factotum. Size: {} KB", factotum_data.len() / 1024);

    let manifest_entry = initrd.entries.iter().find(|e| e.name == "manifest");

    // 2. Allocate Factotum Resources
    let f_cnode = rm.alloc_object(CapType::CNode, 12).expect("Failed to alloc CNode");
    let f_vspace = rm.alloc_object(CapType::PageTable, 0).expect("Failed to alloc VSpace");
    let f_tcb = rm.alloc_object(CapType::TCB, 0).expect("Failed to alloc TCB");
    let f_endpoint = rm.alloc_object(CapType::Endpoint, 0).expect("Failed to alloc Endpoint");
    let f_utcb_frame = rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc UTCB Frame");
    let f_trapframe = rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc TrapFrame");
    let f_kstack = rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc KStack");
    let f_stack_frame = rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc Stack Frame");

    // Allocate an endpoint for 9ball to receive faults/notifications
    let monitor_ep = rm.alloc_object(CapType::Endpoint, 0).expect("Failed to alloc Monitor EP");
    // Mint into 9ball's own CSpace (Slot 11)
    CapPtr(0).cnode_mint(monitor_ep, 11, 0, rights::ALL);

    // 3. Setup Factotum CSpace
    f_cnode.cnode_mint(f_cnode, 0, 0, rights::ALL);
    f_cnode.cnode_mint(f_vspace, 1, 0, rights::ALL);
    f_cnode.cnode_mint(f_tcb, 2, 0, rights::ALL);
    f_cnode.cnode_mint(f_utcb_frame, 3, 0, rights::ALL);
    f_cnode.cnode_copy(CapPtr(INITRD_SLOT), 4, rights::READ);
    f_cnode.cnode_copy(CapPtr(CONSOLE_SLOT), 8, rights::ALL);
    f_cnode.cnode_mint(f_endpoint, 10, 0, rights::ALL);

    // 4. Set 9ball as Factotum's fault handler
    f_tcb.tcb_set_fault_handler(monitor_ep);

    // 4. Load ELF Binary
    let elf = ElfFile::new(factotum_data).expect("Factotum is not a valid ELF");
    let entry_point = elf.entry_point();

    for phdr in elf.program_headers() {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let file_size = phdr.p_filesz as usize;
        let mem_size = phdr.p_memsz as usize;
        let vaddr = phdr.p_vaddr as usize;
        let offset = phdr.p_offset as usize;

        let pages = (mem_size + 4095) / 4096;
        for i in 0..pages {
            unimplemented!()
        }
    }

    // 5. Setup Stack, UTCB and TrapFrame
    map_with_alloc(
        f_vspace,
        f_stack_frame,
        STACK_VA - STACK_SIZE,
        perms::READ | perms::WRITE | perms::USER,
    );
    map_with_alloc(f_vspace, f_utcb_frame, UTCB_VA, perms::READ | perms::WRITE | perms::USER);
    map_with_alloc(f_vspace, f_trapframe, TRAPFRAME_VA, perms::READ | perms::WRITE);
    f_vspace.pagetable_map_trampoline();

    // 6. Transfer Remaining Untyped & IRQ
    let mut dest_slot = 100;
    while rm.untyped_slots.start.0 < rm.untyped_slots.end.0 {
        let cap = rm.untyped_slots.start;
        rm.untyped_slots.start.0 += 1;
        f_cnode.cnode_mint(cap, dest_slot, 0, rights::ALL);
        dest_slot += 1;
    }
    log!("Transferred {} untyped caps to Factotum", dest_slot - 100);

    let irq_start_slot = dest_slot;
    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    let irq_count = bootinfo.irq.end.0 - bootinfo.irq.start.0;
    for i in 0..irq_count {
        let cap = CapPtr(bootinfo.irq.start.0 + i);
        f_cnode.cnode_mint(cap, dest_slot, 0, rights::ALL);
        dest_slot += 1;
    }
    log!("Transferred {} IRQ caps to Factotum", irq_count);

    // 7. Configure & Start TCB
    f_tcb.tcb_configure(f_cnode, f_vspace, f_utcb_frame, f_trapframe, f_kstack);
    f_tcb.tcb_set_priority(255);
    f_tcb.tcb_set_registers(rights::ALL as usize, entry_point, STACK_VA);
    f_tcb.tcb_resume();
    log!("Factotum started!");

    // 8. Initialize Factotum Resources
    let untyped_count = dest_slot - 100;
    let msg_tag = MsgTag::new(protocol::FACTOTUM_PROTO, 3);
    let args = [protocol::INIT_RESOURCES, 100, untyped_count, 0, 0, 0, 0];
    f_endpoint.ipc_call(msg_tag, args);

    let msg_tag = MsgTag::new(protocol::FACTOTUM_PROTO, 3);
    let args = [protocol::INIT_IRQ, irq_start_slot, irq_count, 0, 0, 0, 0];
    f_endpoint.ipc_call(msg_tag, args);

    f_endpoint
}

fn map_with_alloc(vspace: CapPtr, frame: CapPtr, va: usize, perms: usize) {
    unimplemented!()
}

fn spawn_services(f_endpoint: CapPtr, manifest: &Manifest) {
    for (i, entry) in manifest.service.iter().enumerate() {
        log!("Spawning component from manifest: {} (binary: {})", entry.name, entry.binary);

        let utcb = UTCB::current();
        utcb.clear();

        let tag = MsgTag::new(protocol::FACTOTUM_PROTO, 1);
        let args = [protocol::SPAWN_SERVICE_MANIFEST, i, 0, 0, 0, 0, 0];
        f_endpoint.ipc_call(tag, args);

        let pid = UTCB::current().mrs_regs[0];
        if pid == usize::MAX {
            log!("Failed to spawn {}", entry.name);
            continue;
        }
        log!("  PID: {}", pid);
    }
}

fn monitor(monitor_ep: CapPtr) -> ! {
    log!("Entering monitor loop...");
    loop {
        let badge = monitor_ep.ipc_recv();
        let utcb = UTCB::current();
        let tag = utcb.msg_tag;
        let label = tag.label();

        log!("Received message! Badge: {}, Label: {:#x}, Length: {}", badge, label, tag.length());

        // Handle faults (0xFFFF = Page Fault, 0xFFFE = Exception)
        if label == 0xFFFF || label == 0xFFFE {
            let scause = utcb.mrs_regs[0];
            let stval = utcb.mrs_regs[1];
            let sepc = utcb.mrs_regs[2];
            log!(
                "FAULT from badge {}: scause={:#x}, stval={:#x}, sepc={:#x}",
                badge,
                scause,
                stval,
                sepc
            );
            // For now, just loop or kill. In a real OS, we might restart the service.
        }
    }
}
