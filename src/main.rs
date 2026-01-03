#![no_std]
#![no_main]

extern crate alloc;

use glenda::bootinfo::{BOOTINFO_VA, BootInfo, CONSOLE_CAP, INITRD_CAP, INITRD_VA};
use glenda::cap::pagetable::perms;
use glenda::cap::{CapPtr, CapType, rights};
use glenda::console;
use glenda::initrd::Initrd;
use glenda::ipc::{MsgTag, UTCB};
use glenda::println;
use glenda::protocol::factotum as protocol;

mod manager;
use manager::ResourceManager;

const SCRATCH_VA: usize = 0x5000_0000;
const FACTOTUM_STACK_TOP: usize = 0x8000_0000;
const FACTOTUM_UTCB_ADDR: usize = 0x7FFF_F000;
const FACTOTUM_LOAD_ADDR: usize = 0x10000;

// TODO: Refactor this
#[unsafe(no_mangle)]
fn main() -> ! {
    // Initialize logging
    console::init(CapPtr(CONSOLE_CAP));

    println!("Hello from 9ball (Root Task)!");

    let bootinfo = unsafe { &*(BOOTINFO_VA as *const BootInfo) };
    println!("BootInfo Magic: {:#x}", bootinfo.magic);

    // Map Initrd Frame
    let vspace = CapPtr(1);
    let initrd_frame = CapPtr(INITRD_CAP);

    let ret = vspace.pagetable_map(initrd_frame, INITRD_VA, perms::READ);
    if ret != 0 {
        println!("Failed to map initrd: error code {}", ret);
        loop {}
    }
    println!("Initrd mapped at {:#x}", INITRD_VA);

    let total_size_ptr = (INITRD_VA + 8) as *const u32;
    let total_size = unsafe { *total_size_ptr } as usize;

    let initrd_slice = unsafe { core::slice::from_raw_parts(INITRD_VA as *const u8, total_size) };
    let initrd = Initrd::new(initrd_slice).expect("Failed to parse initrd");

    // 1. Find Factotum
    let factotum_entry =
        initrd.entries.iter().find(|e| e.name == "factotum").expect("Factotum not found in initrd");
    let factotum_data =
        &initrd_slice[factotum_entry.offset..factotum_entry.offset + factotum_entry.size];

    println!("Found Factotum. Size: {}", factotum_data.len());

    // Find Manifest
    let manifest_entry = initrd.entries.iter().find(|e| e.name == "manifest");
    let manifest_data = if let Some(entry) = manifest_entry {
        Some(&initrd_slice[entry.offset..entry.offset + entry.size])
    } else {
        None
    };

    // 2. Init Manager
    let mut rm = ResourceManager::new(bootinfo);

    // 3. Allocate Factotum Resources
    let f_cnode = rm.alloc_object(CapType::CNode, 12).expect("Failed to alloc CNode");
    let f_vspace = rm.alloc_object(CapType::PageTable, 0).expect("Failed to alloc VSpace");
    let f_tcb = rm.alloc_object(CapType::TCB, 0).expect("Failed to alloc TCB");
    let f_endpoint = rm.alloc_object(CapType::Endpoint, 0).expect("Failed to alloc Endpoint");
    let f_utcb_frame = rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc UTCB Frame");
    let f_stack_frame = rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc Stack Frame");

    // Allocate Manifest Frame if needed
    let manifest_frame = if manifest_data.is_some() {
        Some(rm.alloc_object(CapType::Frame, 0).expect("Failed to alloc Manifest Frame"))
    } else {
        None
    };

    // 4. Setup Factotum CSpace
    // Slot 0: CSpace
    f_cnode.cnode_mint(f_cnode, 0, 0, rights::ALL);
    // Slot 1: VSpace
    f_cnode.cnode_mint(f_vspace, 1, 0, rights::ALL);
    // Slot 2: TCB
    f_cnode.cnode_mint(f_tcb, 2, 0, rights::ALL);
    // Slot 3: UTCB (Usually not in CSpace, but TCB points to it. Wait, TCB configure needs UTCB address, not cap slot? No, TCB configure needs UTCB Frame Cap?)
    // libglenda-rs: tcb_configure(cspace, vspace, utcb_addr, fault_ep, utcb_frame_cap)

    // Slot 4: Initrd Frame (Copy from Root)
    f_cnode.cnode_copy(CapPtr(INITRD_CAP), 4, rights::READ);

    // Slot 8: Console
    f_cnode.cnode_copy(CapPtr(CONSOLE_CAP), 8, rights::ALL);

    // Slot 10: Endpoint (For listening)
    f_cnode.cnode_mint(f_endpoint, 10, 0, rights::ALL);

    // Copy Manifest Data
    if let (Some(frame), Some(data)) = (manifest_frame, manifest_data) {
        vspace.pagetable_map(frame, SCRATCH_VA, perms::READ | perms::WRITE);
        let scratch_ptr = SCRATCH_VA as *mut u8;
        unsafe {
            scratch_ptr.write_bytes(0, 4096);
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                scratch_ptr,
                core::cmp::min(4096, data.len()),
            );
        }
        vspace.pagetable_unmap(SCRATCH_VA);

        // Put in Factotum CSpace at slot 200
        f_cnode.cnode_mint(frame, 200, 0, rights::READ);
    }

    // 5. Load Flat Binary
    let load_addr = FACTOTUM_LOAD_ADDR;
    let file_size = factotum_data.len();
    let pages = (file_size + 4095) / 4096;

    for i in 0..pages {
        let page_vaddr = load_addr + i * 4096;
        let frame = rm.alloc_object(CapType::Frame, 0).expect("OOM loading binary");

        // Map to Scratch to copy data
        vspace.pagetable_map(frame, SCRATCH_VA, perms::READ | perms::WRITE);

        // Zero the page
        let scratch_ptr = SCRATCH_VA as *mut u8;
        unsafe { scratch_ptr.write_bytes(0, 4096) };

        // Copy data
        let offset = i * 4096;
        let copy_len = core::cmp::min(4096, file_size - offset);
        let src_ptr = &factotum_data[offset];

        unsafe { core::ptr::copy_nonoverlapping(src_ptr as *const u8, scratch_ptr, copy_len) };

        // Unmap from Scratch
        vspace.pagetable_unmap(SCRATCH_VA);

        // Map to Factotum VSpace (RWX for simplicity, as it is flat binary code+data)
        f_vspace.pagetable_map(frame, page_vaddr, perms::READ | perms::WRITE | perms::EXECUTE);
    }

    // 6. Setup Stack
    // Map stack frame to Factotum VSpace
    f_vspace.pagetable_map(f_stack_frame, FACTOTUM_STACK_TOP - 4096, perms::READ | perms::WRITE);

    // 7. Setup UTCB
    // Map UTCB frame to Factotum VSpace
    f_vspace.pagetable_map(f_utcb_frame, FACTOTUM_UTCB_ADDR, perms::READ | perms::WRITE);

    // 8. Transfer Remaining Untyped
    let mut dest_slot = 100;
    while rm.untyped_slots.start.0 < rm.untyped_slots.end.0 {
        let cap = rm.untyped_slots.start;
        rm.untyped_slots.start.0 += 1;

        // Move to Factotum CSpace
        // We use Mint with badge 0? Or Copy? Move?
        // libglenda-rs doesn't have 'move' yet? It has 'mint', 'copy'.
        // We can use 'mint' to give full rights.
        f_cnode.cnode_mint(cap, dest_slot, 0, rights::ALL);
        dest_slot += 1;
    }
    println!("Transferred {} untyped caps to Factotum", dest_slot - 100);

    // Transfer IRQ Caps
    let irq_start_slot = dest_slot;
    let irq_count = bootinfo.irq.end.0 - bootinfo.irq.start.0;
    for i in 0..irq_count {
        let cap = CapPtr(bootinfo.irq.start.0 + i);
        f_cnode.cnode_mint(cap, dest_slot, 0, rights::ALL);
        dest_slot += 1;
    }
    println!("Transferred {} IRQ caps to Factotum", irq_count);

    // 9. Configure & Start TCB
    // tcb_configure(cspace, vspace, utcb_addr, fault_ep, utcb_frame)
    // Fault EP: We can use the same endpoint (slot 10) so Factotum receives its own faults?
    // Or 0 if no handler. Let's use 0 for now.
    f_tcb.tcb_configure(CapPtr(0), CapPtr(1), FACTOTUM_UTCB_ADDR, CapPtr(0), f_utcb_frame);
    f_tcb.tcb_set_priority(255); // High priority

    // Set registers: Entry point, Stack Pointer
    f_tcb.tcb_set_registers(rights::ALL as usize, FACTOTUM_LOAD_ADDR, FACTOTUM_STACK_TOP);

    // Resume
    f_tcb.tcb_resume();
    println!("Factotum started!");

    // 10. Start other components via Factotum

    // First, tell Factotum about the resources we transferred
    // We transferred (dest_slot - 100) caps starting at 100.
    let untyped_count = dest_slot - 100;
    let msg_tag = MsgTag::new(protocol::INIT_RESOURCES, 2);
    let args = [100, untyped_count, 0, 0, 0, 0];
    f_endpoint.ipc_call(msg_tag, &args);
    println!("Sent INIT_RESOURCES to Factotum");

    // Send INIT_IRQ
    let msg_tag = MsgTag::new(protocol::INIT_IRQ, 2);
    let args = [irq_start_slot, irq_count, 0, 0, 0, 0];
    f_endpoint.ipc_call(msg_tag, &args);
    println!("Sent INIT_IRQ to Factotum");

    // Iterate over other initrd entries
    for entry in initrd.entries.iter() {
        if entry.name == "factotum" || entry.name == "manifest" {
            continue;
        }

        println!("Spawning component: {}", entry.name);

        let _ = &initrd_slice[entry.offset..entry.offset + entry.size];

        // SPAWN
        let ipc_buf = glenda::ipc::utcb::get_ipc_buffer();
        ipc_buf.clear();
        ipc_buf.append_str(&entry.name);

        let msg_tag = MsgTag::new(protocol::SPAWN, 2);
        let args = [entry.name.len(), 0, 0, 0, 0, 0];
        f_endpoint.ipc_call(msg_tag, &args);
        let pid = UTCB::current().mrs_regs[0];

        if pid == usize::MAX {
            println!("Failed to spawn {}", entry.name);
            continue;
        }
        println!("  PID: {}", pid);

        // PROCESS_LOAD_IMAGE
        // We use the Initrd Cap which we know is at Slot 4 in Factotum's CSpace.
        // We pass '4' as the frame_cap argument.
        // args: [pid, frame_cap, offset, len, load_addr]
        let msg_tag = MsgTag::new(protocol::PROCESS_LOAD_IMAGE, 5);
        let args = [pid, 4, entry.offset, entry.size, 0x10000, 0];

        f_endpoint.ipc_call(msg_tag, &args);
        let ret = UTCB::current().mrs_regs[0];
        if ret != 0 {
            println!("Failed to load image for {}", entry.name);
            continue;
        }

        // If Unicorn, load manifest
        if entry.name == "unicorn" && manifest_entry.is_some() {
            let m_entry = manifest_entry.unwrap();
            println!("  Loading manifest for Unicorn...");
            let msg_tag = MsgTag::new(protocol::PROCESS_LOAD_IMAGE, 5);
            // frame_cap = 200 (Manifest Frame in Factotum CSpace)
            // Load at 0x2000_0000
            let args = [pid, 200, 0, m_entry.size, 0x2000_0000, 0];
            f_endpoint.ipc_call(msg_tag, &args);
        }

        // PROCESS_START
        // Entry point 0x10000, Stack 0x80000000
        let msg_tag = MsgTag::new(protocol::PROCESS_START, 3);
        let args = [pid, 0x10000, 0x8000_0000, 0, 0, 0];
        f_endpoint.ipc_call(msg_tag, &args);
        println!("  Started {}", entry.name);
    }

    loop {}
}
