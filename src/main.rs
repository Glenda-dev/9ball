#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;

mod bootinfo;
mod layout;
mod manager;

use crate::layout::{INITRD_CAP, MONITOR_CAP};
use bootinfo::BootInfo;
use glenda;
use glenda::cap::pagetable::{Perms, perms};
use glenda::cap::{
    CNode, CONSOLE_CAP, CONSOLE_SLOT, CSPACE_CAP, CSPACE_SLOT, CapPtr, CapType, Endpoint, Frame,
    PageTable, TCB, TCB_SLOT, VSPACE_CAP, VSPACE_SLOT, rights,
};
use glenda::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use glenda::initrd::Initrd;
use glenda::ipc::{MsgTag, UTCB};
use glenda::manifest::Manifest;
use glenda::mem::{
    HEAP_PAGES, HEAP_VA, PGSIZE, STACK_PAGES, STACK_SIZE, STACK_VA, TRAPFRAME_VA, UTCB_VA,
};
use glenda::protocol::factotum as protocol;
use layout::{BOOTINFO_VA, INITRD_SLOT, INITRD_VA, SCRATCH_VA, UTCB_SLOT};
use manager::ResourceManager;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("9ball: {}", format_args!($($arg)*));
    })
}

// TODO: Refactor this
#[unsafe(no_mangle)]
fn main() -> usize {
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
    let f_endpoint = start_factotum(&mut rm, &initrd);

    // 3. Start other components via Factotum
    spawn_services(f_endpoint, &manifest);

    // 4. Enter Monitor Loop
    monitor(MONITOR_CAP); // 9ball's own endpoint
    0
}

fn print_bootinfo(bootinfo: &BootInfo) {
    log!("BootInfo Magic: {:#x}", bootinfo.magic);
    log!("BootInfo DTB: Address = {:#x}, Size = {}", bootinfo.dtb_paddr, bootinfo.dtb_size);
    log!(
        "BootInfo MMIOs: Count = {}, [{},{})",
        bootinfo.mmio_count,
        bootinfo.mmio.start,
        bootinfo.mmio.end
    );
    log!(
        "BootInfo Untypes: Count = {}, [{},{})",
        bootinfo.untyped_count,
        bootinfo.untyped.start,
        bootinfo.untyped.end
    );
    log!("BootInfo IRQS: [{},{})", bootinfo.irq.start, bootinfo.irq.end);
}

fn parse_manifest(initrd: &Initrd) -> Manifest {
    // Find Manifest
    let manifest = if let Some(data) = initrd.get_file("manifest") {
        Manifest::parse(data).expect("Failed to parse manifest")
    } else {
        panic!("Manifest not found in initrd")
    };
    log!(
        "Load manifest with {} services and {} drivers",
        manifest.services.len(),
        manifest.drivers.len()
    );
    manifest
}

fn start_factotum(rm: &mut ResourceManager, initrd: &Initrd) -> Endpoint {
    // 1. Find Factotum
    let factotum_data = initrd.get_file("factotum").expect("Factotum not found in initrd");

    log!("Found Factotum. Size: {} KB", factotum_data.len() / 1024);
    // 2. Allocate Factotum Resources
    let f_cnode = CNode::from(rm.alloc_object(CapType::CNode, 4).expect("Failed to alloc CNode"));
    let f_vspace =
        PageTable::from(rm.alloc_object(CapType::PageTable, 1).expect("Failed to alloc VSpace"));
    let f_tcb = TCB::from(rm.alloc_object(CapType::TCB, 1).expect("Failed to alloc TCB"));
    let f_endpoint =
        Endpoint::from(rm.alloc_object(CapType::Endpoint, 1).expect("Failed to alloc Endpoint"));
    let f_utcb_frame =
        Frame::from(rm.alloc_object(CapType::Frame, 1).expect("Failed to alloc UTCB Frame"));
    let f_trapframe =
        Frame::from(rm.alloc_object(CapType::Frame, 1).expect("Failed to alloc TrapFrame"));
    let f_kstack = Frame::from(rm.alloc_object(CapType::Frame, 1).expect("Failed to alloc KStack"));
    let f_stack_frame = Frame::from(
        rm.alloc_object(CapType::Frame, STACK_PAGES).expect("Failed to alloc Stack Frame"),
    );
    let f_heap_frame = Frame::from(
        rm.alloc_object(CapType::Frame, HEAP_PAGES).expect("Failed to alloc Heap Frame"),
    );
    // Allocate an endpoint for 9ball to receive faults/notifications
    let monitor_ep =
        Endpoint::from(rm.alloc_object(CapType::Endpoint, 1).expect("Failed to alloc Monitor EP"));
    // Mint into 9ball's own CSpace (Slot 11)

    let cspace = CSPACE_CAP;

    cspace.mint(monitor_ep.cap(), 11, 0, rights::ALL);

    // 3. Setup Factotum CSpace
    f_cnode.mint(f_cnode.cap(), CSPACE_SLOT, 0, rights::ALL);
    f_cnode.mint(f_vspace.cap(), VSPACE_SLOT, 0, rights::ALL);
    f_cnode.mint(f_tcb.cap(), TCB_SLOT, 0, rights::ALL);
    f_cnode.mint(f_utcb_frame.cap(), UTCB_SLOT, 0, rights::ALL);
    f_cnode.copy(INITRD_CAP.cap(), INITRD_SLOT, rights::READ);
    f_cnode.copy(CONSOLE_CAP.cap(), CONSOLE_SLOT, rights::ALL);
    f_cnode.mint(f_endpoint.cap(), 10, 0, rights::ALL);

    let entry_point = map_elf(rm, f_vspace, factotum_data);

    // 5. Setup Stack, UTCB and TrapFrame
    {
        use glenda::mem::RES_VA_BASE;
        let initrd_size = initrd.data.len();
        let initrd_start = RES_VA_BASE;
        let initrd_end = initrd_start + initrd_size;
        let pt_l1 = PageTable::from(rm.alloc_object(CapType::PageTable, 1).expect("OOM L1"));
        let _ = f_vspace.map_table(pt_l1, initrd_start, 2);
        let mut curr = initrd_start;
        while curr < initrd_end {
            let pt_l0 = PageTable::from(rm.alloc_object(CapType::PageTable, 1).expect("OOM L0"));
            let _ = f_vspace.map_table(pt_l0, curr, 1);
            curr += 0x200000; // 2MB
        }

        if f_vspace.map(INITRD_CAP, initrd_start, Perms::from(perms::READ | perms::USER)) != 0 {
            panic!("Failed to map INITRD");
        }
    }

    map_with_alloc(
        rm,
        f_vspace,
        f_trapframe,
        TRAPFRAME_VA,
        Perms::from(perms::READ | perms::WRITE),
    );
    f_vspace.setup();
    map_with_alloc(
        rm,
        f_vspace,
        f_stack_frame,
        STACK_VA - STACK_SIZE,
        Perms::from(perms::READ | perms::WRITE | perms::USER),
    );
    map_with_alloc(
        rm,
        f_vspace,
        f_heap_frame,
        HEAP_VA,
        Perms::from(perms::READ | perms::WRITE | perms::USER),
    );
    map_with_alloc(
        rm,
        f_vspace,
        f_utcb_frame,
        UTCB_VA,
        Perms::from(perms::READ | perms::WRITE | perms::USER),
    );

    // 6. Transfer Remaining Untyped & IRQ
    let untyped_start_slot = 100;
    let mut dest_slot = untyped_start_slot;
    let mut ptr = rm.untyped_slots.start;
    while ptr < rm.untyped_slots.end {
        let cap = CapPtr::from(ptr);
        ptr += 1;
        f_cnode.mint(cap, dest_slot, 0, rights::ALL);
        dest_slot += 1;
    }
    log!("Transferred {} untyped caps to Factotum", dest_slot - 100);

    // 7. Configure & Start TCB
    f_tcb.configure(f_cnode, f_vspace, f_utcb_frame, f_trapframe, f_kstack);
    f_tcb.set_priority(254);
    f_tcb.set_registers(rights::ALL as usize, entry_point, STACK_VA);
    f_tcb.resume();
    log!("Factotum started!");

    // 8. Initialize Factotum Resources
    let untyped_count = dest_slot - 100;
    let msg_tag = MsgTag::new(protocol::FACTOTUM_PROTO, 3);
    let args = [protocol::INIT_RESOURCES, untyped_start_slot, untyped_count, 0, 0, 0, 0];
    f_endpoint.call(msg_tag, args);
    f_endpoint
}

/// 解析 ELF 并将其段映射到目标地址空间
fn map_elf(rm: &mut ResourceManager, vspace: PageTable, elf_data: &[u8]) -> usize {
    let elf = ElfFile::new(elf_data).expect("Invalid ELF");

    for phdr in elf.program_headers() {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        log!(
            "Mapping ELF Segment: vaddr={:#x}, memsz={}, filesz={}, offset={:#x}",
            phdr.p_vaddr,
            phdr.p_memsz,
            phdr.p_filesz,
            phdr.p_offset
        );
        let vaddr = phdr.p_vaddr as usize;
        let mem_size = phdr.p_memsz as usize;
        let file_size = phdr.p_filesz as usize;
        let offset = phdr.p_offset as usize;

        let mut pms = perms::USER | perms::READ;
        if phdr.p_flags & PF_W != 0 {
            pms |= perms::WRITE;
        }
        if phdr.p_flags & PF_X != 0 {
            pms |= perms::EXECUTE;
        }

        let perms = Perms::from(pms);

        let start_page = vaddr & !(PGSIZE - 1);
        let end_page = (vaddr + mem_size + PGSIZE - 1) & !(PGSIZE - 1);

        for page_vaddr in (start_page..end_page).step_by(PGSIZE) {
            let frame = Frame::from(rm.alloc_object(CapType::Frame, 1).expect("OOM ELF Frame"));

            // 将页帧临时映射到 9ball 的 SCRATCH_VA 以便拷贝数据
            // 虽然使用了 SCRATCH_VA，但它仅作为 9ball 写入新页帧的窗口
            map_with_alloc(
                rm,
                VSPACE_CAP,
                frame,
                SCRATCH_VA,
                Perms::from(perms::READ | perms::WRITE | perms::USER),
            );
            // my_vspace.pagetable_debug_print();

            let dest_slice =
                unsafe { core::slice::from_raw_parts_mut(SCRATCH_VA as *mut u8, PGSIZE) };
            dest_slice.fill(0);

            // 直接从 elf_data (initrd 中的偏移) 拷贝到目标页帧
            let offset_in_segment = page_vaddr.saturating_sub(vaddr);
            if offset_in_segment < file_size {
                let copy_start = if page_vaddr < vaddr { vaddr - page_vaddr } else { 0 };
                let copy_len = core::cmp::min(PGSIZE - copy_start, file_size - offset_in_segment);
                let src_offset = offset + offset_in_segment + copy_start;

                dest_slice[copy_start..copy_start + copy_len]
                    .copy_from_slice(&elf_data[src_offset..src_offset + copy_len]);
            }

            // 解除 9ball 的临时映射并映射到目标进程
            VSPACE_CAP.unmap(SCRATCH_VA, 1);
            //my_vspace.pagetable_debug_print();
            map_with_alloc(rm, vspace, frame, page_vaddr, perms);
        }
    }
    elf.entry_point()
}
fn map_with_alloc(
    rm: &mut ResourceManager,
    vspace: PageTable,
    frame: Frame,
    va: usize,
    perms: Perms,
) {
    // 1. 尝试直接映射
    if vspace.map(frame, va, perms) == 0 {
        return;
    }

    // 2. 映射失败，说明可能缺少中间页表。
    // Sv39 布局：L2 (Root) -> L1 -> L0 -> Frame

    // 尝试分配一个页表对象，用于填充缺失的层级
    // 注意：我们将重用这个对象，避免在 L1 存在时造成泄漏
    let mut pt_cap = rm.alloc_object(CapType::PageTable, 1).expect("OOM PT Alloc (Initial)");
    let mut pt = PageTable::from(pt_cap);

    // ----------------------------------------------------------------
    // 步骤 A: 检查并映射 L1 Table (由 Root 表的 VPN[2] 指向)
    // ----------------------------------------------------------------
    // 尝试将新分配的页表作为 L1 表映射 (level=2)
    if vspace.map_table(pt, va, 2) == 0 {
        // [成功]：pt 已被安装为 L1 表
        // L1 Table 安装成功后，再次尝试直接映射 Frame
        if vspace.map(frame, va, perms) == 0 {
            return;
        }
        // Frame 映射仍失败，说明还需要 L0 表。
        // 因为 pt 已经被用作 L1，我们需要为 L0 分配一个新的页表对象
        pt_cap = rm.alloc_object(CapType::PageTable, 1).expect("OOM PT Alloc (L0)");
        pt = PageTable::from(pt_cap);
    } else {
        // [失败]：说明 L1 表已存在 (map_table 返回非零)
        // 关键修复：之前分配的 pt 没有被使用，我们留给下一步作为 L0 表尝试！
        // 避免了原代码中无意义的资源泄漏。
    }

    // ----------------------------------------------------------------
    // 步骤 B: 检查并映射 L0 Table (由 L1 表的 VPN[1] 指向)
    // ----------------------------------------------------------------
    // 尝试将 pt (无论是新分配的还是上面回收的) 作为 L0 表映射 (level=1)
    if vspace.map_table(pt, va, 1) == 0 {
        // L0 Table 安装成功，再次尝试映射 Frame
        if vspace.map(frame, va, perms) == 0 {
            return;
        }
    }

    // 3. 如果还失败，说明真的无法映射
    panic!("Failed to map frame at {:#x}", va);
}

fn spawn_services(f_endpoint: Endpoint, manifest: &Manifest) {
    for (i, entry) in manifest.services.iter().enumerate() {
        log!("Spawning component from manifest: {} (binary: {})", entry.name, entry.binary);

        let utcb = UTCB::current();
        utcb.clear();

        let tag = MsgTag::new(protocol::FACTOTUM_PROTO, 1);
        let args = [protocol::SPAWN_SERVICE_MANIFEST, i, 0, 0, 0, 0, 0];
        f_endpoint.call(tag, args);

        let pid = UTCB::current().mrs_regs[0];
        if pid == usize::MAX {
            log!("Failed to spawn {}", entry.name);
            continue;
        }
        log!("  PID: {}", pid);
    }
}

fn monitor(monitor_ep: Endpoint) -> ! {
    log!("Entering monitor loop...");
    loop {
        let badge = monitor_ep.recv(0);
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
