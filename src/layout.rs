use glenda::cap::{CapPtr, Console, Endpoint, Frame};
use glenda::mem::{PGSIZE, RES_VA_BASE};

/// Virtual Address where Initrd is mapped in Root Task
pub const INITRD_VA: usize = RES_VA_BASE + PGSIZE;

/// Virtual Address where BootInfo is mapped in Root Task
pub const BOOTINFO_VA: usize = RES_VA_BASE;

pub const SCRATCH_VA: usize = 0x5000_0000; // 临时映射页，用于 ELF 加载

pub const UTCB_SLOT: usize = 7;

/// Capability Slot for Initrd Frame
pub const INITRD_SLOT: usize = 8;

/// DTB Slot
pub const DTB_SLOT: usize = 9;

pub const MONITOR_SLOT: usize = 10;

pub const INITRD_CAP: Frame = Frame::from(CapPtr::from(INITRD_SLOT));
pub const DTB_CAP: Frame = Frame::from(CapPtr::from(DTB_SLOT));
pub const UTCB_CAP: Frame = Frame::from(CapPtr::from(UTCB_SLOT));
pub const MONITOR_CAP: Endpoint = Endpoint::from(CapPtr::from(MONITOR_SLOT));
