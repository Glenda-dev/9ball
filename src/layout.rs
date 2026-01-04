use glenda::mem::{PGSIZE, RES_VA_BASE};

/// Virtual Address where Initrd is mapped in Root Task
pub const INITRD_VA: usize = RES_VA_BASE + PGSIZE;

/// Virtual Address where BootInfo is mapped in Root Task
pub const BOOTINFO_VA: usize = RES_VA_BASE;

/// Capability Slot for Console
pub const CONSOLE_SLOT: usize = 6;

/// Capability Slot for Initrd Frame
pub const INITRD_SLOT: usize = 7;

/// DTB Slot
pub const DTB_SLOT: usize = 8;

pub const MONITOR_SLOT: usize = 9;
