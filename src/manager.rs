use glenda::bootinfo::{BootInfo, SlotRegion};
use glenda::cap::{CapPtr, CapType};

pub struct ResourceManager {
    pub cnode: CapPtr, // Root Task CNode
    pub empty_slots: SlotRegion,
    pub untyped_slots: SlotRegion,
}

impl ResourceManager {
    pub fn new(bootinfo: &BootInfo) -> Self {
        Self {
            cnode: CapPtr(0), // Root Task CNode is always 0 (implied)
            empty_slots: bootinfo.empty,
            untyped_slots: bootinfo.untyped,
        }
    }

    pub fn alloc_slot(&mut self) -> Option<CapPtr> {
        if self.empty_slots.start.0 < self.empty_slots.end.0 {
            let slot = self.empty_slots.start;
            self.empty_slots.start.0 += 1;
            Some(slot)
        } else {
            None
        }
    }

    // Simple allocator: just takes the next untyped and retypes it completely
    // In a real system, we would split untyped memory.
    // Here we assume we have enough small untyped objects or we waste them.
    pub fn alloc_object(&mut self, obj_type: CapType, size_bits: usize) -> Option<CapPtr> {
        // Find an untyped cap
        if self.untyped_slots.start.0 >= self.untyped_slots.end.0 {
            return None;
        }

        // For simplicity in this demo, we just use one untyped cap per allocation
        // and don't manage the remaining space in it.
        // This is VERY wasteful but sufficient for a demo.
        let untyped_cap = self.untyped_slots.start;
        self.untyped_slots.start.0 += 1;

        let dest_slot = self.alloc_slot()?;
        let dest_cap = dest_slot;

        // Retype
        // Note: untyped_retype(obj_type, size_bits, n_objs, dest_cnode, dest_offset)
        // dest_cnode is our cspace (0), dest_offset is the slot index.
        let ret = untyped_cap.untyped_retype(obj_type, size_bits, 1, self.cnode, dest_slot.0);

        if ret == 0 { Some(dest_cap) } else { None }
    }
}
