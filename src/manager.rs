use crate::bootinfo::{BootInfo, SlotRegion};
use glenda::cap::{CNode, CSPACE_CAP, CapPtr, CapType, Untyped};

pub struct ResourceManager {
    pub cnode: CNode,
    pub empty_slots: SlotRegion,
    pub untyped_slots: SlotRegion,
    pub current_untyped_idx: usize,
}

impl ResourceManager {
    pub fn new(bootinfo: &BootInfo) -> Self {
        Self {
            cnode: CSPACE_CAP,
            empty_slots: bootinfo.empty,
            untyped_slots: bootinfo.untyped,
            current_untyped_idx: 0,
        }
    }

    pub fn alloc_object(&mut self, obj_type: CapType, size_param: usize) -> Option<CapPtr> {
        while self.current_untyped_idx < (self.untyped_slots.end - self.untyped_slots.start) {
            let untyped_cap = CapPtr::from(self.untyped_slots.start + self.current_untyped_idx);

            let dest_cap = if self.empty_slots.start < self.empty_slots.end {
                let s = self.empty_slots.start;
                self.empty_slots.start += 1;
                s
            } else {
                return None;
            };

            let ret = Untyped::from(untyped_cap).retype(
                obj_type,
                size_param,
                1,
                self.cnode,
                CapPtr::from(dest_cap),
                false,
            );

            if ret == 0 {
                return Some(CapPtr::from(dest_cap));
            } else {
                self.empty_slots.start -= 1;
                self.current_untyped_idx += 1;
            }
        }
        None
    }
}
