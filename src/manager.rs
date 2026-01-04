use crate::bootinfo::{BootInfo, SlotRegion, UntypedDesc, MAX_UNTYPED_REGIONS};
use glenda::cap::{CSPACE_SLOT, CapPtr, CapType};

pub struct ResourceManager {
    pub cnode: CapPtr,
    pub empty_slots: SlotRegion,
    pub untyped_slots: SlotRegion,
    pub current_untyped_idx: usize,
    pub mmio_slots: SlotRegion,
    pub mmio_list: [UntypedDesc; MAX_UNTYPED_REGIONS],
    pub mmio_cursors: [usize; MAX_UNTYPED_REGIONS],
}

impl ResourceManager {
    pub fn new(bootinfo: &BootInfo) -> Self {
        Self {
            cnode: CapPtr(CSPACE_SLOT),
            empty_slots: bootinfo.empty,
            untyped_slots: bootinfo.untyped,
            current_untyped_idx: 0,
            mmio_slots: bootinfo.mmio,
            mmio_list: bootinfo.mmio_list,
            mmio_cursors: [0; MAX_UNTYPED_REGIONS],
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

    pub fn alloc_object(&mut self, obj_type: CapType, size_param: usize) -> Option<CapPtr> {
        while self.current_untyped_idx < (self.untyped_slots.end.0 - self.untyped_slots.start.0) {
            let untyped_cap = CapPtr(self.untyped_slots.start.0 + self.current_untyped_idx);
            
            let dest_cap = if self.empty_slots.start.0 < self.empty_slots.end.0 {
                let s = self.empty_slots.start;
                self.empty_slots.start.0 += 1;
                s
            } else {
                return None;
            };

            let ret = untyped_cap.untyped_retype(obj_type, size_param, 1, self.cnode, dest_cap, false);
            
            if ret == 0 {
                return Some(dest_cap);
            } else {
                self.empty_slots.start.0 -= 1;
                self.current_untyped_idx += 1;
            }
        }
        None
    }

    pub fn alloc_mmio(&mut self, paddr: usize, pages: usize) -> Option<CapPtr> {
        for i in 0..MAX_UNTYPED_REGIONS {
            let desc = &self.mmio_list[i];
            if desc.size == 0 { continue; }
            
            if paddr >= desc.paddr && (paddr + pages * 4096) <= (desc.paddr + desc.size) {
                let offset_needed = paddr - desc.paddr;
                let current_offset = self.mmio_cursors[i];
                
                if offset_needed < current_offset {
                    continue;
                }
                
                let untyped_cap = CapPtr(self.mmio_slots.start.0 + i);
                
                if offset_needed > current_offset {
                    let gap = offset_needed - current_offset;
                    let gap_pages = gap / 4096;
                    if gap_pages > 0 {
                        let temp_slot = self.alloc_slot()?;
                        let ret = untyped_cap.untyped_retype(CapType::Frame, gap_pages, 1, self.cnode, temp_slot, false);
                        if ret != 0 { 
                            self.empty_slots.start.0 -= 1;
                            return None; 
                        }
                    }
                    self.mmio_cursors[i] = offset_needed;
                }
                
                let dest_cap = self.alloc_slot()?;
                let ret = untyped_cap.untyped_retype(CapType::Frame, pages, 1, self.cnode, dest_cap, false);
                
                if ret == 0 {
                    self.mmio_cursors[i] += pages * 4096;
                    return Some(dest_cap);
                } else {
                    self.empty_slots.start.0 -= 1;
                    return None;
                }
            }
        }
        None
    }
}
