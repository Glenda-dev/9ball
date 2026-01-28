use crate::bootinfo::{BootInfo, SlotRegion};
use glenda::cap::{CNode, CSPACE_CAP, CapPtr, CapType, Untyped};
use glenda::error::code as errcode;

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
        // 先检查是否有空闲槽位
        if self.empty_slots.start >= self.empty_slots.end {
            return None;
        }

        // 预选槽位，但不立即消耗 (不执行 +1)
        // 这样在循环尝试不同的 Untyped 时，我们复用同一个目标槽位
        let dest_idx = self.empty_slots.start;
        let dest_cap = CapPtr::from(dest_idx);
        let untyped_total = self.untyped_slots.end - self.untyped_slots.start;

        for idx in self.current_untyped_idx..untyped_total {
            let untyped_cap = CapPtr::from(self.untyped_slots.start + idx);

            // 尝试 Retype
            let ret = Untyped::from(untyped_cap)
                .retype(obj_type, size_param, 1, self.cnode, dest_cap, false);

            if ret == errcode::SUCCESS {
                // 成功：确认消耗该槽位，并返回
                self.empty_slots.start += 1;
                return Some(dest_cap);
            } else if ret == errcode::UNTYPE_OOM {
                // 失败：当前 Untyped 可能空间不足，尝试下一个
                // 此时 dest_idx (self.empty_slots.start) 保持不变，供下一次迭代使用
                self.current_untyped_idx += 1;
            } else {
                // 其他错误，直接返回 None
                return None;
            }
        }
        None
    }
}
