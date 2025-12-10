use ostd::{
    cpu::{CpuId as OstdCpuId, CpuSet as OstdCpuSet},
    early_println,
};

use crate::{cpu::id::set::CpuSet, util::id_set::IdSet};

pub struct CpuId(OstdCpuId);

impl CpuId {
    pub fn new(raw_id: u32) -> Self {
        Self(OstdCpuId::new(raw_id))
    }
    pub const fn bsp() -> Self {
        Self(OstdCpuId::bsp())
    }
}

mod set {
    use crate::{
        cpu::id::CpuId,
        util::id_set::{Id, IdSet},
    };

    pub type CpuSet = IdSet<CpuId>;

    impl Id for CpuId {
        type Inner = ostd::cpu::CpuId;
    }
}

pub fn init_cpu_id() {
    early_println!("[framevisor] Initializing CPU ID...");
    CpuId::bsp();
    CpuSet::new_full();
    early_println!("[framevisor] CPU ID initialized");
}
