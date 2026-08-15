// SPDX-License-Identifier: MPL-2.0

use alloc::{
    collections::BTreeSet,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor::VmId;
use aster_systree::{Error, MAX_ATTR_SIZE, Result, SysAttrSetBuilder, SysPerms, SysStr};
use aster_util::printer::VmPrinter;
use ostd::{
    cpu::{CpuId, CpuSet},
    mm::{VmReader, VmWriter},
    sync::SpinLock,
};

use crate::util::ReadCString;

/// A stable cgroup CPU-placement domain observed by FrameVM schedulers.
///
/// The object survives cpuset controller activation changes. Its parent link is
/// immutable, so a FrameVM can retain the domain captured at creation without
/// following later movement of the creator process.
pub(crate) struct CpuPlacement {
    active: AtomicBool,
    configured: SpinLock<Option<CpuSet>>,
    parent: Option<Weak<Self>>,
    children: SpinLock<Vec<Weak<Self>>>,
    framevms: SpinLock<BTreeSet<VmId>>,
}

impl CpuPlacement {
    fn new_root() -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(true),
            configured: SpinLock::new(Some(CpuSet::new_full())),
            parent: None,
            children: SpinLock::new(Vec::new()),
            framevms: SpinLock::new(BTreeSet::new()),
        })
    }

    fn new_child(parent: &Arc<Self>, active: bool) -> Arc<Self> {
        let placement = Arc::new(Self {
            active: AtomicBool::new(active),
            configured: SpinLock::new(None),
            parent: Some(Arc::downgrade(parent)),
            children: SpinLock::new(Vec::new()),
            framevms: SpinLock::new(BTreeSet::new()),
        });
        parent.children.lock().push(Arc::downgrade(&placement));
        placement
    }

    /// Returns this domain's effective online CPU set.
    pub(crate) fn effective_cpu_set(&self) -> CpuSet {
        let parent_set = self
            .parent
            .as_ref()
            .and_then(Weak::upgrade)
            .map_or_else(CpuSet::new_full, |parent| parent.effective_cpu_set());
        if !self.active.load(Ordering::Acquire) {
            return parent_set;
        }

        let Some(configured) = self.configured.lock().clone() else {
            return parent_set;
        };
        let mut effective = CpuSet::new_empty();
        for cpu in configured.iter().filter(|cpu| parent_set.contains(*cpu)) {
            effective.add(cpu);
        }
        effective
    }

    fn configured_cpu_set(&self) -> Option<CpuSet> {
        self.configured.lock().clone()
    }

    fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Release);
        self.notify_subtree();
    }

    fn set_configured_cpu_set(&self, cpu_set: CpuSet) {
        *self.configured.lock() = Some(cpu_set);
        self.notify_subtree();
    }

    /// Subscribes a FrameVM and immediately applies the current effective set.
    pub(crate) fn subscribe_framevm(&self, vm_id: VmId) {
        self.framevms.lock().insert(vm_id);
        Self::apply_to_framevm(vm_id, &self.effective_cpu_set());
    }

    /// Removes a FrameVM subscription.
    pub(crate) fn unsubscribe_framevm(&self, vm_id: VmId) {
        self.framevms.lock().remove(&vm_id);
    }

    fn notify_subtree(&self) {
        let effective_cpu_set = self.effective_cpu_set();
        let framevms: Vec<_> = self.framevms.lock().iter().copied().collect();
        let children: Vec<_> = self
            .children
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect();

        for vm_id in framevms {
            Self::apply_to_framevm(vm_id, &effective_cpu_set);
        }
        for child in children {
            child.notify_subtree();
        }
        self.children
            .lock()
            .retain(|child| child.strong_count() != 0);
    }

    fn apply_to_framevm(vm_id: VmId, cpu_set: &CpuSet) {
        crate::sched::update_framevm_cpu_affinity(vm_id, cpu_set);
    }
}

/// A sub-controller responsible for CPU placement in the cgroup subsystem.
pub(crate) struct CpuSetController {
    placement: Arc<CpuPlacement>,
}

impl CpuSetController {
    pub(super) fn init_attr_set(builder: &mut SysAttrSetBuilder, is_root: bool) {
        if !is_root {
            builder.add(SysStr::from("cpuset.cpus"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(SysStr::from("cpuset.mems"), SysPerms::DEFAULT_RW_ATTR_PERMS);
        }

        builder.add(
            SysStr::from("cpuset.cpus.effective"),
            SysPerms::DEFAULT_RO_ATTR_PERMS,
        );
        builder.add(
            SysStr::from("cpuset.mems.effective"),
            SysPerms::DEFAULT_RO_ATTR_PERMS,
        );
    }

    pub(super) fn inherit_state_from(&mut self, previous: &Self, active: bool) {
        self.placement = previous.placement.clone();
        self.placement.set_active(active);
    }

    fn print_cpu_set(cpu_set: &CpuSet, printer: &mut VmPrinter) -> Result<()> {
        let mut cpus = cpu_set.iter().peekable();
        let mut first_range = true;
        while let Some(start) = cpus.next() {
            let mut end = start;
            while cpus
                .peek()
                .is_some_and(|next| u32::from(*next) == u32::from(end).saturating_add(1))
            {
                end = cpus.next().unwrap();
            }
            if !first_range {
                write!(printer, ",")?;
            }
            if start == end {
                write!(printer, "{}", u32::from(start))?;
            } else {
                write!(printer, "{}-{}", u32::from(start), u32::from(end))?;
            }
            first_range = false;
        }
        writeln!(printer)?;
        Ok(())
    }

    fn parse_cpu_set(content: &str) -> Result<CpuSet> {
        let content = content.trim();
        if content.is_empty() {
            return Ok(CpuSet::new_empty());
        }

        let mut cpu_set = CpuSet::new_empty();
        for range in content.split(',') {
            let (start, end) = match range.split_once('-') {
                Some((start, end)) => (start, end),
                None => (range, range),
            };
            let start = start
                .parse::<usize>()
                .map_err(|_| Error::InvalidOperation)?;
            let end = end.parse::<usize>().map_err(|_| Error::InvalidOperation)?;
            if start > end {
                return Err(Error::InvalidOperation);
            }
            for raw_cpu in start..=end {
                let cpu = CpuId::try_from(raw_cpu).map_err(|_| Error::InvalidOperation)?;
                cpu_set.add(cpu);
            }
        }
        Ok(cpu_set)
    }
}

impl super::SubControl for CpuSetController {
    fn is_attr_absent(&self, name: &str) -> bool {
        !self.placement.active.load(Ordering::Acquire)
            && matches!(name, "cpuset.cpus" | "cpuset.mems")
    }

    fn read_attr_at(&self, name: &str, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        match name {
            "cpuset.cpus" => {
                let cpu_set = self
                    .placement
                    .configured_cpu_set()
                    .unwrap_or_else(CpuSet::new_empty);
                Self::print_cpu_set(&cpu_set, &mut printer)?;
            }
            "cpuset.cpus.effective" => {
                Self::print_cpu_set(&self.placement.effective_cpu_set(), &mut printer)?;
            }
            "cpuset.mems" => writeln!(printer)?,
            "cpuset.mems.effective" => writeln!(printer, "0")?,
            _ => return Err(Error::AttributeError),
        }

        Ok(printer.bytes_written())
    }

    fn write_attr(&self, name: &str, reader: &mut VmReader) -> Result<usize> {
        let (content, len) = reader
            .read_cstring_until_end(MAX_ATTR_SIZE)
            .map_err(|_| Error::PageFault)?;
        let content = content.to_str().map_err(|_| Error::InvalidOperation)?;
        match name {
            "cpuset.cpus" => self
                .placement
                .set_configured_cpu_set(Self::parse_cpu_set(content)?),
            "cpuset.mems" if matches!(content.trim(), "" | "0") => {}
            "cpuset.mems" => return Err(Error::InvalidOperation),
            _ => return Err(Error::AttributeError),
        }
        Ok(len)
    }
}

impl super::SubControlStatic for CpuSetController {
    fn new(is_root: bool, is_active: bool, parent_controller: Option<&super::Controller>) -> Self {
        let placement = if is_root {
            CpuPlacement::new_root()
        } else {
            CpuPlacement::new_child(&parent_controller.unwrap().cpu_placement(), is_active)
        };
        Self { placement }
    }

    fn type_() -> super::SubCtrlType {
        super::SubCtrlType::CpuSet
    }

    fn read_from(controller: &super::Controller) -> Arc<super::SubController<Self>> {
        controller.cpuset.read().get().clone()
    }
}

impl super::Controller {
    /// Returns the stable CPU-placement domain represented by this cgroup.
    pub(crate) fn cpu_placement(&self) -> Arc<CpuPlacement> {
        self.cpuset
            .read()
            .get()
            .inner
            .as_ref()
            .unwrap()
            .placement
            .clone()
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn child_effective_set_tracks_parent_shrink_empty_and_restore() {
        let root = CpuPlacement::new_root();
        let child = CpuPlacement::new_child(&root, true);
        assert_eq!(child.effective_cpu_set(), CpuSet::new_full());

        child.set_configured_cpu_set(CpuSet::new_full());
        root.set_configured_cpu_set(CpuSet::new_empty());
        assert!(child.effective_cpu_set().is_empty());

        root.set_configured_cpu_set(CpuSet::new_full());
        assert_eq!(child.effective_cpu_set(), CpuSet::new_full());
    }

    #[ktest]
    fn inactive_child_inherits_parent_until_activated() {
        let root = CpuPlacement::new_root();
        let child = CpuPlacement::new_child(&root, false);
        child.set_configured_cpu_set(CpuSet::new_empty());
        assert_eq!(child.effective_cpu_set(), CpuSet::new_full());

        child.set_active(true);
        assert!(child.effective_cpu_set().is_empty());
    }

    #[ktest]
    fn cpu_list_parser_accepts_ranges_and_rejects_invalid_bounds() {
        let parsed = CpuSetController::parse_cpu_set("0").unwrap();
        assert_eq!(parsed.count(), 1);
        assert!(parsed.contains(CpuId::bsp()));
        assert!(CpuSetController::parse_cpu_set("").unwrap().is_empty());
        assert!(CpuSetController::parse_cpu_set("1-0").is_err());
        assert!(CpuSetController::parse_cpu_set("invalid").is_err());
    }
}
