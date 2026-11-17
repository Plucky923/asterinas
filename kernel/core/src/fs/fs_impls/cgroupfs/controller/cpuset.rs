// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use aster_systree::{Error, MAX_ATTR_SIZE, Result, SysAttrSetBuilder, SysPerms, SysStr};
use aster_util::printer::VmPrinter;
use ostd::{
    cpu::{AtomicCpuSet, CpuId, CpuSet, all_cpus, num_cpus},
    mm::{VmReader, VmWriter},
    util::id_set::Id,
};

use crate::util::ReadCString;

/// A sub-controller responsible for CPU resource management in the cgroup subsystem.
pub(crate) struct CpuSetController {
    configured_cpus: AtomicCpuSet,
    affinity_violations: AtomicU64,
}

impl CpuSetController {
    pub(super) fn init_attr_set(builder: &mut SysAttrSetBuilder, is_root: bool) {
        if !is_root {
            builder.add(SysStr::from("cpuset.cpus"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(SysStr::from("cpuset.mems"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(
                SysStr::from("cpuset.affinity_violations"),
                SysPerms::DEFAULT_RO_ATTR_PERMS,
            );
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

    pub(super) fn configured_cpus(&self) -> CpuSet {
        self.configured_cpus.load(Ordering::Acquire)
    }

    pub(super) fn record_violation(&self) {
        self.affinity_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn write_cpu_list(&self, printer: &mut VmPrinter, set: &CpuSet) -> Result<()> {
        let mut range_start: Option<usize> = None;
        let mut range_end: usize = 0;
        let mut first = true;
        for cpu_id in set.iter() {
            let id = cpu_id.as_usize();
            match range_start {
                None => {
                    range_start = Some(id);
                    range_end = id;
                }
                Some(_) if id == range_end + 1 => {
                    range_end = id;
                }
                Some(start) => {
                    if !first {
                        write!(printer, ",")?;
                    }
                    first = false;
                    if start == range_end {
                        write!(printer, "{}", start)?;
                    } else {
                        write!(printer, "{}-{}", start, range_end)?;
                    }
                    range_start = Some(id);
                    range_end = id;
                }
            }
        }
        if let Some(start) = range_start {
            if !first {
                write!(printer, ",")?;
            }
            if start == range_end {
                write!(printer, "{}", start)?;
            } else {
                write!(printer, "{}-{}", start, range_end)?;
            }
        }
        writeln!(printer)?;
        Ok(())
    }
}

pub(super) fn intersect_cpu_sets(a: &CpuSet, b: &CpuSet) -> CpuSet {
    let mut out = CpuSet::new_empty();
    for cpu_id in all_cpus() {
        if a.contains(cpu_id) && b.contains(cpu_id) {
            out.add(cpu_id);
        }
    }
    out
}

fn parse_cpu_list(spec: &str) -> Result<CpuSet> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Ok(CpuSet::new_full());
    }
    let total = num_cpus();
    let mut out = CpuSet::new_empty();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(Error::InvalidOperation);
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: usize = start_s.trim().parse().map_err(|_| Error::InvalidOperation)?;
            let end: usize = end_s.trim().parse().map_err(|_| Error::InvalidOperation)?;
            if start > end || end >= total {
                return Err(Error::InvalidOperation);
            }
            for id in start..=end {
                let cpu_id = CpuId::try_from(id).map_err(|_| Error::InvalidOperation)?;
                out.add(cpu_id);
            }
        } else {
            let id: usize = part.parse().map_err(|_| Error::InvalidOperation)?;
            if id >= total {
                return Err(Error::InvalidOperation);
            }
            let cpu_id = CpuId::try_from(id).map_err(|_| Error::InvalidOperation)?;
            out.add(cpu_id);
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidOperation);
    }
    Ok(out)
}

impl super::SubControl for CpuSetController {
    fn read_attr_at(&self, name: &str, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        match name {
            "cpuset.cpus" | "cpuset.cpus.effective" => {
                let cpus = self.configured_cpus();
                self.write_cpu_list(&mut printer, &cpus)?;
            }
            // Currently we only support a single memory node.
            "cpuset.mems" | "cpuset.mems.effective" => writeln!(printer, "0")?,
            "cpuset.affinity_violations" => {
                writeln!(printer, "{}", self.affinity_violations.load(Ordering::Relaxed))?;
            }
            _ => return Err(Error::AttributeError),
        }

        Ok(printer.bytes_written())
    }

    fn write_attr(&self, name: &str, reader: &mut VmReader) -> Result<usize> {
        match name {
            "cpuset.cpus" => {
                let (content, len) = reader
                    .read_cstring_until_end(MAX_ATTR_SIZE)
                    .map_err(|_| Error::PageFault)?;
                let spec = content.to_str().map_err(|_| Error::InvalidOperation)?;
                let parsed = parse_cpu_list(spec)?;
                self.configured_cpus.store(&parsed, Ordering::Release);
                Ok(len)
            }
            _ => Err(Error::AttributeError),
        }
    }
}

impl super::SubControlStatic for CpuSetController {
    fn new(_is_root: bool, _is_active: bool) -> Self {
        Self {
            configured_cpus: AtomicCpuSet::new(CpuSet::new_full()),
            affinity_violations: AtomicU64::new(0),
        }
    }

    fn type_() -> super::SubCtrlType {
        super::SubCtrlType::CpuSet
    }

    fn read_from(controller: &super::Controller) -> Arc<super::SubController<Self>> {
        controller.cpuset.read().get().clone()
    }
}
