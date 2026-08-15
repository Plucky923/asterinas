// SPDX-License-Identifier: MPL-2.0

//! MSI-X interrupt management for NVMe devices.
//!
//! This module provides MSI-X interrupt vector allocation and management
//! for NVMe controllers, allowing per-queue interrupt handling for better
//! performance and scalability.

use alloc::vec::Vec;

use aster_pci::capability::msix::CapabilityMsixData;
use ostd::irq::IrqLine;

/// MSI-X interrupt manager for NVMe devices.
///
/// NVMe devices can use multiple MSI-X vectors for improved interrupt handling:
/// - Admin queue vector: Used for admin command completions.
/// - I/O queue vectors: Each I/O queue can have its own interrupt vector.
pub(crate) struct NvmeMsixManager {
    /// Number of MSI-X vectors backed by allocated IRQ lines.
    vector_count: u16,
    /// MSI-X vector for admin queue (queue 0).
    admin_vector: u16,
    /// Available MSI-X vectors for I/O queues.
    unused_vectors: Vec<u16>,
    /// MSI-X vectors currently assigned to I/O queues.
    used_vectors: Vec<u16>,
    /// MSI-X capability data.
    msix: CapabilityMsixData,
}

impl NvmeMsixManager {
    /// Creates a new MSI-X manager and initializes all available interrupt vectors.
    ///
    /// # Arguments
    ///
    /// * `msix` - The MSI-X capability data from PCI configuration space
    ///
    /// # Returns
    ///
    /// A new `NvmeMsixManager` with the vectors that fit in the current IRQ pool, or `None` if the
    /// required admin vector cannot be allocated.
    pub(crate) fn new(mut msix: CapabilityMsixData, required_vector_count: u16) -> Option<Self> {
        let table_size = msix.table_size();
        if table_size == 0 || required_vector_count == 0 {
            return None;
        }
        let vector_count = table_size.min(required_vector_count);
        let mut irqs = Vec::with_capacity(usize::from(vector_count));
        for _ in 0..vector_count {
            let Ok(irq) = IrqLine::alloc() else {
                break;
            };
            irqs.push(irq);
        }

        let allocated_vector_count = u16::try_from(irqs.len()).ok()?;
        if allocated_vector_count == 0 {
            return None;
        }

        for (i, irq) in irqs.into_iter().enumerate() {
            msix.set_interrupt_vector(irq, i as u16);
        }

        // Reserve the first vector for admin queue
        let admin_vector = 0;
        let vector_list: Vec<u16> = (1..allocated_vector_count).rev().collect();

        Some(Self {
            vector_count: allocated_vector_count,
            admin_vector,
            unused_vectors: vector_list,
            used_vectors: Vec::new(),
            msix,
        })
    }

    /// Returns the admin queue MSI-X vector and its IRQ line.
    pub(crate) fn admin_irq(&mut self) -> (u16, &mut IrqLine) {
        (
            self.admin_vector,
            self.msix.irq_mut(self.admin_vector as usize).unwrap(),
        )
    }

    /// Allocates an MSI-X vector for an I/O queue.
    ///
    /// Returns `Some((vector_id, irq_line))` if a vector is available, or `None` otherwise.
    pub(crate) fn alloc_io_queue_irq(&mut self) -> Option<(u16, &mut IrqLine)> {
        let vector = self.unused_vectors.pop()?;
        self.used_vectors.push(vector);
        Some((vector, self.msix.irq_mut(vector as usize).unwrap()))
    }

    /// Returns the total number of MSI-X vectors available.
    pub(crate) fn table_size(&self) -> u16 {
        self.vector_count
    }

    /// Returns a mutable reference to the IRQ line for the given vector if any.
    pub(crate) fn irq_for_vector_mut(&mut self, vector: u16) -> Option<&mut IrqLine> {
        self.msix.irq_mut(vector as usize)
    }
}
