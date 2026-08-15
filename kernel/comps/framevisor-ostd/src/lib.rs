// SPDX-License-Identifier: MPL-2.0

//! OSTD-shaped service facade.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
pub use aster_framevisor::arch::if_tdx_enabled;
pub use aster_framevisor::{
    Error as FramevisorError, alert, arch, crit, debug, early_print, early_println, emerg, error,
    info, log, log_enabled, main, notice, prelude, util, warn,
};
pub use host_ostd::{
    Error, Result, const_assert, global_frame_allocator, global_heap_allocator,
    global_heap_allocator_slot_map, impl_untyped_frame_meta_for, panic_handler, ptr_null_of,
};

#[doc(hidden)]
pub mod ktest {
    //! Re-exports the ktest support expected by the OSTD attribute macro.

    pub use aster_framevisor::ktest::*;
}

/// Defines an inner-mutable vCPU-local variable for FrameVM service code.
#[macro_export]
macro_rules! cpu_local_cell {
    ($( $(#[$attr:meta])* $vis:vis static $name:ident: $t:ty = $init:expr; )*) => {
        $(
            $(#[$attr])* $vis static $name: $crate::cpu::local::CpuLocalCell<$t> =
                $crate::cpu::local::CpuLocalCell::new(
                    || $init,
                    concat!(module_path!(), "::", stringify!($name)),
                );
        )*
    };
}

/// Defines a static CPU-local variable for FrameVM service code.
#[macro_export]
macro_rules! cpu_local {
    ($( $(#[$attr:meta])* $vis:vis static $name:ident: $t:ty = $init:expr; )*) => {
        $(
            $(#[$attr])* $vis static $name: $crate::cpu::local::StaticCpuLocal<$t> =
                $crate::cpu::local::StaticCpuLocal::new(
                    || $init,
                    concat!(module_path!(), "::", stringify!($name)),
                );
        )*
    }
}

/// OSTD-shaped panic facade.
pub mod panic {
    pub use aster_framevisor::panic::abort;
    pub use host_ostd::panic::{begin_panic, catch_unwind, print_stack_trace};
}

/// OSTD-shaped CPU facade.
pub mod cpu {
    pub use aster_framevisor::cpu::*;

    /// OSTD-shaped CPU-local storage facade.
    pub mod local {
        pub use aster_framevisor::cpu::local::{
            CpuLocalCell, CpuLocalGuard, CpuLocalRemoteGuard, StaticCpuLocal,
        };
    }
}

/// OSTD-shaped memory facade.
pub mod mm {
    pub use host_ostd::mm::{
        self, AnyUFrameMeta, CachePolicy, Fallible, FallibleVmRead, FallibleVmWrite, Frame,
        HasDaddr, HasPaddr, HasPaddrRange, HasSize, Infallible, KERNEL_VADDR_RANGE,
        MAX_USERSPACE_VADDR, PAGE_SIZE, PageFlags, PageProperty, Segment, Split, UFrame, USegment,
        UniqueFrame, VmIo, VmIoFill, VmIoOnce, VmReader, VmSpace, VmWriter,
        frame::FrameRef,
        io::{PodAtomic, PodOnce},
        vm_space,
        vm_space::{Cursor, CursorMut, VmQueriedItem},
    };

    /// Virtual addresses.
    pub type Vaddr = usize;

    /// Physical addresses.
    pub type Paddr = usize;

    /// Device addresses.
    pub type Daddr = usize;

    /// OSTD frame namespace with a FrameVM-backed allocation entry.
    pub mod frame {
        pub use host_ostd::mm::frame::{
            Frame, FrameRef, GlobalFrameAllocator, Segment, linked_list, meta, segment, unique,
            untyped,
        };

        pub use super::FrameAllocOptions;
    }

    /// OSTD heap namespace. The provider trait remains source-compatible;
    /// provider instances are installed by the loaded FrameVM image.
    pub mod heap {
        pub use host_ostd::mm::heap::*;
    }

    /// OSTD-shaped physical-frame allocation options backed by the current
    /// FrameVM's memory domain.
    pub struct FrameAllocOptions(aster_framevisor::mm::FrameAllocOptions);

    impl Default for FrameAllocOptions {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FrameAllocOptions {
        /// Creates allocation options with OSTD's default zeroing policy.
        pub fn new() -> Self {
            Self(aster_framevisor::mm::FrameAllocOptions::new())
        }

        /// Selects whether newly allocated pages are zero initialized.
        pub fn zeroed(&mut self, zeroed: bool) -> &mut Self {
            self.0.zeroed(zeroed);
            self
        }

        /// Allocates one OSTD frame in the current FrameVM domain.
        pub fn alloc_frame(&self) -> host_ostd::Result<Frame<()>> {
            self.0
                .alloc_frame_for_service()
                .map_err(map_framevisor_error)
        }

        /// Allocates one typed OSTD frame in the current FrameVM domain.
        pub fn alloc_frame_with<M: frame::meta::AnyFrameMeta>(
            &self,
            metadata: M,
        ) -> host_ostd::Result<Frame<M>> {
            self.0
                .alloc_frame_with_for_service(metadata)
                .map_err(map_framevisor_error)
        }

        /// Allocates a contiguous OSTD segment in the current FrameVM domain.
        pub fn alloc_segment(&self, nframes: usize) -> host_ostd::Result<Segment<()>> {
            self.0
                .alloc_segment_for_service(nframes)
                .map_err(map_framevisor_error)
        }

        /// Allocates a typed contiguous OSTD segment in the current domain.
        pub fn alloc_segment_with<M: frame::meta::AnyFrameMeta, F>(
            &self,
            nframes: usize,
            metadata_fn: F,
        ) -> host_ostd::Result<Segment<M>>
        where
            F: FnMut(Paddr) -> M,
        {
            self.0
                .alloc_segment_with_for_service(nframes, metadata_fn)
                .map_err(map_framevisor_error)
        }
    }

    fn map_framevisor_error(error: aster_framevisor::Error) -> host_ostd::Error {
        match error {
            aster_framevisor::Error::InvalidArgs => host_ostd::Error::InvalidArgs,
            aster_framevisor::Error::NoMemory => host_ostd::Error::NoMemory,
            aster_framevisor::Error::PageFault => host_ostd::Error::PageFault,
            aster_framevisor::Error::AccessDenied => host_ostd::Error::AccessDenied,
            aster_framevisor::Error::IoError => host_ostd::Error::IoError,
            aster_framevisor::Error::NotEnoughResources => host_ostd::Error::NotEnoughResources,
            aster_framevisor::Error::Overflow => host_ostd::Error::Overflow,
        }
    }

    /// Returns the current FrameVM's uncommitted memory budget in bytes.
    ///
    /// The service must not observe Host-wide free memory: that value would
    /// allow one image to infer or consume another VM's budget.  Before a
    /// FrameVM task is bound, no service allocation scope exists and the
    /// conservative answer is zero.
    pub fn load_total_free_size() -> usize {
        let Some(frame_vcpu_id) = aster_framevisor::current_frame_vcpu_id() else {
            return 0;
        };
        let Some(frame_vm) = aster_framevisor::get_framevm(frame_vcpu_id.vm_id()) else {
            return 0;
        };
        let stats = frame_vm.memory_stats();
        stats
            .limit
            .saturating_sub(stats.committed.saturating_add(stats.reserved))
    }

    /// OSTD-shaped DMA facade.
    pub mod dma {
        pub use aster_framevisor::mm::dma::*;
    }

    /// OSTD-shaped VM I/O facade.
    pub mod io {
        pub use aster_framevisor::mm::io::*;
        pub use host_ostd::mm::io::{VmIo, VmIoFill, VmIoOnce};

        /// OSTD-shaped VM reader/writer helper facade.
        pub mod util {
            pub use host_ostd::mm::io::util::*;
        }
    }

    /// OSTD-shaped TLB facade.
    pub mod tlb {
        pub use host_ostd::mm::tlb::*;
    }
}

/// OSTD-shaped boot facade.
pub mod boot {
    pub use aster_framevisor::boot::{
        BootInfo, BootloaderAcpiArg, BootloaderFramebufferArg, boot_info, memory_region,
    };
}

/// OSTD-shaped console facade.
pub mod console {
    pub use aster_framevisor::{clear_input, early_print, has_input, is_active, read, write};
}

/// OSTD-shaped IRQ facade.
pub mod irq {
    pub use aster_framevisor::irq::{
        DisabledLocalIrqGuard, InterruptLevel, IrqCallbackFunction, IrqLine, PciIrqRequester,
        disable_local, register_bottom_half_handler_l1, register_bottom_half_handler_l2,
    };
}

/// OSTD-shaped device I/O facade.
pub mod io {
    pub use host_ostd::{
        arch::device::io_port::{PortRead, PortWrite},
        io::IoMem,
    };
}

/// OSTD-shaped bus facade.
pub mod bus {
    pub use host_ostd::bus::BusProbeError;
}

/// OSTD-shaped power facade.
pub mod power {
    pub use aster_framevisor::power::{ExitCode, poweroff, restart};
}

/// OSTD-shaped PCI platform facade.
pub mod pci {
    pub use aster_framevisor::{
        device::FunctionClaim,
        pci::{IoMem, claim_current_function, current_bus_range, read_config32, write_config32},
    };
}

/// OSTD-shaped RNG facade.
pub mod rng {
    pub use aster_framevisor::rng::fill_bytes;
}

/// OSTD-shaped synchronization facade.
pub mod sync {
    pub use aster_framevisor::sync::{
        GuardTransfer, LocalIrqDisabled, Once, PreemptDisabled, RwLock, RwLockReadGuard,
        RwLockUpgradeableGuard, RwLockWriteGuard, SpinGuardian, SpinLock, SpinLockGuard, WaitQueue,
        Waiter, Waker,
    };
    pub use host_ostd::sync::{
        Mutex, MutexGuard, Rcu, RcuOption, RcuOptionReadGuard, RoArc, RwArc, RwMutex,
        RwMutexReadGuard, RwMutexUpgradeableGuard, RwMutexWriteGuard,
    };
}

/// OSTD-shaped user-mode facade.
pub mod user {
    pub use aster_framevisor::user::*;
    pub use host_ostd::user::UserContextApi;
}

/// Low-level FrameV transport facade.
pub mod framev {
    /// Low-level FrameV Sock transport hooks used by `framev-pci`.
    pub mod sock {
        pub use aster_framevisor::framev_sock::{
            activate_claimed, guest_cid_claimed, is_active_claimed, queue_count_claimed,
            recv_packet_claimed, submit_packet_claimed, take_transport_reset_claimed,
        };
    }

    /// Low-level FrameV RNG transport hooks used by `framev-pci`.
    pub mod rng {
        pub use aster_framevisor::rng::fill_bytes_claimed;
    }

    /// Low-level FrameV console transport hooks used by `framev-pci`.
    pub mod console {
        pub use aster_framevisor::console::{take_claimed_input, write_claimed};
    }

    /// Low-level FrameV block transport hooks used by `framev-pci`.
    pub mod blk {
        pub use aster_framevisor::device::{
            BlockDestinations, BlockSources, MAX_BLOCK_EXTENTS, current_block_config,
            flush_current_block, read_current_block, write_current_block,
        };
    }

    /// Low-level FrameV-net transport hooks used by `framev-pci`.
    pub mod net {
        pub use aster_framevisor::framev_net::{
            current_net_config, has_completed_buffer_claimed, is_endpoint_lost_claimed,
            poll_receive_claimed, post_receive_buffer_claimed, send_claimed,
            take_completed_buffer_claimed, take_reclaimed_buffer_claimed,
        };
    }
}

/// OSTD-shaped task facade.
pub mod task {
    use alloc::sync::Arc;

    pub use aster_framevisor::{
        TaskAdmission, TaskWorker,
        task::{
            CurrentTask, DisabledPreemptGuard, Task, TaskOptions, disable_preempt,
            inject_post_schedule_handler, inject_pre_schedule_handler, inject_pre_user_run_handler,
            inject_shutdown_handler,
            scheduler::info::{AtomicCpuId, TaskScheduleInfo},
        },
    };

    /// Returns the current virtual CPU index.
    ///
    /// The service-facing surface exposes the OSTD-shaped CPU value while VM
    /// ownership remains internal to FrameVisor's task binding.
    pub fn current_cpu_index() -> Option<usize> {
        aster_framevisor::current_frame_vcpu_id().map(|id| id.vcpu_index())
    }

    /// Returns admission state for ordinary tasks in the current FrameVM.
    pub fn current_task_admission() -> aster_framevisor::Result<Arc<TaskAdmission>> {
        aster_framevisor::current_task_admission()
    }
    pub use host_ostd::task::halt_cpu;

    /// OSTD-shaped atomic-mode facade.
    pub mod atomic_mode {
        pub use aster_framevisor::task::atomic_mode::{AsAtomicModeGuard, InAtomicMode};
    }

    /// OSTD-shaped scheduler facade.
    pub mod scheduler {
        pub use aster_framevisor::task::scheduler::{
            EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags, enable_preemption_on_cpu,
            inject_scheduler,
        };

        /// OSTD-shaped scheduler info facade.
        pub mod info {
            pub use aster_framevisor::task::scheduler::info::{
                AtomicCpuId, CommonSchedInfo, TaskScheduleInfo,
            };
        }
    }
}

/// OSTD-shaped timer facade.
pub mod timer {
    pub use aster_framevisor::timer::{
        Jiffies, TIMER_FREQ, read_wall_clock, register_callback_on_cpu,
    };
}
