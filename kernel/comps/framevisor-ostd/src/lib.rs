// SPDX-License-Identifier: MPL-2.0

//! OSTD-shaped service facade.

#![no_std]
#![deny(unsafe_code)]

#[cfg(target_arch = "x86_64")]
pub use aster_framevisor::arch::if_tdx_enabled;
pub use aster_framevisor::{
    Error as FramevisorError, alert, arch, crit, debug, early_print, early_println, emerg, error,
    info, log, log_enabled, main, notice, prelude, util, warn,
};
pub use host_ostd::{Error, Result, const_assert, impl_untyped_frame_meta_for, panic_handler};

/// Defines an inner-mutable vCPU-local variable for FrameVM service code.
#[macro_export]
macro_rules! cpu_local_cell {
    ($( $(#[$attr:meta])* $vis:vis static $name:ident: $t:ty = $init:expr; )*) => {
        $(
            $(#[$attr])* $vis static $name: $crate::cpu::local::CpuLocalCell<$t> =
                $crate::cpu::local::CpuLocalCell::new(
                    || $init,
                    $crate::__private::allocate_cpu_local_object_id,
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
                    $crate::__private::allocate_cpu_local_object_id,
                );
        )*
    }
}

#[doc(hidden)]
pub mod __private {
    use core::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CPU_LOCAL_OBJECT_ID: AtomicU64 = AtomicU64::new(1);

    #[doc(hidden)]
    pub fn allocate_cpu_local_object_id() -> aster_framevisor::cpu::local::CpuLocalObjectId {
        aster_framevisor::cpu::local::CpuLocalObjectId::from_raw(
            NEXT_CPU_LOCAL_OBJECT_ID.fetch_add(1, Ordering::Relaxed),
        )
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
        FrameAllocOptions, HasDaddr, HasPaddr, HasPaddrRange, HasSize, Infallible,
        KERNEL_VADDR_RANGE, MAX_USERSPACE_VADDR, PAGE_SIZE, PageFlags, PageProperty, Segment,
        Split, UFrame, USegment, UniqueFrame, VmIo, VmIoFill, VmIoOnce, VmReader, VmSpace,
        VmWriter, frame,
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

    /// Returns the FrameVM-visible free memory size in bytes.
    ///
    /// FrameVM does not expose Host OSTD's allocator CPU-local caches through
    /// the service ABI. Until FrameVM has its own allocator domain, report the
    /// service-visible usable memory as the conservative free-memory view.
    pub fn load_total_free_size() -> usize {
        super::boot::boot_info()
            .memory_regions
            .iter()
            .filter(|region| region.typ() == super::boot::memory_region::MemoryRegionType::Usable)
            .map(|region| region.len())
            .sum()
    }

    /// OSTD-shaped DMA facade.
    pub mod dma {
        pub use host_ostd::mm::dma::*;
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
    pub use aster_framevisor::{
        clear_input, early_print, has_input, is_active, read, register_input_callback, write,
    };
}

/// OSTD-shaped IRQ facade.
pub mod irq {
    pub use aster_framevisor::irq::{
        DisabledLocalIrqGuard, InterruptLevel, IrqCallbackFunction, IrqLine, disable_local,
        register_bottom_half_handler_l1, register_bottom_half_handler_l2,
    };
}

/// OSTD-shaped device I/O facade.
pub mod io {
    pub use host_ostd::io::IoMem;
}

/// OSTD-shaped power facade.
pub mod power {
    pub use aster_framevisor::power::{ExitCode, poweroff, restart};
}

/// OSTD-shaped RNG facade.
pub mod rng {
    pub use aster_framevisor::rng::fill_bytes;
}

/// OSTD-shaped synchronization facade.
pub mod sync {
    pub use aster_framevisor::sync::*;
    pub use host_ostd::sync::{
        Rcu, RcuOption, RcuOptionReadGuard, RoArc, RwArc, RwMutex, RwMutexReadGuard,
        RwMutexUpgradeableGuard, RwMutexWriteGuard,
    };
}

/// OSTD-shaped user-mode facade.
pub mod user {
    pub use aster_framevisor::user::*;
    pub use host_ostd::user::UserContextApi;
}

/// Low-level FrameV boot metadata facade.
pub mod framev {
    const FRAMEV_DEVICES_CMDLINE_KEY: &str = "framev.devices";

    /// Returns the FrameV device descriptor boot-argument value.
    pub fn devices_boot_arg() -> Option<&'static str> {
        super::boot::boot_info()
            .kernel_cmdline
            .split_whitespace()
            .find_map(|arg| {
                let (key, value) = arg.split_once('=')?;
                (key == FRAMEV_DEVICES_CMDLINE_KEY).then_some(value)
            })
    }

    /// Low-level FrameV Sock transport hooks used by `framev-bus`.
    pub mod sock {
        pub use aster_framevisor::framev_sock::{
            activate, current_vcpu_index, current_vm_id, deactivate, guest_cid, has_pending_packet,
            install_rx_callback, is_active, queue_count, recv_packet, submit_packet,
        };
    }

    /// Low-level FrameV RNG transport hooks used by `framev-bus`.
    pub mod rng {
        pub use aster_framevisor::rng::fill_bytes;
    }

    /// Low-level FrameV console transport hooks used by `framev-bus`.
    pub mod console {
        pub use aster_framevisor::console::{register_input_callback, write};
    }

    /// Low-level FrameV block transport hooks used by `framev-bus`.
    pub mod blk {
        pub use aster_framevisor::device::{
            BlockRequestCompletion, BlockRequestResource, BlockReturnedResource,
            current_block_config, submit_current_block_request,
        };
    }
}

/// OSTD-shaped task facade.
pub mod task {
    pub use aster_framevisor::task::{
        CurrentTask, DisabledPreemptGuard, Task, TaskOptions, disable_preempt,
        inject_post_schedule_handler, inject_pre_schedule_handler, inject_pre_user_run_handler,
        scheduler::info::{AtomicCpuId, TaskScheduleInfo},
    };
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
    pub use aster_framevisor::timer::{Jiffies, TIMER_FREQ, register_callback_on_cpu};
}
