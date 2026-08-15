//! OSTD VM I/O types exposed through the FrameVisor service facade.

pub use host_ostd::mm::{
    Fallible, FallibleVmRead, FallibleVmWrite, Infallible, PodAtomic, PodOnce, VmIo, VmIoFill,
    VmIoOnce, VmReader, VmWriter,
};

pub mod util {
    pub use host_ostd::mm::io::util::*;
}
