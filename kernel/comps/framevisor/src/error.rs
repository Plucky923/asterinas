use ostd::early_println;

use crate::mm::page_table::PageTableError;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid arguments provided.
    InvalidArgs,
    /// Insufficient memory available.
    NoMemory,
    /// Page fault occurred.
    PageFault,
    /// Access to a resource is denied.
    AccessDenied,
    /// Input/output error.
    IoError,
    /// Insufficient system resources.
    NotEnoughResources,
    /// Arithmetic Overflow occurred.
    Overflow,
}

impl From<PageTableError> for Error {
    fn from(_err: PageTableError) -> Error {
        Error::AccessDenied
    }
}

pub fn init_error() {
    let result = Error::InvalidArgs;
    match result {
        Error::InvalidArgs => early_println!("[framevisor] Invalid arguments provided"),
        Error::NoMemory => early_println!("[framevisor] Insufficient memory available"),
        Error::PageFault => early_println!("[framevisor] Page fault occurred"),
        Error::AccessDenied => early_println!("[framevisor] Access to a resource is denied"),
        Error::IoError => early_println!("[framevisor] Input/output error"),
        Error::NotEnoughResources => early_println!("[framevisor] Insufficient system resources"),
        Error::Overflow => early_println!("[framevisor] Arithmetic Overflow occurred"),
    }
    let result = PageTableError::UnalignedVaddr;
    let error = Error::from(result);
    match error {
        Error::InvalidArgs => early_println!("[framevisor] Invalid arguments provided"),
        Error::NoMemory => early_println!("[framevisor] Insufficient memory available"),
        Error::PageFault => early_println!("[framevisor] Page fault occurred"),
        Error::AccessDenied => early_println!("[framevisor] Access to a resource is denied"),
        Error::IoError => early_println!("[framevisor] Input/output error"),
        Error::NotEnoughResources => early_println!("[framevisor] Insufficient system resources"),
        Error::Overflow => early_println!("[framevisor] Arithmetic Overflow occurred"),
    }
    early_println!("[framevisor] Initializing error...");
}
