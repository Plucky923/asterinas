// SPDX-License-Identifier: MPL-2.0

//! Dynamic-link console transport used by the service console component.

#![no_std]
#![deny(unsafe_code)]

use spin::Once;

/// A callback invoked when bytes arrive from the active service console.
pub type ConsoleInputCallback = fn(&[u8]);

/// A result returned by the console transport.
pub type Result<T> = core::result::Result<T, Error>;

/// An error returned by the console transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The host did not install a console transport backend.
    Unavailable,
}

/// Host-provided console transport operations.
#[derive(Clone, Copy)]
pub struct Backend {
    write_fn: fn(&[u8]) -> Result<usize>,
    read_fn: fn(&mut [u8]) -> Result<usize>,
    acquire_input_fn: fn() -> Result<()>,
    release_input_fn: fn() -> Result<()>,
    register_input_callback_fn: fn(ConsoleInputCallback) -> Result<()>,
}

impl Backend {
    /// Creates a console transport backend.
    pub const fn new(
        write_fn: fn(&[u8]) -> Result<usize>,
        read_fn: fn(&mut [u8]) -> Result<usize>,
        acquire_input_fn: fn() -> Result<()>,
        release_input_fn: fn() -> Result<()>,
        register_input_callback_fn: fn(ConsoleInputCallback) -> Result<()>,
    ) -> Self {
        Self {
            write_fn,
            read_fn,
            acquire_input_fn,
            release_input_fn,
            register_input_callback_fn,
        }
    }
}

static BACKEND: Once<Backend> = Once::new();

/// Installs the host console transport backend.
pub fn install_backend(backend: Backend) {
    if BACKEND.get().is_some() {
        return;
    }

    BACKEND.call_once(|| backend);
}

/// Writes bytes to the active service console.
#[inline(never)]
pub fn write(bytes: &[u8]) -> Result<usize> {
    let backend = backend()?;
    (backend.write_fn)(bytes)
}

/// Reads bytes from the active service console.
#[inline(never)]
pub fn read(output: &mut [u8]) -> Result<usize> {
    let backend = backend()?;
    (backend.read_fn)(output)
}

/// Acquires service console input.
#[inline(never)]
pub fn acquire_input() -> Result<()> {
    let backend = backend()?;
    (backend.acquire_input_fn)()
}

/// Releases service console input.
#[inline(never)]
pub fn release_input() -> Result<()> {
    let backend = backend()?;
    (backend.release_input_fn)()
}

/// Registers a callback for active service-console input.
#[inline(never)]
pub fn register_input_callback(callback: ConsoleInputCallback) -> Result<()> {
    let backend = backend()?;
    (backend.register_input_callback_fn)(callback)
}

fn backend() -> Result<Backend> {
    BACKEND.get().copied().ok_or(Error::Unavailable)
}

#[used]
static _PRESERVE_CONSOLE_TRANSPORT_WRITE: fn(&[u8]) -> Result<usize> = write;

#[used]
static _PRESERVE_CONSOLE_TRANSPORT_READ: fn(&mut [u8]) -> Result<usize> = read;

#[used]
static _PRESERVE_CONSOLE_TRANSPORT_ACQUIRE_INPUT: fn() -> Result<()> = acquire_input;

#[used]
static _PRESERVE_CONSOLE_TRANSPORT_RELEASE_INPUT: fn() -> Result<()> = release_input;

#[used]
static _PRESERVE_CONSOLE_TRANSPORT_REGISTER_INPUT_CALLBACK: fn(ConsoleInputCallback) -> Result<()> =
    register_input_callback;

/// Preserves transport symbols for dynamic service modules.
pub fn preserve_symbols() {
    let functions = (
        write as fn(&[u8]) -> Result<usize>,
        read as fn(&mut [u8]) -> Result<usize>,
        acquire_input as fn() -> Result<()>,
        release_input as fn() -> Result<()>,
        register_input_callback as fn(ConsoleInputCallback) -> Result<()>,
    );
    core::hint::black_box(functions);
}
