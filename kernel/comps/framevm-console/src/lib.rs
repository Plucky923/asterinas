// SPDX-License-Identifier: MPL-2.0

//! Console device facade used by dynamically loaded kernel images.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod font;
pub mod mode;

use alloc::{fmt::Debug, string::String, sync::Arc, vec::Vec};
use core::{
    any::Any,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use aster_console_transport as console_transport;
use ostd::{
    mm::{Infallible, VmReader},
    sync::{LocalIrqDisabled, Once, SpinLock, SpinLockGuard},
};

pub type ConsoleCallback = dyn Fn(VmReader<Infallible>) + Send + Sync;

const DEFAULT_INPUT_OWNER_ID: usize = 0;
const DEFAULT_CONSOLE_NAME: &str = "Virtio-Console";

/// Identifies a consumer that may own console input delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputOwner(usize);

impl InputOwner {
    /// Returns the default input owner.
    pub const fn default() -> Self {
        Self(DEFAULT_INPUT_OWNER_ID)
    }
}

/// An error returned by [`AnyConsoleDevice::set_font`].
#[derive(Clone, Copy, Debug)]
pub enum ConsoleSetFontError {
    InappropriateDevice,
    InvalidFont,
}

/// A console device.
pub trait AnyConsoleDevice: Send + Sync + Any + Debug {
    /// Sends data to the console device.
    fn send(&self, buf: &[u8]);

    /// Registers a callback invoked when the console device receives data.
    fn register_callback(&self, callback: &'static ConsoleCallback);

    /// Sets the font of the console device.
    fn set_font(&self, _font: font::BitmapFont) -> Result<(), ConsoleSetFontError> {
        Err(ConsoleSetFontError::InappropriateDevice)
    }

    /// Sets the console mode.
    #[must_use]
    fn set_mode(&self, _mode: mode::ConsoleMode) -> bool {
        false
    }

    /// Gets the current console mode.
    fn mode(&self) -> Option<mode::ConsoleMode> {
        None
    }

    /// Sets the keyboard mode.
    #[must_use]
    fn set_keyboard_mode(&self, _mode: mode::KeyboardMode) -> bool {
        false
    }

    /// Gets the current keyboard mode.
    fn keyboard_mode(&self) -> Option<mode::KeyboardMode> {
        None
    }
}

/// Registers a console device.
pub fn register_device(name: String, device: Arc<dyn AnyConsoleDevice>) {
    component().devices.lock().push((name, device));
}

/// Returns all console devices.
pub fn all_devices() -> Vec<(String, Arc<dyn AnyConsoleDevice>)> {
    ensure_default_device();
    component().devices.lock().clone()
}

/// Locks and returns all console devices.
pub fn all_devices_lock<'a>()
-> SpinLockGuard<'a, Vec<(String, Arc<dyn AnyConsoleDevice>)>, LocalIrqDisabled> {
    ensure_default_device();
    component().devices.lock()
}

/// Allocates a new console input owner.
pub fn alloc_input_owner() -> InputOwner {
    let id = component().next_owner_id.fetch_add(1, Ordering::Relaxed);
    InputOwner(id)
}

/// Routes subsequent console input to `owner`.
pub fn acquire_input(owner: InputOwner) {
    component().input_owner_id.store(owner.0, Ordering::Release);
    let _ = console_transport::acquire_input();
}

/// Releases console input if it is currently owned by `owner`.
pub fn release_input(owner: InputOwner) {
    let _ = component().input_owner_id.compare_exchange(
        owner.0,
        DEFAULT_INPUT_OWNER_ID,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    let _ = console_transport::release_input();
}

/// Returns whether console input is currently owned by `owner`.
pub fn input_is_owned_by(owner: InputOwner) -> bool {
    component().input_owner_id.load(Ordering::Acquire) == owner.0
}

/// Returns whether console input is currently routed to the default owner.
pub fn input_is_owned_by_default() -> bool {
    input_is_owned_by(InputOwner::default())
}

#[derive(Debug)]
struct VirtualConsoleDevice;

impl AnyConsoleDevice for VirtualConsoleDevice {
    fn send(&self, buf: &[u8]) {
        let _ = console_transport::write(buf);
    }

    fn register_callback(&self, callback: &'static ConsoleCallback) {
        component().callbacks.lock().push(callback);
        ensure_transport_callback_registered();
    }

    fn set_mode(&self, mode: mode::ConsoleMode) -> bool {
        mode == mode::ConsoleMode::Text
    }

    fn mode(&self) -> Option<mode::ConsoleMode> {
        Some(mode::ConsoleMode::Text)
    }
}

struct Component {
    devices: SpinLock<Vec<(String, Arc<dyn AnyConsoleDevice>)>, LocalIrqDisabled>,
    callbacks: SpinLock<Vec<&'static ConsoleCallback>>,
    input_owner_id: AtomicUsize,
    next_owner_id: AtomicUsize,
    transport_callback_registered: AtomicBool,
}

impl Component {
    fn new() -> Self {
        Self {
            devices: SpinLock::new(Vec::new()),
            callbacks: SpinLock::new(Vec::new()),
            input_owner_id: AtomicUsize::new(DEFAULT_INPUT_OWNER_ID),
            next_owner_id: AtomicUsize::new(DEFAULT_INPUT_OWNER_ID + 1),
            transport_callback_registered: AtomicBool::new(false),
        }
    }
}

static COMPONENT: Once<Component> = Once::new();
static DEFAULT_DEVICE_REGISTERED: Once<()> = Once::new();

fn component() -> &'static Component {
    COMPONENT.call_once(Component::new)
}

fn ensure_default_device() {
    DEFAULT_DEVICE_REGISTERED.call_once(|| {
        register_device(
            String::from(DEFAULT_CONSOLE_NAME),
            Arc::new(VirtualConsoleDevice),
        );
    });
}

fn ensure_transport_callback_registered() {
    if component()
        .transport_callback_registered
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    if console_transport::register_input_callback(dispatch_transport_input).is_err() {
        component()
            .transport_callback_registered
            .store(false, Ordering::Release);
    }
}

fn dispatch_transport_input(bytes: &[u8]) {
    if input_is_owned_by_default() {
        return;
    }

    let callbacks = component().callbacks.lock().clone();
    for callback in callbacks {
        callback(VmReader::from(bytes));
    }
}
