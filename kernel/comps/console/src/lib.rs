// SPDX-License-Identifier: MPL-2.0

//! The console device of Asterinas.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod font;
pub mod mode;

use alloc::{collections::BTreeMap, fmt::Debug, string::String, sync::Arc, vec::Vec};
use core::{
    any::Any,
    sync::atomic::{AtomicUsize, Ordering},
};

use component::{ComponentInitError, init_component};
use ostd::{
    mm::{Infallible, VmReader},
    sync::{LocalIrqDisabled, SpinLock, SpinLockGuard},
};
use spin::Once;

pub type ConsoleCallback = dyn Fn(VmReader<Infallible>) + Send + Sync;

const DEFAULT_INPUT_OWNER_ID: usize = 0;

/// Identifies a consumer that may own console input delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputOwner(usize);

impl InputOwner {
    /// Returns the default input owner used by the host kernel TTY path.
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

// TODO: Refactor `AnyConsoleDevice`; this interface should not include
// VT-specific mode operations.
pub trait AnyConsoleDevice: Send + Sync + Any + Debug {
    /// Sends data to the console device.
    fn send(&self, buf: &[u8]);

    /// Registers a callback that will be invoked when the console device receives data.
    ///
    /// The callback may be called in the interrupt context. Therefore, it should _never_ sleep.
    fn register_callback(&self, callback: &'static ConsoleCallback);

    /// Sets the font of the console device.
    fn set_font(&self, _font: font::BitmapFont) -> Result<(), ConsoleSetFontError> {
        Err(ConsoleSetFontError::InappropriateDevice)
    }

    // TODO: Add support for getting the font of the console device.

    /// Sets the console mode (text or graphics, see [`mode::ConsoleMode`]).
    ///
    /// Returns true if the mode was changed, false if the mode is not supported.
    #[must_use]
    fn set_mode(&self, _mode: mode::ConsoleMode) -> bool {
        false
    }

    /// Gets the current console mode.
    ///
    /// Returns the current console mode, or `None` if mode switching is not supported.
    fn mode(&self) -> Option<mode::ConsoleMode> {
        None
    }

    /// Sets the keyboard mode (see [`mode::KeyboardMode`]).
    ///
    /// Returns true if the mode was changed, false if the mode is not supported.
    #[must_use]
    fn set_keyboard_mode(&self, _mode: mode::KeyboardMode) -> bool {
        false
    }

    /// Gets the current keyboard mode.
    ///
    /// Returns the current keyboard mode, or `None` if mode switching is not supported.
    fn keyboard_mode(&self) -> Option<mode::KeyboardMode> {
        None
    }
}

pub fn register_device(name: String, device: Arc<dyn AnyConsoleDevice>) {
    COMPONENT
        .get()
        .unwrap()
        .console_device_table
        .lock()
        .insert(name, device);
}

pub fn all_devices() -> Vec<(String, Arc<dyn AnyConsoleDevice>)> {
    let console_devices = COMPONENT.get().unwrap().console_device_table.lock();
    console_devices
        .iter()
        .map(|(name, device)| (name.clone(), device.clone()))
        .collect()
}

pub fn all_devices_lock<'a>()
-> SpinLockGuard<'a, BTreeMap<String, Arc<dyn AnyConsoleDevice>>, LocalIrqDisabled> {
    COMPONENT.get().unwrap().console_device_table.lock()
}

/// Allocates a new console input owner.
pub fn alloc_input_owner() -> InputOwner {
    let id = COMPONENT
        .get()
        .unwrap()
        .next_input_owner_id
        .fetch_add(1, Ordering::Relaxed);
    InputOwner(id)
}

/// Routes subsequent console input to `owner`.
pub fn acquire_input(owner: InputOwner) {
    COMPONENT
        .get()
        .unwrap()
        .input_owner_id
        .store(owner.0, Ordering::Release);
}

/// Releases console input if it is currently owned by `owner`.
pub fn release_input(owner: InputOwner) {
    let _ = COMPONENT.get().unwrap().input_owner_id.compare_exchange(
        owner.0,
        DEFAULT_INPUT_OWNER_ID,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

/// Returns whether console input is currently owned by `owner`.
pub fn input_is_owned_by(owner: InputOwner) -> bool {
    COMPONENT
        .get()
        .unwrap()
        .input_owner_id
        .load(Ordering::Acquire)
        == owner.0
}

/// Returns whether console input is currently routed to the host kernel TTY path.
pub fn input_is_owned_by_default() -> bool {
    input_is_owned_by(InputOwner::default())
}

static COMPONENT: Once<Component> = Once::new();

#[init_component]
fn component_init() -> Result<(), ComponentInitError> {
    let component = Component::init()?;
    COMPONENT.call_once(|| component);
    Ok(())
}

#[derive(Debug)]
struct Component {
    console_device_table: SpinLock<BTreeMap<String, Arc<dyn AnyConsoleDevice>>, LocalIrqDisabled>,
    input_owner_id: AtomicUsize,
    next_input_owner_id: AtomicUsize,
}

impl Component {
    pub fn init() -> Result<Self, ComponentInitError> {
        Ok(Self {
            console_device_table: SpinLock::new(BTreeMap::new()),
            input_owner_id: AtomicUsize::new(DEFAULT_INPUT_OWNER_ID),
            next_input_owner_id: AtomicUsize::new(DEFAULT_INPUT_OWNER_ID + 1),
        })
    }
}
