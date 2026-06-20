// SPDX-License-Identifier: MPL-2.0

//! Modes and flags for the console and keyboard.

use int_to_c_enum::TryFromInt;

/// The console mode.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub enum ConsoleMode {
    /// The text mode.
    Text = 0,
    /// The graphics mode.
    Graphics = 1,
}

/// The keyboard mode.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub enum KeyboardMode {
    /// The scancode mode.
    Raw = 0,
    /// The ASCII mode.
    Xlate = 1,
    /// The keycode mode.
    MediumRaw = 2,
    /// The Unicode mode.
    Unicode = 3,
    /// The off mode.
    Off = 4,
}

bitflags::bitflags! {
    /// The keyboard mode flags.
    pub struct KeyboardModeFlags: u8 {
        /// The application key mode.
        const APPLICATION = 1 << 0;
        /// The cursor key mode.
        const CURSOR_KEY = 1 << 1;
        /// The repeat mode.
        const REPEAT = 1 << 2;
        /// The CRLF mode.
        const CRLF = 1 << 3;
        /// The meta key mode.
        const META = 1 << 4;
    }
}
