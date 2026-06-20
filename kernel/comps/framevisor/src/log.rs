// SPDX-License-Identifier: MPL-2.0

//! Kernel logging API.

use core::{
    fmt,
    sync::atomic::{AtomicU8, Ordering},
};

/// Kernel log level, matching the severity levels described in `syslog(2)`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Level {
    /// System is unusable.
    Emerg = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Crit = 2,
    /// Error conditions.
    Error = 3,
    /// Warning conditions.
    Warning = 4,
    /// Normal but significant condition.
    Notice = 5,
    /// Informational.
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

impl Level {
    /// Creates a `Level` from a numeric value.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Emerg,
            1 => Self::Alert,
            2 => Self::Crit,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad(match self {
            Self::Emerg => "EMERG",
            Self::Alert => "ALERT",
            Self::Crit => "CRIT",
            Self::Error => "ERROR",
            Self::Warning => "WARN",
            Self::Notice => "NOTICE",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        })
    }
}

/// A filter for log levels.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LevelFilter {
    /// All logging disabled.
    Off = 0,
    /// Enable Emerg only.
    Emerg = 1,
    /// Enable Emerg and Alert.
    Alert = 2,
    /// Enable Emerg through Crit.
    Crit = 3,
    /// Enable Emerg through Error.
    Error = 4,
    /// Enable Emerg through Warning.
    Warning = 5,
    /// Enable Emerg through Notice.
    Notice = 6,
    /// Enable Emerg through Info.
    Info = 7,
    /// Enable all levels.
    Debug = 8,
}

impl LevelFilter {
    /// Returns `true` if `level` passes this filter.
    #[inline]
    pub const fn is_enabled(self, level: Level) -> bool {
        (self as u8) > (level as u8)
    }

    /// Constructs a filter that enables `level` and all more-severe levels.
    pub const fn from_level(level: Level) -> Self {
        match level {
            Level::Emerg => Self::Emerg,
            Level::Alert => Self::Alert,
            Level::Crit => Self::Crit,
            Level::Error => Self::Error,
            Level::Warning => Self::Warning,
            Level::Notice => Self::Notice,
            Level::Info => Self::Info,
            Level::Debug => Self::Debug,
        }
    }

    /// Creates a `LevelFilter` from a numeric value.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Off,
            1 => Self::Emerg,
            2 => Self::Alert,
            3 => Self::Crit,
            4 => Self::Error,
            5 => Self::Warning,
            6 => Self::Notice,
            7 => Self::Info,
            _ => Self::Debug,
        }
    }
}

/// Compile-time maximum log level.
pub const STATIC_MAX_LEVEL: LevelFilter = LevelFilter::Debug;

static DYNAMIC_MAX_LEVEL: AtomicU8 = AtomicU8::new(LevelFilter::Debug as u8);

/// Sets the runtime maximum log level.
pub fn set_max_level(mut filter: LevelFilter) {
    if filter > STATIC_MAX_LEVEL {
        filter = STATIC_MAX_LEVEL;
    }

    DYNAMIC_MAX_LEVEL.store(filter as u8, Ordering::Relaxed);
}

/// Returns the current runtime maximum log level.
#[inline]
pub fn max_level() -> LevelFilter {
    LevelFilter::from_u8(DYNAMIC_MAX_LEVEL.load(Ordering::Relaxed))
}

#[doc(hidden)]
pub fn __write_log(level: Level, args: fmt::Arguments<'_>) {
    crate::console::early_print(format_args!("{level}: {args}\n"));
}

/// Logs a message at the given level.
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)+) => {{
        let __level: $crate::log::Level = $level;
        if $crate::log_enabled!(__level) {
            $crate::log::__write_log(__level, format_args!($($arg)+));
        }
    }};
}

/// Returns `true` if a message at the given level would be logged.
#[macro_export]
macro_rules! log_enabled {
    ($level:expr) => {{
        let __level: $crate::log::Level = $level;
        $crate::log::STATIC_MAX_LEVEL.is_enabled(__level)
            && $crate::log::max_level().is_enabled(__level)
    }};
}

/// Logs a message at the `Emerg` level.
#[macro_export]
macro_rules! emerg {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Emerg, $($arg)+) };
}

/// Logs a message at the `Alert` level.
#[macro_export]
macro_rules! alert {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Alert, $($arg)+) };
}

/// Logs a message at the `Crit` level.
#[macro_export]
macro_rules! crit {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Crit, $($arg)+) };
}

/// Logs a message at the `Error` level.
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Error, $($arg)+) };
}

/// Logs a message at the `Warning` level.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Warning, $($arg)+) };
}

/// Logs a message at the `Notice` level.
#[macro_export]
macro_rules! notice {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Notice, $($arg)+) };
}

/// Logs a message at the `Info` level.
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Info, $($arg)+) };
}

/// Logs a message at the `Debug` level.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => { $crate::log!($crate::log::Level::Debug, $($arg)+) };
}
