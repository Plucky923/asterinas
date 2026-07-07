// SPDX-License-Identifier: MPL-2.0

//! Kernel logging API.

use core::{
    fmt,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::sync::Once;

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

static LOGGER: Once<&'static dyn Log> = Once::new();

/// Registers the global logger backend.
pub fn inject_logger(logger: &'static dyn Log) {
    LOGGER.call_once(|| logger);
}

#[inline]
fn logger() -> Option<&'static dyn Log> {
    LOGGER.get().copied()
}

/// Writes a log record to the registered logger or early console.
#[doc(hidden)]
pub fn __write_log_record(record: &Record<'_>) {
    if let Some(logger) = logger() {
        logger.log(record);
    } else {
        crate::console::early_print(format_args!(
            "{}: {}{}\n",
            record.level(),
            record.prefix(),
            record.args()
        ));
    }
}

/// The logger backend trait.
pub trait Log: Sync + Send {
    /// Logs a record.
    fn log(&self, record: &Record<'_>);
}

/// A single log record carrying level, message, and source location.
pub struct Record<'a> {
    level: Level,
    prefix: &'static str,
    args: fmt::Arguments<'a>,
    module_path: &'static str,
    file: &'static str,
    line: u32,
}

impl<'a> Record<'a> {
    /// Creates a new log record.
    #[doc(hidden)]
    #[inline]
    pub fn new(
        level: Level,
        prefix: &'static str,
        args: fmt::Arguments<'a>,
        module_path: &'static str,
        file: &'static str,
        line: u32,
    ) -> Self {
        Self {
            level,
            prefix,
            args,
            module_path,
            file,
            line,
        }
    }

    /// Returns the log level.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Returns the per-module log prefix.
    pub fn prefix(&self) -> &'static str {
        self.prefix
    }

    /// Returns the formatted message arguments.
    pub fn args(&self) -> &fmt::Arguments<'a> {
        &self.args
    }

    /// Returns the full module path where the log call originated.
    pub fn module_path(&self) -> &'static str {
        self.module_path
    }

    /// Returns the source file path.
    pub fn file(&self) -> &'static str {
        self.file
    }

    /// Returns the source line number.
    pub fn line(&self) -> u32 {
        self.line
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
    sync_log_crate_max_level(filter);
}

/// Returns the current runtime maximum log level.
#[inline]
pub fn max_level() -> LevelFilter {
    LevelFilter::from_u8(DYNAMIC_MAX_LEVEL.load(Ordering::Relaxed))
}

fn sync_log_crate_max_level(filter: LevelFilter) {
    ::log::set_max_level(map_level_filter(filter));
}

pub(crate) fn init_from_cmdline(kernel_cmdline: &str) {
    let filter = parse_log_level_from_cmdline(kernel_cmdline).unwrap_or(LevelFilter::Off);
    set_max_level(filter);

    static BRIDGE: LogCrateBridge = LogCrateBridge;
    let _ = ::log::set_logger(&BRIDGE);
}

fn parse_log_level_from_cmdline(kernel_cmdline: &str) -> Option<LevelFilter> {
    let value = kernel_cmdline
        .split(' ')
        .find(|arg| arg.starts_with("ostd.log_level="))
        .map(|arg| arg.split('=').next_back().unwrap_or_default())?;

    parse_level_str(value)
}

fn parse_level_str(level: &str) -> Option<LevelFilter> {
    match level {
        "off" => Some(LevelFilter::Off),
        "emerg" => Some(LevelFilter::Emerg),
        "alert" => Some(LevelFilter::Alert),
        "crit" => Some(LevelFilter::Crit),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warning),
        "notice" => Some(LevelFilter::Notice),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        _ => None,
    }
}

struct LogCrateBridge;

impl ::log::Log for LogCrateBridge {
    fn enabled(&self, _metadata: &::log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &::log::Record) {
        if let Some(logger) = logger() {
            let level = map_log_level(record.level());
            logger.log(&Record::new(
                level,
                "",
                *record.args(),
                record.module_path_static().unwrap_or(""),
                record.file_static().unwrap_or(""),
                record.line().unwrap_or(0),
            ));
        }
    }

    fn flush(&self) {}
}

fn map_log_level(level: ::log::Level) -> Level {
    match level {
        ::log::Level::Error => Level::Error,
        ::log::Level::Warn => Level::Warning,
        ::log::Level::Info => Level::Info,
        ::log::Level::Debug => Level::Debug,
        ::log::Level::Trace => Level::Debug,
    }
}

fn map_level_filter(filter: LevelFilter) -> ::log::LevelFilter {
    match filter {
        LevelFilter::Off => ::log::LevelFilter::Off,
        LevelFilter::Emerg | LevelFilter::Alert | LevelFilter::Crit | LevelFilter::Error => {
            ::log::LevelFilter::Error
        }
        LevelFilter::Warning => ::log::LevelFilter::Warn,
        LevelFilter::Notice | LevelFilter::Info => ::log::LevelFilter::Info,
        LevelFilter::Debug => ::log::LevelFilter::Trace,
    }
}

/// Logs a message at the given level.
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)+) => {{
        const __LEVEL: $crate::log::Level = $level;
        if $crate::log_enabled!(__LEVEL) {
            $crate::log::__write_log_record(&$crate::log::Record::new(
                __LEVEL,
                __log_prefix!(),
                format_args!($($arg)+),
                module_path!(),
                file!(),
                line!(),
            ));
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
