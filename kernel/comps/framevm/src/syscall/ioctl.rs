// SPDX-License-Identifier: MPL-2.0

use ostd::{
    mm::VmSpace,
    sync::{Once, SpinLock},
};

use super::{
    Errno, Error, FdFlags, Result, StatusFlags, current_fd_file, current_fd_table,
    read_fixed_from_user, read_i32_from_user, with_current_user_task_data, write_to_user,
};
use crate::{
    fd_table::FileDesc,
    process::{foreground_process_group, set_controlling_terminal, set_foreground_process_group},
};

const TERMIOS_SIZE: usize = 36;
const WINSIZE_SIZE: usize = 8;
const FIONCLEX: usize = 0x5450;
const FIOCLEX: usize = 0x5451;
const FIONBIO: usize = 0x5421;
const FIOASYNC: usize = 0x5452;
const FIONREAD: usize = 0x541B;

struct ConsoleTerminalState {
    termios: SpinLock<[u8; TERMIOS_SIZE]>,
    winsize: SpinLock<[u8; WINSIZE_SIZE]>,
}

static CONSOLE_TERMINAL_STATE: Once<ConsoleTerminalState> = Once::new();

/// Handles terminal ioctl operations.
pub(super) fn sys_ioctl(fd: i32, request: usize, arg: usize, vm_space: &VmSpace) -> Result<isize> {
    if handle_fd_ioctl(fd, request)? {
        return Ok(0);
    }

    if handle_file_ioctl(fd, request, arg, vm_space)? {
        return Ok(0);
    }

    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    if request == FIONREAD {
        let bytes_to_read = file.bytes_to_read()?.min(i32::MAX as usize) as i32;
        write_to_user(vm_space, arg, &bytes_to_read.to_ne_bytes())?;
        return Ok(0);
    }

    if !file.is_terminal() {
        return Err(Error::new(Errno::ENOTTY));
    }

    const TCGETS: usize = 0x5401;
    const TCSETS: usize = 0x5402;
    const TCSETSW: usize = 0x5403;
    const TCSETSF: usize = 0x5404;
    const TIOCGWINSZ: usize = 0x5413;
    const TIOCSWINSZ: usize = 0x5414;
    const TIOCSCTTY: usize = 0x540E;
    const TIOCGPGRP: usize = 0x540F;
    const TIOCSPGRP: usize = 0x5410;

    match request {
        TCGETS => {
            let termios = *console_terminal_state().termios.lock();
            write_to_user(vm_space, arg, &termios)?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let termios = read_fixed_from_user::<TERMIOS_SIZE>(vm_space, arg)?;
            *console_terminal_state().termios.lock() = termios;
            Ok(0)
        }
        TIOCSCTTY => with_current_user_task_data(|task_data| {
            set_controlling_terminal(&task_data.process);
            Ok(0)
        }),
        TIOCGPGRP => {
            let foreground_pgid = foreground_process_group() as i32;
            write_to_user(vm_space, arg, &foreground_pgid.to_ne_bytes())?;
            Ok(0)
        }
        TIOCSPGRP => {
            let pgid = read_i32_from_user(vm_space, arg)?;
            with_current_user_task_data(|task_data| {
                set_foreground_process_group(&task_data.process, pgid)?;
                Ok(0)
            })?;
            Ok(0)
        }
        TIOCGWINSZ => {
            let winsize = *console_terminal_state().winsize.lock();
            write_to_user(vm_space, arg, &winsize)?;
            Ok(0)
        }
        TIOCSWINSZ => {
            let winsize = read_fixed_from_user::<WINSIZE_SIZE>(vm_space, arg)?;
            *console_terminal_state().winsize.lock() = winsize;
            Ok(0)
        }
        _ => Err(Error::new(Errno::ENOTTY)),
    }
}

fn handle_fd_ioctl(fd: i32, request: usize) -> Result<bool> {
    let set_close_on_exec = match request {
        FIONCLEX => false,
        FIOCLEX => true,
        _ => return Ok(false),
    };

    let fd = FileDesc::try_from(fd)?;
    let fd_table = current_fd_table()?;
    let fd_table = fd_table.lock();
    let entry = fd_table.get_entry(fd)?;
    let mut flags = entry.flags();
    flags.set(FdFlags::CLOEXEC, set_close_on_exec);
    entry.set_flags(flags);
    Ok(true)
}

fn handle_file_ioctl(fd: i32, request: usize, arg: usize, vm_space: &VmSpace) -> Result<bool> {
    let status_flag = match request {
        FIONBIO => StatusFlags::O_NONBLOCK,
        FIOASYNC => StatusFlags::O_ASYNC,
        _ => return Ok(false),
    };

    let fd = FileDesc::try_from(fd)?;
    let file = {
        let fd_table = current_fd_table()?;
        fd_table.lock().get_file(fd)?
    };
    let enabled = read_i32_from_user(vm_space, arg)? != 0;
    let mut status_flags = file.status_flags();
    status_flags.set(status_flag, enabled);
    file.set_status_flags(status_flags)?;
    Ok(true)
}

fn console_terminal_state() -> &'static ConsoleTerminalState {
    CONSOLE_TERMINAL_STATE.call_once(|| ConsoleTerminalState {
        termios: SpinLock::new(default_termios()),
        winsize: SpinLock::new(default_winsize()),
    })
}

fn default_termios() -> [u8; TERMIOS_SIZE] {
    const ICRNL: u32 = 0x100;
    const IXON: u32 = 0x400;
    const OPOST: u32 = 0x1;
    const ONLCR: u32 = 0x4;
    const B38400: u32 = 0xf;
    const CS8: u32 = 0x30;
    const CREAD: u32 = 0x80;
    const ISIG: u32 = 0x1;
    const ICANON: u32 = 0x2;
    const ECHO: u32 = 0x8;
    const ECHOE: u32 = 0x10;
    const ECHOK: u32 = 0x20;
    const ECHOCTL: u32 = 0x200;
    const ECHOKE: u32 = 0x800;
    const IEXTEN: u32 = 0x8000;

    let mut termios = [0u8; 36];
    termios[0..4].copy_from_slice(&(ICRNL | IXON).to_ne_bytes());
    termios[4..8].copy_from_slice(&(OPOST | ONLCR).to_ne_bytes());
    termios[8..12].copy_from_slice(&(B38400 | CS8 | CREAD).to_ne_bytes());
    termios[12..16].copy_from_slice(
        &(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN).to_ne_bytes(),
    );

    let control_chars = [
        3u8, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
    ];
    termios[17..36].copy_from_slice(&control_chars);
    termios
}

fn default_winsize() -> [u8; WINSIZE_SIZE] {
    let mut winsize = [0u8; WINSIZE_SIZE];
    winsize[0..2].copy_from_slice(&24u16.to_ne_bytes());
    winsize[2..4].copy_from_slice(&80u16.to_ne_bytes());
    winsize
}
