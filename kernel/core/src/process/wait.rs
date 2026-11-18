// SPDX-License-Identifier: MPL-2.0

use ostd::task::Task;

use super::{
    Pid, Process,
    process_filter::ProcessFilter,
    signal::{constants::SIGCHLD, with_sigmask_changed},
};
use crate::{
    events::IoEvents,
    prelude::*,
    process::{
        ReapedChildrenStats, Uid, pid_table,
        posix_thread::{AsPosixThread, PosixThread, ptrace::PtraceWaitStatus},
        signal::sig_num::SigNum,
        status::StopWaitStatus,
    },
    thread::{Thread, Tid},
    time::clocks::ProfClock,
};

// The definition of WaitOptions is from Occlum
bitflags! {
    pub(crate) struct WaitOptions: u32 {
        const WNOHANG = 0x1;
        const WSTOPPED = 0x2; // Same as WUNTRACED
        const WEXITED = 0x4;
        const WCONTINUED = 0x8;
        const WNOWAIT = 0x01000000;
        const WNOTHREAD = 0x20000000;
        const WALL = 0x40000000;
        const WCLONE = 0x80000000;
    }
}

impl WaitOptions {
    pub(crate) fn check(&self) -> Result<()> {
        let supported_args = WaitOptions::WNOHANG
            | WaitOptions::WSTOPPED
            | WaitOptions::WCONTINUED
            | WaitOptions::WNOWAIT;
        if !supported_args.contains(*self) {
            warn!(
                "unsupported wait options are found: {:?}",
                *self - supported_args
            );
        }

        Ok(())
    }
}

pub(crate) fn do_wait(
    child_filter: ProcessFilter,
    wait_options: WaitOptions,
    ctx: &Context,
) -> Result<Option<WaitStatus>> {
    wait_options.check()?;

    let is_nonblocking = if let ProcessFilter::WithPidfd(pid_file) = &child_filter {
        pid_file.is_nonblocking()
    } else {
        false
    };

    let zombie_child = with_sigmask_changed(
        ctx,
        |sigmask| sigmask + SIGCHLD,
        || {
            ctx.process.children_wait_queue().pause_until(|| {
                let has_unready_tracee = match try_wait_tracees(&child_filter, wait_options, ctx) {
                    WaitResult::Found(status) => return Some(Ok(Some(status))),
                    WaitResult::MatchedButUnready => true,
                    WaitResult::NoMatch => false,
                };

                let has_unready_child = match try_wait_children(&child_filter, wait_options, ctx) {
                    WaitResult::Found(status) => return Some(Ok(Some(status))),
                    WaitResult::MatchedButUnready => true,
                    WaitResult::NoMatch => false,
                };

                if !has_unready_tracee && !has_unready_child {
                    return Some(Err(Error::with_message(
                        Errno::ECHILD,
                        "the process has no child to wait",
                    )));
                }

                if wait_options.contains(WaitOptions::WNOHANG) {
                    return Some(Ok(None));
                }

                if is_nonblocking {
                    return Some(Err(Error::with_message(
                        Errno::EAGAIN,
                        "the PID file is nonblocking and the child has not terminated",
                    )));
                }

                // wait
                None
            })
        },
    )??;

    Ok(zombie_child)
}

fn wait_filter(child_pid: Pid, child: &Arc<Process>, child_filter: &ProcessFilter) -> bool {
    match &child_filter {
        ProcessFilter::Any => true,
        ProcessFilter::WithPid(pid) => child_pid == *pid,
        ProcessFilter::WithPgid(pgid) => child.pgid() == *pgid,
        ProcessFilter::WithPidfd(pid_file) => match pid_file.process_opt() {
            Some(process) => Arc::ptr_eq(&process, child),
            None => false,
        },
    }
}

pub(crate) enum WaitStatus {
    Zombie(Arc<Process>, Uid),
    Stop(Arc<Process>, Uid, SigNum),
    Continue(Arc<Process>, Uid),
    TraceeExit(Arc<Thread>),
    TraceeStop(Arc<Thread>, PtraceWaitStatus),
}

impl WaitStatus {
    pub(crate) fn pid(&self) -> Pid {
        match self.source() {
            WaitStatusSource::Process(process, _) => process.pid(),
            WaitStatusSource::Thread(thread) => thread.tid(),
        }
    }

    pub(crate) fn uid(&self) -> Uid {
        match self.source() {
            WaitStatusSource::Process(_, uid) => uid,
            WaitStatusSource::Thread(thread) => thread.credentials().ruid(),
        }
    }

    pub(crate) fn prof_clock(&self) -> &Arc<ProfClock> {
        match self.source() {
            WaitStatusSource::Process(process, _) => process.prof_clock(),
            WaitStatusSource::Thread(thread) => thread.prof_clock(),
        }
    }

    pub(crate) fn minor_faults(&self) -> u64 {
        match self.source() {
            WaitStatusSource::Process(process, _) => process
                .minor_faults()
                .saturating_add(process.reaped_children_stats().lock().minflt()),
            WaitStatusSource::Thread(_) => 0,
        }
    }

    fn source(&self) -> WaitStatusSource<'_> {
        match self {
            WaitStatus::Zombie(process, uid)
            | WaitStatus::Stop(process, uid, _)
            | WaitStatus::Continue(process, uid) => WaitStatusSource::Process(process, *uid),
            WaitStatus::TraceeExit(thread) | WaitStatus::TraceeStop(thread, _) => {
                WaitStatusSource::Thread(thread.as_posix_thread().unwrap())
            }
        }
    }
}

enum WaitStatusSource<'a> {
    Process(&'a Process, Uid),
    Thread(&'a PosixThread),
}

/// The result of trying to wait for a child/tracee state change.
enum WaitResult {
    /// A waitable status is found.
    Found(WaitStatus),
    /// At least one target matches, but none is waitable yet.
    MatchedButUnready,
    /// No target matches the wait filter.
    NoMatch,
}

/// Checks tracees for exited or ptrace-stopped threads.
fn try_wait_tracees(
    child_filter: &ProcessFilter,
    wait_options: WaitOptions,
    ctx: &Context,
) -> WaitResult {
    // Currently, we only support the main thread as the tracer,
    // so there is no need to check the tracees of other threads.
    //
    // Lock order: tracer.tracees -> tracee.tracee_status
    let Some(tracees) = ctx.posix_thread.tracees() else {
        return WaitResult::NoMatch;
    };
    let tracees = tracees.lock();

    let mut fallback_result = WaitResult::NoMatch;

    for thread in tracees.values() {
        let tracee = thread.as_posix_thread().unwrap();
        let process = tracee.process_ref();
        if process.status().is_reaped() {
            continue;
        }
        if !wait_filter(tracee.tid(), process, child_filter) {
            continue;
        }

        // We have found at least one tracee matching `child_filter`.
        fallback_result = WaitResult::MatchedButUnready;

        // Exit/death by signal is reported first to the tracer, then,
        // when the tracer consumes the waitpid(2) result, to the real
        // parent (to the real parent only when the whole multithreaded
        // process exits). If the tracer and the real parent are the same
        // process, the report is sent only once.
        //
        // Reference: <https://man7.org/linux/man-pages/man2/ptrace.2.html>
        if thread.is_exited() {
            // Lock order: tracer.tracees -> tracee_process.tasks
            if process
                .main_thread()
                .is_ok_and(|main| Arc::ptr_eq(&main, thread))
                && !process.status().is_zombie()
            {
                // Delay reporting `TraceeExit` for a process's main-thread tracee until the
                // process becomes zombie.
                //
                // This avoids a race when the main thread is the last thread to exit and its
                // tracer is also its parent: the thread has called `Thread::exit()` but
                // `ProcessStatus::set_zombie()` has not run yet, so an early wait could
                // report the same exit twice, first as `WaitStatus::TraceeExit` and
                // later as `WaitStatus::Zombie`.
                //
                // Also matches Linux behavior:
                // <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/exit.c#L1486-L1487>.
                continue;
            }

            let thread = thread.clone();
            if !wait_options.contains(WaitOptions::WNOWAIT) {
                cleanup_exited_tracee(&thread, tracees, ctx);
            }
            return WaitResult::Found(WaitStatus::TraceeExit(thread));
        }

        // Waiting for ptrace-stops does not require `WaitOptions::WSTOPPED`.
        if let Some(sig_num) = tracee.wait_ptrace_stopped(wait_options) {
            return WaitResult::Found(WaitStatus::TraceeStop(thread.clone(), sig_num));
        }
    }

    fallback_result
}

fn cleanup_exited_tracee(
    thread: &Arc<Thread>,
    mut tracees: MutexGuard<BTreeMap<Tid, Arc<Thread>>>,
    ctx: &Context,
) {
    let tracee = thread.as_posix_thread().unwrap();
    let process = tracee.process_ref();
    tracees.remove(&tracee.tid());
    tracee.detach_tracer();
    drop(tracees);

    if !process.status().is_zombie() {
        return;
    }
    if !process
        .main_thread()
        .is_ok_and(|main| Arc::ptr_eq(&main, thread))
    {
        return;
    }
    let tracee_parent = process.parent().lock().process().clone();
    let is_our_child = core::ptr::eq(Weak::as_ptr(&tracee_parent), Arc::as_ptr(&ctx.process));
    if !is_our_child {
        if let Some(parent) = tracee_parent.upgrade() {
            parent.children_wait_queue().wake_all();
        }
        return;
    }

    let main_task = {
        let mut children = ctx.process.children().lock();
        reap_zombie_child(
            process,
            children.as_mut().unwrap(),
            ctx.process.reaped_children_stats(),
        )
    };
    if let Some(main_task) = main_task {
        process.pidfile_pollee.notify(IoEvents::HUP);
        drop(main_task);
    }
}

/// Checks children for zombie or stopped/continued events.
fn try_wait_children(
    child_filter: &ProcessFilter,
    wait_options: WaitOptions,
    ctx: &Context,
) -> WaitResult {
    // Acquire the children lock at first to prevent race conditions.
    // We want to ensure that multiple waiting threads
    // do not return the same waited process status.
    let mut children_lock = ctx.process.children().lock();
    let children_mut = children_lock.as_mut().unwrap();

    let mut fallback_result = WaitResult::NoMatch;

    for child in children_mut.values() {
        if !wait_filter(child.pid(), child, child_filter) {
            continue;
        }

        // We have found at least one child matching `child_filter`.
        fallback_result = WaitResult::MatchedButUnready;

        let main_thread = child.main_thread().unwrap();
        let posix_thread = main_thread.as_posix_thread().unwrap();
        if posix_thread.is_traced() {
            continue;
        }

        if child.status().is_zombie() {
            let child = child.clone();
            let uid = posix_thread.credentials().ruid();
            if !wait_options.contains(WaitOptions::WNOWAIT) {
                let main_task =
                    reap_zombie_child(&child, children_mut, ctx.process.reaped_children_stats());
                drop(children_lock);
                child.pidfile_pollee.notify(IoEvents::HUP);
                drop(main_task);
            }
            return WaitResult::Found(WaitStatus::Zombie(child, uid));
        }

        if !wait_options.intersects(WaitOptions::WSTOPPED | WaitOptions::WCONTINUED) {
            continue;
        }
        let Some(stop_wait_status) = child.wait_stopped_or_continued(wait_options) else {
            continue;
        };
        let uid = posix_thread.credentials().ruid();
        let wait_status = match stop_wait_status {
            StopWaitStatus::Stopped(sig_num) => WaitStatus::Stop(child.clone(), uid, sig_num),
            StopWaitStatus::Continue => WaitStatus::Continue(child.clone(), uid),
        };
        return WaitResult::Found(wait_status);
    }

    fallback_result
}

/// Reaps a zombie and returns its main task for the caller to drop after releasing the locks.
fn reap_zombie_child(
    child_process: &Arc<Process>,
    children_lock: &mut BTreeMap<Pid, Arc<Process>>,
    reaped_children_stats: &Mutex<ReapedChildrenStats>,
) -> Option<Arc<Task>> {
    let child_pid = child_process.pid();
    // The real parent may reap this tracee after its tracer detaches.
    if !children_lock
        .get(&child_pid)
        .is_some_and(|child| Arc::ptr_eq(child, child_process))
    {
        return None;
    }
    children_lock.remove(&child_pid);
    assert!(child_process.status().is_zombie());

    let mut pid_table = pid_table::pid_table_mut();

    // Lock order: children of process -> PID table -> tasks of process
    pid_table.remove_process(child_pid);
    let main_task = child_process.tasks().lock().reap_main();
    debug_assert_eq!(main_task.as_posix_thread().unwrap().tid(), child_pid);
    child_process.status().set_reaped();

    // Lock order: children of process -> PID table
    // -> group of process -> group inner -> session inner

    // Remove the process group and the session from global table, if necessary
    let mut child_group_mut = child_process.process_group.lock();
    child_process.clear_old_group_and_session(&mut child_group_mut, &mut pid_table);

    let (mut user_time, mut kernel_time, child_minflt) = {
        let stats = child_process.reaped_children_stats().lock();
        let (ut, kt) = stats.get();
        (ut, kt, stats.minflt())
    };
    user_time += child_process.prof_clock().user_clock().read_time();
    kernel_time += child_process.prof_clock().kernel_clock().read_time();
    let total_minflt = child_process.minor_faults().saturating_add(child_minflt);
    reaped_children_stats
        .lock()
        .add(user_time, kernel_time, total_minflt);

    Some(main_task)
}
