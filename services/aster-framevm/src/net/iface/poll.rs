// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use ostd::{debug, sync::SpinLock, timer::Jiffies};
use spin::Once;

use super::{Iface, iter_all_ifaces};
use crate::{
    sched::{Nice, SchedPolicy},
    thread::{Thread, kernel_thread::ThreadOptions},
    time::wait::WaitTimeout,
};

static POLL_THREADS: Once<SpinLock<Option<Vec<Arc<Thread>>>>> = Once::new();
static IS_STOPPING: AtomicBool = AtomicBool::new(false);

pub fn init_in_first_kthread() {
    let poll_threads = POLL_THREADS.call_once(|| SpinLock::new(None));
    if poll_threads.lock().is_some() {
        return;
    }

    let threads = iter_all_ifaces()
        .map(|iface| spawn_background_poll_thread(iface.clone()))
        .collect();
    let mut registered_threads = poll_threads.lock();
    if registered_threads.is_none() {
        *registered_threads = Some(threads);
    }
}

/// Starts shutdown of every network polling thread owned by this FrameVM.
///
/// The service poweroff caller runs on a FrameVM vCPU. Joining the polling
/// threads there can prevent those threads from being scheduled to observe the
/// stop request. Their static handles remain valid during the drain phase;
/// FrameVisor keeps the service image mapped until the polling functions have
/// returned.
pub(crate) fn shutdown() {
    IS_STOPPING.store(true, Ordering::Release);
    for iface in iter_all_ifaces() {
        iface.sched_poll().polling_wait_queue().wake_all();
    }
}

pub(super) fn poll_ifaces() {
    for iface in iter_all_ifaces() {
        iface.poll();
    }
}

fn spawn_background_poll_thread(iface: Arc<Iface>) -> Arc<Thread> {
    let task_fn = move || {
        debug!("spawn background poll thread for {:?}", iface.name());

        let sched_poll = iface.sched_poll();
        let wait_queue = sched_poll.polling_wait_queue();

        loop {
            if IS_STOPPING.load(Ordering::Acquire) {
                break;
            }
            let next_poll_at_ms = if let Some(next_poll_at_ms) = sched_poll.next_poll_at_ms() {
                next_poll_at_ms
            } else {
                wait_queue.wait_until(|| {
                    if IS_STOPPING.load(Ordering::Acquire) {
                        return Some(0);
                    }
                    sched_poll.next_poll_at_ms()
                })
            };

            if IS_STOPPING.load(Ordering::Acquire) {
                break;
            }

            let now_as_ms = Jiffies::elapsed().as_duration().as_millis() as u64;

            // FIXME: Ideally, we should perform the `poll` just before `next_poll_at_ms`.
            // However, this approach may result in a spinning busy loop
            // if the `poll` operation yields no results.
            // To mitigate this issue,
            // we have opted to assign a high priority to the polling thread,
            // ensuring that the `poll` runs as soon as possible.
            // For a more in-depth discussion, please refer to the following link:
            // <https://github.com/asterinas/asterinas/pull/630#discussion_r1496817030>.
            if now_as_ms >= next_poll_at_ms {
                iface.poll();
                continue;
            }

            let duration = Duration::from_millis(next_poll_at_ms - now_as_ms);
            let _ = wait_queue.wait_until_or_timeout(
                // If `sched_poll.next_poll_at_ms()` changes to an earlier time, we will end the
                // waiting.
                || {
                    if IS_STOPPING.load(Ordering::Acquire) {
                        return Some(());
                    }
                    (sched_poll.next_poll_at_ms()? < next_poll_at_ms).then_some(())
                },
                &duration,
            );
        }
    };

    ThreadOptions::new(task_fn)
        .sched_policy(SchedPolicy::Fair(Nice::MIN))
        .spawn()
}
