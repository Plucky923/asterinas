// SPDX-License-Identifier: MPL-2.0

//! 简化版 Pollee for FrameVM
//!
//! 提供基于 WaitQueue 的事件等待和唤醒机制，用于 FrameVM 的 socket 阻塞等待。

use aster_framevisor::sync::WaitQueue;

pub struct Pollee {
    wait_queue: WaitQueue,
}

impl Pollee {
    /// 创建新的 Pollee
    pub fn new() -> Self {
        Self {
            wait_queue: WaitQueue::new(),
        }
    }

    /// 通知有事件到达，唤醒所有等待的任务
    pub fn notify(&self) {
        self.wait_queue.wake_all();
    }

    /// 等待直到条件满足
    ///
    /// 此方法会阻塞当前任务，直到 `cond` 返回 `Some(R)`。
    ///
    /// # 参数
    /// - `cond`: 检查条件的闭包。如果返回 `Some(R)`，则停止等待并返回结果。
    pub fn wait_until<F, R>(&self, cond: F) -> R
    where
        F: FnMut() -> Option<R>,
    {
        self.wait_queue.wait_until(cond)
    }
}
