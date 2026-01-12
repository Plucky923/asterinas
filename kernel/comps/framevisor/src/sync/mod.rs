// SPDX-License-Identifier: MPL-2.0

//! Sync primitives wrapper for FrameVM
//!
//! 包装 ostd 的同步原语，提供给 FrameVM 使用

mod wait_queue;

pub use wait_queue::WaitQueue;
