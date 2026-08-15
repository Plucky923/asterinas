// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) struct AioContextTable {
    contexts: BTreeMap<u64, u32>,
    next_context_id: Option<u64>,
}

impl AioContextTable {
    pub(super) fn new() -> Self {
        Self {
            contexts: BTreeMap::new(),
            next_context_id: Some(1),
        }
    }

    pub(super) fn create(&mut self, max_events: u32) -> Result<u64> {
        let context_id = self.next_context_id.ok_or_else(|| {
            Error::with_message(Errno::EAGAIN, "all AIO context identifiers are in use")
        })?;

        self.next_context_id = context_id.checked_add(1);
        self.contexts.insert(context_id, max_events);
        Ok(context_id)
    }

    pub(super) fn remove(&mut self, context_id: u64) -> bool {
        self.contexts.remove(&context_id).is_some()
    }
}
