use core::fmt::Debug;

use ostd::util::id_set::{Id as OstdId, IdSet as OstdIdSet};

pub trait Id {
    type Inner: OstdId;
}

pub struct IdSet<I: Id>(OstdIdSet<I::Inner>);

impl<I: Id> IdSet<I> {
    pub fn new_full() -> Self {
        Self(OstdIdSet::new_full())
    }

    pub fn new_empty() -> Self {
        Self(OstdIdSet::new_empty())
    }
}
