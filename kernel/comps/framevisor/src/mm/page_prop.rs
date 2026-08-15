//! Page-property wrappers exposed through the OSTD-compatible surface.

use host_ostd::mm::{CachePolicy as OstdCachePolicy, PageFlags as OstdPageFlags};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageProperty {
    /// The flags associated with the page.
    pub flags: PageFlags,
    /// The cache policy for the page.
    pub cache: CachePolicy,
}

impl PageProperty {
    pub fn new_user(flags: PageFlags, cache: CachePolicy) -> Self {
        Self { flags, cache }
    }
}

pub type PageFlags = OstdPageFlags;
pub type CachePolicy = OstdCachePolicy;
