//! Page-property wrappers exposed through the OSTD-compatible surface.

use host_ostd::mm::{
    CachePolicy as OstdCachePolicy, PageFlags as OstdPageFlags, PageProperty as OstdPageProperty,
};

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

    pub(crate) fn new_with_inner(prop: OstdPageProperty) -> Self {
        Self {
            flags: prop.flags,
            cache: prop.cache,
        }
    }

    pub(crate) fn inner(self) -> OstdPageProperty {
        OstdPageProperty::new_user(self.flags, self.cache)
    }
}

pub type PageFlags = OstdPageFlags;
pub type CachePolicy = OstdCachePolicy;
