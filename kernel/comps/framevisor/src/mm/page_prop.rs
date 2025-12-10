use ostd::mm::{
    CachePolicy as OstdCachePolicy, PageFlags as OstdPageFlags, PageProperty as OstdPageProperty,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageProperty(OstdPageProperty);

impl PageProperty {
    pub fn new_user(flags: PageFlags, cache: CachePolicy) -> Self {
        Self(OstdPageProperty::new_user(flags, cache))
    }

    pub fn inner(self) -> OstdPageProperty {
        self.0
    }
}

pub type PageFlags = OstdPageFlags;
pub type CachePolicy = OstdCachePolicy;
