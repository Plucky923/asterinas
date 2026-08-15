// SPDX-License-Identifier: MPL-2.0

//! FrameVM import and dependency policy loading.

use serde::Deserialize;

use super::types::FrameVmStageError;

const DEFAULT_POLICY: &str = include_str!("policy.toml");

#[derive(Clone, Debug, Default, Deserialize)]
pub(super) struct FrameVmPolicy {
    #[serde(default)]
    pub bundling: BundlingPolicy,
    #[serde(default)]
    pub host_symbols: HostSymbolsPolicy,
    #[serde(default)]
    pub validation: ValidationPolicy,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(super) struct BundlingPolicy {
    #[serde(default)]
    pub ordinary_rlibs: Vec<String>,
    #[serde(default)]
    pub ordinary_dependency_markers: Vec<String>,
    #[serde(default)]
    pub on_demand_rlibs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(super) struct HostSymbolsPolicy {
    #[serde(default)]
    pub rlibs: Vec<String>,
    #[serde(default)]
    pub archive_rlibs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(super) struct ValidationPolicy {
    #[serde(default)]
    pub allowed_host_dynamic_prefixes: Vec<String>,
    #[serde(default)]
    pub allowed_host_dynamic_contains: Vec<String>,
    #[serde(default)]
    pub non_host_exception_prefixes: Vec<String>,
    #[serde(default)]
    pub non_host_exception_contains: Vec<String>,
    #[serde(default)]
    pub raw_exception_symbols: Vec<String>,
}

impl FrameVmPolicy {
    pub(super) fn load_default() -> Result<Self, FrameVmStageError> {
        toml::from_str(DEFAULT_POLICY).map_err(|error| {
            FrameVmStageError::ObjectBuild(format!("failed to parse embedded policy: {error}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::FrameVmPolicy;

    #[test]
    fn policy_rlib_sets_are_consistent() {
        let policy = FrameVmPolicy::load_default().unwrap();
        let expected_markers = policy
            .bundling
            .ordinary_rlibs
            .iter()
            .map(|crate_name| format!("{crate_name}::"))
            .collect::<BTreeSet<_>>();
        let actual_markers = policy
            .bundling
            .ordinary_dependency_markers
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        assert_eq!(actual_markers, expected_markers);
        assert!(policy
            .bundling
            .ordinary_rlibs
            .iter()
            .all(|name| !policy.bundling.on_demand_rlibs.contains(name)));
        assert!(
            policy
                .host_symbols
                .rlibs
                .iter()
                .any(|name| name == "iced_x86")
        );
        assert!(
            policy
                .host_symbols
                .archive_rlibs
                .iter()
                .any(|name| name == "iced_x86")
        );
        assert!(
            policy
                .host_symbols
                .archive_rlibs
                .iter()
                .all(|name| policy.host_symbols.rlibs.contains(name))
        );
        assert!(
            !policy
                .bundling
                .ordinary_rlibs
                .iter()
                .any(|name| name == "iced_x86")
        );
    }
}
