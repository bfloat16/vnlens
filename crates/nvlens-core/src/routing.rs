//! Explicit archive routes and parameters supplied by engine identification.

use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveOptions {
    pub keys: BTreeMap<&'static str, Secret>,
    pub numbers: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveRoute {
    pub tag: &'static str,
    pub options: ArchiveOptions,
}

impl ArchiveRoute {
    #[must_use]
    pub fn new(tag: &'static str) -> Self {
        Self {
            tag,
            options: ArchiveOptions::default(),
        }
    }
}
