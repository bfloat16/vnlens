//! Explicit archive routes and parameters supplied by engine identification.

use std::collections::BTreeMap;

use crate::ResourceKind;

/// Storage context for name-based routing. Entry kinds come from index metadata,
/// never from eagerly inspecting payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceOrigin {
    File,
    Entry(ResourceKind),
}

/// One engine-selected handler. A multiplexed container explicitly names its
/// audio and video handlers; stream metadata decides which one is needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceRoute {
    Archive(Box<ArchiveRoute>),
    Image(&'static str),
    Model(&'static str),
    Audio(&'static str),
    Script(&'static str),
    Video(&'static str),
    Media {
        audio: &'static str,
        video: &'static str,
    },
    Other(ResourceKind),
}

impl ResourceRoute {
    #[must_use]
    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::Archive(_) => ResourceKind::Archive,
            Self::Image(_) => ResourceKind::Image,
            Self::Model(_) => ResourceKind::Model,
            Self::Audio(_) | Self::Media { .. } => ResourceKind::Audio,
            Self::Script(_) => ResourceKind::Script,
            Self::Video(_) => ResourceKind::Video,
            Self::Other(kind) => *kind,
        }
    }
}

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
    /// Engine-resolved companion locations, opened only on resource requests.
    pub paths: BTreeMap<&'static str, std::path::PathBuf>,
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
