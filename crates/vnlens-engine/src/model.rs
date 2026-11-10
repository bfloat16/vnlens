//! Immutable identification results. Secret material is redacted in Debug.

use std::path::PathBuf;
use vnlens_core::ArchiveOptions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Propeller,
    Rugp,
    Escude,
    SystemNnn,
    Exhibit,
    Yuris,
    Will,
    AgesMk2,
    Bgi,
    Softpal,
    Csystem,
    Siglus,
    Kaleido,
    Krkr,
    KrkrzHxv4,
}

#[derive(Clone, Debug)]
pub struct Identification {
    pub root: PathBuf,
    pub engine: Engine,
    pub evidence: String,
    pub files: std::sync::Arc<vnlens_io::FileSystem>,
    pub(crate) options: ArchiveOptions,
    pub(crate) emote: bool,
}

impl Identification {
    /// Parameters shared with resource decoders; Debug redacts all keys.
    #[must_use]
    pub fn resource_options(&self) -> &ArchiveOptions {
        &self.options
    }
}
