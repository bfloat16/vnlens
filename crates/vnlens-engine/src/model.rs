//! Immutable identification results. Secret material is redacted in Debug.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// A recognized NS filesystem host; proprietary game formats still require
    /// their own engine evidence and are never guessed from container payloads.
    NintendoSwitch,
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
    EntisGls,
    Csystem,
    Siglus,
    RealLive,
    Kaleido,
    Krkr,
    KrkrzHxv4,
    Mages,
    Otomate,
    Gss,
    NScripter,
    Tamsoft,
    Artemis,
}

#[derive(Clone, Debug)]
pub struct Identification {
    pub root: PathBuf,
    pub engine: Engine,
    pub evidence: String,
    pub files: std::sync::Arc<vnlens_io::FileSystem>,
    pub(crate) options: ArchiveOptions,
    pub(crate) middleware: Vec<&'static crate::routing::Router>,
    pub(crate) compose_pimg: Arc<AtomicBool>,
}

impl Identification {
    /// Selects PIMG image composition for this host's shared game context.
    /// Cloned contexts and mounted archives observe the same setting.
    pub fn set_compose_pimg(&self, enabled: bool) {
        self.compose_pimg.store(enabled, Ordering::Relaxed);
    }

    /// Whether this engine context permits PSB containers, including unnamed
    /// entries whose logical headers are read only after selection.
    #[must_use]
    pub fn supports_psb(&self) -> bool {
        matches!(
            self.resource_route("", ResourceOrigin::Entry(ResourceKind::Unknown), b"PSB\0"),
            ResourceRoute::Archive(_)
        )
    }

    /// Parameters shared with resource decoders; Debug redacts all keys.
    #[must_use]
    pub fn resource_options(&self) -> &ArchiveOptions {
        &self.options
    }
}
