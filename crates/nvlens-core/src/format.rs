//! Format trait hierarchy and compile-time registration.

use std::borrow::Cow;
use std::sync::Arc;

use nvlens_io::ArcView;

use crate::{Entry, Result};

/// Shared metadata for every format handler.
pub trait Format: Sync + Send {
    /// Unique short tag, usually the primary extension, e.g. `"arc/willv2"`.
    fn tag(&self) -> &'static str;

    /// Human-readable description (engine / origin).
    fn description(&self) -> &'static str;

    /// Possible first-4-byte signatures (little-endian `u32`); `0` means the
    /// signature is not fixed, and the format is tried as a fallback.
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }

    /// Associated extensions (lowercase, no dot), used for probe ordering and
    /// type inference.
    fn extensions(&self) -> &'static [&'static str];
}

/// An archive format: probes a raw view and opens it into enumerable entries.
pub trait ArchiveFormat: Format {
    /// Whether the archive may contain subdirectories.
    fn is_hierarchic(&self) -> bool {
        false
    }

    /// Probes and opens the archive.
    ///
    /// - `Ok(Some(_))`: matched and opened successfully;
    /// - `Ok(None)`: not this format, the probe layer tries the next candidate;
    /// - `Err(_)`: this format, but the data is corrupt.
    ///
    /// Implementations may `Arc::clone` the view into the returned [`Archive`]
    /// to support later reads.
    fn try_open(&self, view: &Arc<ArcView>) -> Result<Option<Box<dyn Archive>>>;
}

/// An opened archive instance, owning its state (index, keys, view handle).
pub trait Archive: Send {
    /// All entries.
    fn entries(&self) -> &[Entry];

    /// Opens an entry's content. Stored entries borrow the mapping with zero
    /// copy; transformed entries return an owned buffer.
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>>;
}

/// A registration record for an archive format. Each implementation submits one
/// constructor closure via [`register_archive!`].
pub struct ArchiveRegistration(pub fn() -> Box<dyn ArchiveFormat>);

impl std::fmt::Debug for ArchiveRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveRegistration").finish()
    }
}

inventory::collect!(ArchiveRegistration);

/// Registers an [`ArchiveFormat`] implementation (must implement `Default`).
///
/// ```ignore
/// register_archive!(WillV2Arc);
/// ```
#[macro_export]
macro_rules! register_archive {
    ($ty:ty) => {
        $crate::inventory::submit! {
            $crate::ArchiveRegistration(|| ::std::boxed::Box::new(<$ty as ::core::default::Default>::default()))
        }
    };
}
