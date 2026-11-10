//! Format trait hierarchy and compile-time registration.

use std::borrow::Cow;
use std::sync::Arc;

use vnlens_io::ArcView;

use crate::{ArchiveOptions, Entry, Result};

/// Shared metadata for every format handler.
///
/// The metadata methods are declared in a fixed order — tag, signatures, extensions,
/// description — and every implementation must state all of them (there are no
/// defaults) so that each format documents its own identifying data.
pub trait Format: Sync + Send {
    /// Unique short tag, usually the primary extension, e.g. `"arc/willv2"`.
    fn tag(&self) -> &'static str;

    /// Possible first-4-byte magic signatures (little-endian `u32`). Return
    /// `&[0]` when the format has no fixed magic and is recognized by
    /// structure instead.
    fn signatures(&self) -> &'static [u32];

    /// Associated extensions (lowercase, no dot), used for metadata. Archive
    /// dispatch uses an identified route rather than these extensions.
    fn extensions(&self) -> &'static [&'static str];

    /// Human-readable description (engine / origin).
    fn description(&self) -> &'static str;
}

/// A directed archive reader. Engine identification selects exactly one reader.
pub trait ArchiveFormat: Format {
    /// Opens the selected format with resolved engine parameters. Structural
    /// mismatches are errors; they never trigger another format reader.
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>>;
}

/// An opened archive instance, owning its state (index, keys, view handle).
pub trait Archive: Send {
    /// All entries.
    fn entries(&self) -> &[Entry];

    /// Opens logical resource bytes after archive and embedded-resource
    /// transformations. Hosts must not apply the disk resource envelope again.
    /// Stored entries borrow the mapping; transformed entries own their buffer.
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>>;

    /// Opens the same logical bytes as open_entry, with independent streaming
    /// cursors. Formats return None when they do not yet provide a streaming
    /// resource path with the same transformations.
    fn open_entry_source(&self, _entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        Ok(None)
    }

    /// Opens an entry's raw stored content when a format can expose it.
    ///
    /// The default preserves compatibility for formats without a distinct raw
    /// path. Container formats may override this to skip decompression,
    /// decryption, decoding, or nested shell conversion.
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.open_entry(entry)
    }

    /// Resolves optional original script paths, indexed by `entries()` position.
    /// Called only when the host explicitly requests virtual paths. Implementations
    /// may read the necessary mapping metadata, but must not scan entry payloads.
    /// Unmapped entries retain their stored names; reading always uses the original entry.
    fn virtual_paths(&self) -> Result<Vec<(usize, String)>> {
        Ok(Vec::new())
    }
    /// Reads a named dependency outside this archive using engine-resolved
    /// locations. This is called only after the host's local lookup misses.
    fn read_companion(&self, _name: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Whether an entry may expose a lazily indexed object-reference container.
    /// This is metadata only: implementations must not read its payload here.
    fn has_references(&self, _entry: &Entry) -> bool {
        false
    }

    /// Opens references declared by one explicitly selected object. Their
    /// payloads remain lazy, and the returned archive retains its source views.
    /// Returns None when a possible reference owner has no stored children.
    fn open_references(&self, _entry: &Entry) -> Result<Option<Box<dyn Archive>>> {
        Ok(None)
    }
}

/// Resolves a format's named companion resource on demand.
/// Implementations must not preload unrelated entries during construction.
pub trait ResourceResolver {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Original name of the resource being decoded, when known by the host.
    fn resource_name(&self) -> Option<&str> {
        None
    }
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
