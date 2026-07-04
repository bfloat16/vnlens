//! Format catalog and the probing workflow.

use std::path::Path;
use std::sync::Arc;

use nvlens_io::ArcView;

use crate::format::ArchiveRegistration;
use crate::{Archive, ArchiveFormat, Result};

/// A successfully opened archive plus the metadata of the matched format.
pub struct Opened {
    pub format_tag: &'static str,
    pub format_description: &'static str,
    pub archive: Box<dyn Archive>,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("format_tag", &self.format_tag)
            .field("entries", &self.archive.entries().len())
            .finish()
    }
}

/// A catalog of registered formats, built lazily from compile-time records.
pub struct Catalog {
    archives: Vec<Box<dyn ArchiveFormat>>,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalog")
            .field(
                "archives",
                &self.archives.iter().map(|a| a.tag()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Catalog {
    /// Collects every archive format registered via `register_archive!`.
    pub fn load() -> Self {
        let archives = inventory::iter::<ArchiveRegistration>()
            .map(|reg| (reg.0)())
            .collect();
        Self { archives }
    }

    /// The registered archive formats, for enumeration.
    pub fn archive_formats(&self) -> &[Box<dyn ArchiveFormat>] {
        &self.archives
    }

    /// Opens `path` as an archive, probing each candidate format with formats
    /// whose extension matches taking priority.
    ///
    /// Returns `Ok(None)` when every format declines (not an archive).
    pub fn open(&self, path: impl AsRef<Path>) -> Result<Option<Opened>> {
        let path = path.as_ref();
        let view = Arc::new(ArcView::open(path)?);
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Extension-matching formats first, others keep registration order
        // (stable sort).
        let mut order: Vec<&Box<dyn ArchiveFormat>> = self.archives.iter().collect();
        order.sort_by_key(|fmt| !fmt.extensions().contains(&ext.as_str()));

        for fmt in order {
            match fmt.try_open(&view) {
                Ok(Some(archive)) => {
                    return Ok(Some(Opened {
                        format_tag: fmt.tag(),
                        format_description: fmt.description(),
                        archive,
                    }));
                }
                Ok(None) => continue,
                Err(e) => {
                    // Recognized as this format but corrupt; log and keep trying
                    // other candidates.
                    tracing::debug!(format = fmt.tag(), error = %e, "try_open failed");
                    continue;
                }
            }
        }
        Ok(None)
    }
}
