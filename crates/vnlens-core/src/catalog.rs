//! Registered archive readers, selected exclusively by explicit engine routes.

use std::path::Path;
use std::sync::Arc;

use vnlens_io::ArcView;

use crate::format::ArchiveRegistration;
use crate::{Archive, ArchiveFormat, Error, Result};

/// A successfully opened archive plus the metadata of the matched format.
pub struct Opened {
    pub format_tag: &'static str,
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
    #[must_use]
    pub fn load() -> Self {
        let archives = inventory::iter::<ArchiveRegistration>()
            .map(|reg| (reg.0)())
            .collect();
        Self::new(archives)
    }

    /// Creates a catalog from caller-selected handlers, retaining their order.
    #[must_use]
    pub fn new(archives: Vec<Box<dyn ArchiveFormat>>) -> Self {
        Self { archives }
    }

    /// Opens exactly the route selected by engine identification. No probing,
    /// extension fallback, or alternative reader is attempted.
    pub fn open(&self, path: impl AsRef<Path>, route: &crate::ArchiveRoute) -> Result<Opened> {
        let format = self.format(route.tag)?;
        let view = Arc::new(ArcView::open(path)?);
        let archive = format.open(&view, &route.options)?;
        Ok(Opened {
            format_tag: format.tag(),
            archive,
        })
    }

    /// Opens a physical or embedded view in its existing game filesystem.
    pub fn open_view(&self, view: Arc<ArcView>, route: &crate::ArchiveRoute) -> Result<Opened> {
        let format = self.format(route.tag)?;
        let archive = format.open(&view, &route.options)?;
        Ok(Opened {
            format_tag: format.tag(),
            archive,
        })
    }

    /// Opens logical bytes with the selected format's streaming source entry.
    /// None preserves that same format's mapped-view path; no reader is probed.
    pub fn open_source(
        &self,
        source: Arc<dyn vnlens_io::ReadAt>,
        name: &str,
        route: &crate::ArchiveRoute,
    ) -> Result<Option<Opened>> {
        let format = self.format(route.tag)?;
        Ok(format
            .open_source(source, name, &route.options)?
            .map(|archive| Opened {
                format_tag: format.tag(),
                archive,
            }))
    }

    fn format(&self, tag: &str) -> Result<&dyn ArchiveFormat> {
        self.archives
            .iter()
            .find(|format| format.tag() == tag)
            .map(Box::as_ref)
            .ok_or_else(|| Error::Unsupported(format!("Archive route is not registered: {tag}")))
    }
}

#[cfg(test)]
#[path = "../tests/catalog.rs"]
mod tests;
