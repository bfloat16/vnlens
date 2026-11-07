//! Registered archive readers, selected exclusively by explicit engine routes.

use std::path::Path;
use std::sync::Arc;

use nvlens_io::ArcView;

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
        let format = self
            .archives
            .iter()
            .find(|format| format.tag() == route.tag)
            .ok_or_else(|| {
                Error::Unsupported(format!("Archive route is not registered: {}", route.tag))
            })?;
        let view = Arc::new(ArcView::open(path)?);
        let archive = format.open(&view, &route.options)?;
        Ok(Opened {
            format_tag: format.tag(),
            archive,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArchiveOptions, ArchiveRoute, Format};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Handler {
        tag: &'static str,
        calls: Arc<AtomicUsize>,
    }
    impl Format for Handler {
        fn tag(&self) -> &'static str {
            self.tag
        }
        fn signatures(&self) -> &'static [u32] {
            &[0]
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["exe"]
        }
        fn description(&self) -> &'static str {
            "Synthetic reader"
        }
    }
    impl ArchiveFormat for Handler {
        fn open(&self, _: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(Error::Corrupt {
                offset: 7,
                reason: "selected reader rejected input".into(),
            })
        }
    }

    #[test]
    fn dispatch_never_tries_other_readers_or_opens_an_unrouted_path() -> Result<()> {
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let catalog = Catalog::new(vec![
            Box::new(Handler {
                tag: "first",
                calls: first.clone(),
            }),
            Box::new(Handler {
                tag: "second",
                calls: second.clone(),
            }),
        ]);
        let result = catalog.open(std::env::current_exe()?, &ArchiveRoute::new("second"));
        assert!(matches!(result, Err(Error::Corrupt { offset: 7, .. })));
        assert_eq!(first.load(Ordering::Relaxed), 0);
        assert_eq!(second.load(Ordering::Relaxed), 1);
        assert!(matches!(
            catalog.open("path-that-does-not-exist", &ArchiveRoute::new("unknown")),
            Err(Error::Unsupported(_))
        ));
        assert_eq!(second.load(Ordering::Relaxed), 1);
        Ok(())
    }
}
