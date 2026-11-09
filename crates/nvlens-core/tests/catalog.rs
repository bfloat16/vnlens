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
