use super::*;
use std::{
    borrow::Cow,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Counted {
    bytes: Vec<u8>,
    calls: Arc<AtomicUsize>,
    broken: bool,
}
impl ReadAt for Counted {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.broken {
            return Err(io::Error::other("Unrequested broken payload"));
        }
        Ok(Cow::Borrowed(crate::BinaryReader::bytes_at(
            &self.bytes,
            offset as usize,
            size,
        )?))
    }
}
#[test]
fn embedded_listing_is_lazy_and_related_views_keep_the_overlay() -> io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "nvlens-overlay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let broken = Arc::new(AtomicUsize::new(0));
    let mut files = FileSystem::default();
    for name in ["Arc01.dat", "folder/CON.foo"] {
        files.insert(
            root.join(name),
            Arc::new(Counted {
                bytes: b"index".to_vec(),
                calls: calls.clone(),
                broken: false,
            }),
        )?;
    }
    files.insert(
        root.join("bad.dat"),
        Arc::new(Counted {
            bytes: vec![0],
            calls: broken.clone(),
            broken: true,
        }),
    )?;
    let files = Arc::new(files);
    assert_eq!(files.read_dir(&root)?.len(), 3);
    assert!(files.is_dir(&root.join("folder")));
    assert_eq!(
        files.read_dir(&root.join("folder"))?[0].path,
        root.join("folder/CON.foo")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let view = files.open(&root.join("arc01.DAT"))?;
    assert_eq!(view.slice(0, 5)?, b"index");
    assert_eq!(files.open(&root.join("Arc01.dat"))?.slice(0, 5)?, b"index");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        view.open_related(root.join("folder/CON.foo"))?
            .slice(0, 5)?,
        b"index"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(broken.load(Ordering::Relaxed), 0);
    assert!(files.open(&root.join("bad.dat")).is_err());
    assert_eq!(broken.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
#[cfg(windows)]
fn embedded_and_physical_children_share_the_requested_parent() -> io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "nvlens-verbatim-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("Arc05.dat"), [])?;
    let result = (|| {
        let mut files = FileSystem::default();
        files.insert(
            root.canonicalize()?.join("Arc02.dat"),
            Arc::new(Counted {
                bytes: vec![1],
                calls: Arc::new(AtomicUsize::new(0)),
                broken: true,
            }),
        )?;
        for parent in [&root, &root.canonicalize()?] {
            let entries = files.read_dir(parent)?;
            assert_eq!(entries.len(), 2);
            assert!(
                entries
                    .iter()
                    .all(|entry| entry.path.parent() == Some(parent.as_path()))
            );
        }
        Ok(())
    })();
    std::fs::remove_dir_all(root)?;
    result
}
