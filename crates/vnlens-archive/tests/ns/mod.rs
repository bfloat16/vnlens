use super::*;
use vnlens_core::{ArchiveRoute, Catalog};
use vnlens_io::BinaryWriter;

#[test]
fn all_ns_handlers_are_registered_and_support_logical_sources() -> Result<()> {
    let catalog = Catalog::load();
    let mut empty = vec![0; 16];
    empty[..4].copy_from_slice(b"PFS0");
    let source: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(empty));
    let mounted = catalog
        .open_source(source, "game.nsp", &ArchiveRoute::new("ns/pfs0"))?
        .ok_or(vnlens_core::Error::InvalidFormat)?;
    assert!(mounted.archive.entries().is_empty());
    for tag in ["ns/xci", "ns/hfs0", "ns/nca", "ns/romfs"] {
        let source: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(vec![0; 16]));
        let error = catalog.open_source(source, "bad", &ArchiveRoute::new(tag));
        assert!(error.is_err());
        assert!(!matches!(error, Err(vnlens_core::Error::Unsupported(_))));
    }
    let mut bytes = vec![0; 45];
    bytes[..4].copy_from_slice(b"PFS0");
    BinaryWriter::u32_le(1, &mut bytes[4..]);
    BinaryWriter::u32_le(4, &mut bytes[8..]);
    BinaryWriter::u64_le(1, &mut bytes[24..]);
    bytes[40..44].copy_from_slice(b"raw\0");
    bytes[44] = 42;
    let view = Arc::new(ArcView::from_bytes("fixture.nsp".into(), bytes.into()));
    let mounted = catalog.open_view(view, &ArchiveRoute::new("ns/pfs0"))?;
    assert!(matches!(
        mounted.archive.open_entry(&mounted.archive.entries()[0])?,
        Cow::Borrowed(&[42])
    ));
    Ok(())
}
