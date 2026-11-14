use super::*;
use std::io;
use vnlens_io::BinaryWriter;

fn fixture(big: bool) -> Vec<u8> {
    let mut data = vec![0; 0x335];
    data[..4].copy_from_slice(if big { b"CL3B" } else { b"CL3L" });
    for (at, value) in [
        (8, 3),
        (0xc, 1),
        (0x10, 0x40),
        (0x60, 1),
        (0x64, 0x235),
        (0x68, 0x100),
        (0x304, 0x230),
        (0x308, 5),
    ] {
        if big {
            BinaryWriter::u32_be(value, &mut data[at..]);
        } else {
            BinaryWriter::u32_le(value, &mut data[at..]);
        }
    }
    data[0x40..0x50].copy_from_slice(b"FILE_COLLECTION\0");
    data[0x100..0x10c].copy_from_slice(b"../image.tid");
    data[0x330..].copy_from_slice(b"TID!!");
    data
}

struct IndexOnly {
    data: Arc<[u8]>,
}
impl ReadAt for IndexOnly {
    fn len(&self) -> u64 {
        self.data.len()
    }
    fn read_at(&self, at: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if at + size as u64 > 0x330 {
            return Err(io::Error::other("Payload must remain lazy"));
        }
        self.data.read_at(at, size)
    }
}

#[test]
fn registers_and_preserves_names_and_raw_index_in_both_byte_orders() -> Result<()> {
    for big in [false, true] {
        let data = fixture(big);
        let view = Arc::new(ArcView::from_bytes("fixture.cl3".into(), data.into()));
        let opened = vnlens_core::Catalog::load().open_view(
            view,
            &vnlens_core::ArchiveRoute {
                tag: "cl3/otomate",
                options: Default::default(),
            },
        )?;
        let entry = &opened.archive.entries()[0];
        assert_eq!(entry.name, "../image.tid");
        assert_eq!(entry.offset, 0x330);
        assert_eq!(entry.size, 5);
        assert!(matches!(
            opened.archive.open_entry(entry)?,
            Cow::Borrowed(_)
        ));
        assert_eq!(opened.archive.open_entry(entry)?.as_ref(), b"TID!!");
        let metadata = opened.archive.metadata().ok_or(Error::InvalidFormat)?;
        let index = metadata
            .downcast_ref::<Index>()
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(index.records[0].len(), 0x230);
    }
    Ok(())
}

#[test]
fn mounting_does_not_read_payload_and_streams_only_selected_entry() -> Result<()> {
    let archive = Collection::open(Arc::new(IndexOnly {
        data: fixture(false).into(),
    }))?;
    assert_eq!(archive.entries().len(), 1);
    assert!(archive.open_entry(&archive.entries()[0]).is_err());
    let archive = Collection::open(Arc::new(Arc::<[u8]>::from(fixture(false))))?;
    let source = archive
        .open_entry_source(&archive.entries()[0])?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(source.read_at(1, 2)?.as_ref(), b"ID");
    Ok(())
}

#[test]
fn malformed_and_truncated_indices_report_errors() {
    let mut data = fixture(false);
    BinaryWriter::u32_le(u32::MAX, &mut data[0xc..]);
    assert!(
        matches!(Collection::open(Arc::new(Arc::<[u8]>::from(data))), Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    let mut data = fixture(false);
    BinaryWriter::u32_le(0x234, &mut data[0x304..]);
    assert!(matches!(
        Collection::open(Arc::new(Arc::<[u8]>::from(data))),
        Err(Error::Corrupt { .. })
    ));
    let mut data = fixture(false);
    data[0] = 0;
    assert!(matches!(
        Collection::open(Arc::new(Arc::<[u8]>::from(data))),
        Err(Error::InvalidFormat)
    ));
}
