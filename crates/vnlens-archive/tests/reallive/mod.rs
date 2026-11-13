use super::*;
use vnlens_io::BinaryWriter;

fn view(bytes: Vec<u8>) -> Arc<ArcView> {
    Arc::new(ArcView::from_bytes("Seen.txt".into(), bytes.into()))
}
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 80008];
    for (id, offset) in [(42, 80000), (9999, 80004)] {
        BinaryWriter::u32_le(offset, &mut bytes[id * 8..]);
        BinaryWriter::u32_le(4, &mut bytes[id * 8 + 4..]);
    }
    bytes[80000..].copy_from_slice(b"goodBAD!");
    bytes
}

#[test]
fn index_holes_lazy_payloads_and_original_storage() -> Result<()> {
    let view = view(fixture());
    let archive = Seen.open(&view, &ArchiveOptions::default())?;
    assert_eq!(
        archive
            .entries()
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["Seen0042.txt", "Seen9999.txt"]
    );
    let entry = &archive.entries()[0];
    assert!(matches!(archive.open_entry(entry)?, Cow::Borrowed(b"good")));
    assert_eq!(archive.open_entry_raw(entry)?.as_ref(), b"good");
    // No compiler headers or keys are required to mount a valid index.
    // The corrupt, unrequested second scene cannot affect this first read.
    let mut forged = entry.clone();
    forged.offset += 1;
    assert!(matches!(
        archive.open_entry(&forged),
        Err(Error::Corrupt { .. })
    ));
    Ok(())
}

#[test]
fn rejects_truncated_index_storage_and_overlap() {
    for length in [0, 7, 79999, 80007] {
        let mut bytes = fixture();
        bytes.truncate(length);
        assert!(
            matches!(Seen.open(&view(bytes), &ArchiveOptions::default()), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    let mut bytes = fixture();
    BinaryWriter::u32_le(79999, &mut bytes[42 * 8..]);
    assert!(matches!(
        Seen.open(&view(bytes), &ArchiveOptions::default()),
        Err(Error::Corrupt { .. })
    ));
}
