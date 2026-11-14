use super::*;
use std::sync::atomic::AtomicUsize;
use vnlens_io::BinaryWriter;

struct Observed {
    bytes: Arc<[u8]>,
    reads: Arc<AtomicUsize>,
}
impl ReadAt for Observed {
    fn len(&self) -> u64 {
        self.bytes.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.read_at(offset, size)
    }
}
fn index(rows: &[(&str, u32, u32, u32, u32)]) -> Vec<u8> {
    let mut bytes = b"LSDARC V.100".to_vec();
    let mut count = [0; 4];
    BinaryWriter::u32_le(rows.len() as u32, &mut count);
    bytes.extend(count);
    for (name, flags, offset, logical, stored) in rows {
        for value in [flags, offset, logical, stored] {
            let mut word = [0; 4];
            BinaryWriter::u32_le(*value, &mut word);
            bytes.extend(word);
        }
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
    }
    bytes
}
#[test]
fn paired_virtual_archives_are_lazy_and_preserve_names_padding_and_raw_data() -> Result<()> {
    let reads = Arc::new(AtomicUsize::new(0));
    let source: Arc<dyn ReadAt> = Arc::new(Observed {
        bytes: Arc::from(&b"dataPAD!bad!"[..]),
        reads: reads.clone(),
    });
    let root = std::path::PathBuf::from("gss.romfs");
    let mut files = vnlens_io::FileSystem::isolated(root.clone());
    files.insert(root.join("BMPDATA.ARC"), source)?;
    let bytes = index(&[("../original", 0, 0, 4, 8), ("unvisited", 1, 8, 100, 4)]);
    files.insert(
        root.join("BMPDATA.BIN"),
        Arc::new(Arc::<[u8]>::from(bytes.clone())),
    )?;
    let view = Arc::new(Arc::new(files).open(&root.join("BMPDATA.BIN"))?);
    let opened = vnlens_core::Catalog::load()
        .open_view(view, &vnlens_core::ArchiveRoute::new("lsdarc/gss"))?;
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(opened.archive.entries()[0].name, "../original");
    assert_eq!(opened.archive.entries()[0].size, 8);
    assert!(matches!(
        opened.archive.open_entry(&opened.archive.entries()[0])?,
        Cow::Borrowed(b"data")
    ));
    assert_eq!(
        opened
            .archive
            .open_entry_raw(&opened.archive.entries()[0])?
            .as_ref(),
        b"dataPAD!"
    );
    let stream = opened
        .archive
        .open_entry_source(&opened.archive.entries()[0])?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(stream.len(), 4);
    assert_eq!(stream.read_at(0, 4)?.as_ref(), b"data");
    assert!(
        opened
            .archive
            .open_entry(&opened.archive.entries()[1])
            .is_err()
    );
    assert!(matches!(
        opened
            .archive
            .open_entry_source_cancellable(&opened.archive.entries()[0], &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
#[test]
fn compressed_entry_and_bin_envelope_match_logical_sources() -> Result<()> {
    let compressed = b"LSD\x1aNR\x03\0\0\0\0\0\x43abc\xf0";
    let mut bytes = compressed.to_vec();
    bytes.extend_from_slice(b"BIN\x1axyz");
    let size = compressed.len() as u32;
    let bank = Bank::open(
        &index(&[("packed", 1, 0, 3, size), ("wrapped", 0, size, 7, 7)]),
        Arc::new(Arc::<[u8]>::from(bytes)),
        "SCRDATA",
    )?;
    for (entry, expected) in bank.entries.iter().zip([&b"abc"[..], &b"xyz"[..]]) {
        assert_eq!(bank.open_entry(entry)?.as_ref(), expected);
        let source = bank.source(entry, &AtomicBool::new(false))?;
        assert_eq!(source.read_at(0, 3)?.as_ref(), expected);
    }
    assert!(bank.entries[0].packed.is_some());
    assert_eq!(bank.entries[0].kind, ResourceKind::Script);
    Ok(())
}
#[test]
fn invalid_indices_truncation_and_field_boundaries_are_checked() -> Result<()> {
    let source: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(vec![0; 4]));
    let bytes = index(&[("name", 0, 0, 4, 4)]);
    for end in 0..bytes.len() {
        assert!(Bank::open(&bytes[..end], source.clone(), "custom").is_err());
    }
    let mut wrong = bytes.clone();
    wrong[0] = 0;
    assert!(matches!(
        Bank::open(&wrong, source.clone(), "custom"),
        Err(Error::InvalidFormat)
    ));
    assert!(matches!(
        Bank::open(&index(&[("name", 0, 0, 5, 4)]), source.clone(), "custom"),
        Err(Error::Corrupt { .. })
    ));
    assert!(
        matches!(Bank::open(&index(&[("name", 0, u32::MAX, 4, 4)]), source.clone(), "custom"), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    let mut bytes = b"LSDARC V.100".to_vec();
    let mut count = [0; 4];
    BinaryWriter::u32_le(65537, &mut count);
    bytes.extend(count);
    for i in 0..65537 {
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(format!("entry{i}\0").as_bytes());
    }
    let bank = Bank::open(&bytes, source, "custom")?;
    assert_eq!(bank.entries.len(), 65537);
    Ok(())
}
