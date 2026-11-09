use super::*;
use nvlens_io::BinaryWriter;
use std::sync::Mutex;

fn class(name: &str) -> Class {
    Class {
        name: name.into(),
        schema: 1,
        encoded: None,
    }
}
#[test]
fn unrequested_volume_errors_do_not_affect_mount_or_borrowed_reads() -> Result<()> {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Unsupported(e.to_string()))?
        .as_nanos();
    let dir =
        Temp(std::env::temp_dir().join(format!("nvlens-rugp-{}-{nonce}", std::process::id())));
    std::fs::create_dir(&dir.0)?;
    let path = dir.0.join("first.rio");
    std::fs::write(&path, b"plain")?;
    let sources = Arc::new(Sources {
        root: u32::MAX,
        primary: Arc::new(ArcView::open(&path)?),
        volumes: vec![
            ici::Volume {
                name: "first.rio".into(),
                base: 0,
                size: 5,
            },
            ici::Volume {
                name: "missing.rio.002".into(),
                base: 5,
                size: 4,
            },
        ],
        paths: vec![path, dir.0.join("missing.rio.002")],
        opened: vec![OnceLock::new(), OnceLock::new()],
        shift: 0,
        children: HashMap::new(),
        patches: HashMap::new(),
    });
    let objects = [(0, 5), (5, 4)]
        .into_iter()
        .map(|(offset, size)| Object {
            class: class("CIcon"),
            flags: 8,
            offset,
            size,
            name: None,
            parent: None,
        })
        .collect();
    let archive = Package::new(sources, objects, Arc::new(ArchiveOptions::default()))?;
    assert_eq!(archive.entries().len(), 2);
    assert!(matches!(
        archive.open_entry_raw(&archive.entries[0])?,
        Cow::Borrowed(b"plain")
    ));
    assert!(
        matches!(archive.open_entry_raw(&archive.entries[1]),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::NotFound)
    );
    assert!(matches!(
        archive.open_entry(&archive.entries[0])?,
        Cow::Borrowed(b"plain")
    ));
    Ok(())
}
#[test]
fn mounting_reads_only_the_declared_index_and_decodes_stored_ranges() -> Result<()> {
    let mut index = wire::envelope(&[], &class("CrelicUnitedGameProject"), 4, 0x14, 1)?;
    let end = index.len() - 2;
    BinaryWriter::u16_le(1, &mut index[end..]);
    let name = nvlens_crypto::compress::rugp::encode_class_name(b"Cr6Ti")?;
    let at = index.len();
    index.resize(at + 8 + name.len() + 8, 0);
    BinaryWriter::u16_le(0x8208, &mut index[at..]);
    BinaryWriter::u16_le(0xffff, &mut index[at + 3..]);
    BinaryWriter::u16_le(3, &mut index[at + 5..]);
    index[at + 7] = name.len() as u8;
    index[at + 8..at + 8 + name.len()].copy_from_slice(&name);
    BinaryWriter::u32_le(
        wire::OFFSET_BIAS.wrapping_add(512),
        &mut index[at + 8 + name.len()..],
    );
    BinaryWriter::u32_le(
        wire::SIZE_BIAS.wrapping_add((3 << 13) | 3),
        &mut index[at + 12 + name.len()..],
    );
    struct Source {
        index: Vec<u8>,
        reads: Mutex<Vec<(u64, usize)>>,
    }
    impl ReadAt for Source {
        fn len(&self) -> u64 {
            1024
        }
        fn read_at(&self, at: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
            self.reads
                .lock()
                .map_err(|_| std::io::Error::other("Test read trace unavailable"))?
                .push((at, size));
            if at != 64 || size != self.index.len() {
                return Err(std::io::Error::other(
                    "Entry contents were read during indexing",
                ));
            }
            Ok(Cow::Borrowed(&self.index))
        }
    }
    let source = Source {
        index,
        reads: Mutex::new(Vec::new()),
    };
    let (_, objects) = read_index(&source, 64, source.index.len() as u64)?;
    assert_eq!(objects.len(), 1);
    assert_eq!((objects[0].offset, objects[0].size), (512, 3));
    assert_eq!(objects[0].class.name, "Cr6Ti");
    assert_eq!(
        *source
            .reads
            .lock()
            .map_err(|_| Error::Unsupported("Test read trace unavailable".into()))?,
        vec![(64, source.index.len())]
    );
    assert!(
        read_index(
            &source.index[..source.index.len() - 1].as_ref(),
            0,
            source.index.len() as u64 - 1
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn patch_tail_bounds_and_replacement_addresses_use_declared_units() -> Result<()> {
    let mut data = vec![0; 32 + 12 + 4];
    BinaryWriter::u32_le(wire::OFFSET_BIAS.wrapping_add(100), &mut data[32..]);
    BinaryWriter::u32_le(wire::OFFSET_BIAS.wrapping_add(4), &mut data[36..]);
    BinaryWriter::u32_le(wire::SIZE_BIAS.wrapping_add((5 << 13) | 5), &mut data[40..]);
    BinaryWriter::u32_le(1, &mut data[44..]);
    let index = patch_index(&data.as_slice(), 1, 2)?;
    assert_eq!(index.get(&100), Some(&(2, 8, 5)));
    BinaryWriter::u32_le(100, &mut data[44..]);
    assert!(
        matches!(patch_index(&data.as_slice(),1,2),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
