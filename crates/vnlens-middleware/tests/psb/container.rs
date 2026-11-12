#![allow(clippy::unwrap_used)]
use super::super::read::tests::version_fixture;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn resource_fixture(payload: &[u8]) -> Vec<u8> {
    let root = [0x21, 0x0d, 1, 0x0d, 0, 0x0d, 1, 0x0d, 0, 0x19, 0];
    let mut bytes = version_fixture(3, &root, 0);
    let lengths = BinaryReader::u32_le(&bytes[28..]) as usize;
    bytes.truncate(lengths);
    bytes.extend([0x0d, 1, 0x10]);
    let mut length = [0; 4];
    vnlens_io::BinaryWriter::u32_le(u32::try_from(payload.len()).unwrap(), &mut length);
    bytes.extend(length);
    let offset = u32::try_from(bytes.len()).unwrap();
    vnlens_io::BinaryWriter::u32_le(offset, &mut bytes[32..]);
    bytes.extend(payload);
    let checksum = vnlens_crypto::checksum::adler32::checksum(&bytes[8..40]);
    vnlens_io::BinaryWriter::u32_le(checksum, &mut bytes[40..]);
    bytes
}

#[test]
fn nested_containers_only_read_the_selected_level_index() {
    struct IndexOnly {
        source: Arc<dyn ReadAt>,
        payload: u64,
        accessed: AtomicBool,
    }
    impl ReadAt for IndexOnly {
        fn len(&self) -> u64 {
            self.source.len()
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
            assert!(offset + size as u64 <= self.payload || self.accessed.load(Ordering::Relaxed));
            self.source.read_at(offset, size)
        }
    }
    let mut bytes = b"PSB\0".to_vec();
    for _ in 0..4 {
        bytes = resource_fixture(&bytes);
    }
    let bytes: Arc<[u8]> = bytes.into();
    let mut source: Arc<dyn ReadAt> = Arc::new(bytes);
    for _ in 0..4 {
        let payload = u64::from(BinaryReader::u32_le(&source.read_at(32, 4).unwrap()));
        let guarded = Arc::new(IndexOnly {
            source,
            payload,
            accessed: AtomicBool::new(false),
        });
        let file = PsbFile::open(guarded.clone(), ParseOptions::default()).unwrap();
        assert_eq!(file.entries().len(), 1);
        let entry = &file.entries()[0];
        assert_eq!(entry.name, "a");
        assert_eq!(entry.offset, payload);
        assert!(file.entry_metadata(entry).unwrap().is_none());
        // Creating a child source is also lazy. Its invalid contents at the
        // innermost level must not affect any of the parent mounts.
        source = file.open_entry_source(entry).unwrap().unwrap();
        guarded.accessed.store(true, Ordering::Relaxed);
    }
    assert!(matches!(
        PsbFile::open(source, ParseOptions::default()),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
}

#[test]
fn nested_psb_files_keep_shells_and_decode_only_on_access() {
    let leaf = resource_fixture(b"leaf");
    let mut bytes = leaf;
    for shell in [
        crate::mdf::tests::encode_fixture,
        crate::mdf::tests::mzs_fixture,
        crate::mdf::tests::psz_fixture,
    ] {
        bytes = resource_fixture(&shell(&bytes));
    }
    let bytes: Arc<[u8]> = bytes.into();
    let mut file = PsbFile::open(Arc::new(bytes), ParseOptions::default()).unwrap();
    assert!(file.document.shell.is_none());
    for kind in [
        crate::mdf::ShellKind::Psz,
        crate::mdf::ShellKind::Mzs,
        crate::mdf::ShellKind::Mdf,
    ] {
        assert_eq!(file.entries().len(), 1);
        let source = file.open_entry_source(&file.entries()[0]).unwrap().unwrap();
        file = PsbFile::open(source, ParseOptions::default()).unwrap();
        assert_eq!(
            file.document.shell.as_ref().map(|shell| shell.kind),
            Some(kind)
        );
    }
    assert_eq!(
        file.open_entry(&file.entries()[0]).unwrap().as_ref(),
        b"leaf"
    );
}

#[test]
fn serialized_members_are_native_files_with_shared_parsed_context() {
    let root = [
        0x21, 0x0d, 1, 0x0d, 0, 0x0d, 1, 0x0d, 0, 0x20, 0x0d, 2, 0x0d, 0, 1, 2, 0x15, 0,
    ];
    let bytes: Arc<[u8]> = version_fixture(3, &root, 0).into();
    let file = PsbFile::open(Arc::new(bytes), ParseOptions::default()).unwrap();
    assert_eq!(file.entries().len(), 2);
    let entry = &file.entries()[1];
    assert_eq!(entry.name, "a");
    assert_eq!(entry.kind, ResourceKind::Data);
    let value = file
        .entry_metadata(entry)
        .unwrap()
        .unwrap()
        .downcast::<super::super::PsbValueFile>()
        .unwrap();
    assert!(Arc::ptr_eq(&value.document, &file.document));
    assert_eq!(value.key.as_deref(), Some("a"));
    assert_eq!(value.value().unwrap().as_list().unwrap().len(), 2);
    assert_eq!(
        value.value().unwrap().as_list().unwrap()[1].as_str(),
        Some("日本語")
    );
    assert_eq!(file.open_entry(entry).unwrap().as_ref(), &root[9..]);
    assert_eq!(file.open_entry_raw(entry).unwrap().as_ref(), &root[9..]);
    let source = file.open_entry_source(entry).unwrap().unwrap();
    assert_eq!(
        source.read_at(0, root.len() - 9).unwrap().as_ref(),
        &root[9..]
    );
}

#[test]
fn retains_metadata_names_and_lazy_resource_sources() {
    let root = [0x21, 0x0d, 1, 0x0d, 0, 0x0d, 1, 0x0d, 0, 0x19, 0];
    let data = version_fixture(3, &root, 0);
    let offset = u64::from(vnlens_io::BinaryReader::u32_le(&data[32..]));
    struct Guarded {
        bytes: Arc<[u8]>,
        offset: u64,
        enabled: AtomicBool,
    }
    impl ReadAt for Guarded {
        fn len(&self) -> u64 {
            self.bytes.len()
        }
        fn read_at(&self, at: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
            assert!(at + size as u64 <= self.offset || self.enabled.load(Ordering::Relaxed));
            self.bytes.read_at(at, size)
        }
    }
    let source = Arc::new(Guarded {
        bytes: data.into(),
        offset,
        enabled: AtomicBool::new(false),
    });
    let file = PsbFile::open(source.clone(), ParseOptions::default()).unwrap();
    assert_eq!(file.entries().len(), 1);
    assert_eq!(file.entries()[0].name, "a");
    let metadata = file.metadata().unwrap().downcast::<Psb>().unwrap();
    assert_eq!(metadata.header.version, 3);
    assert_eq!(metadata.strings, ["日本語"]);
    assert_eq!(
        metadata.root.as_object().unwrap()["a"],
        PsbValue::Resource {
            index: 0,
            is_extra: false
        }
    );
    assert!(!metadata.nodes.is_empty());
    let resource = file.open_entry_source(&file.entries()[0]).unwrap().unwrap();
    source.enabled.store(true, Ordering::Relaxed);
    assert_eq!(resource.read_at(0, 3).unwrap().as_ref(), b"res");
    assert!(resource.read_at(2, 2).is_err());
    assert_eq!(
        file.open_entry(&file.entries()[0]).unwrap().as_ref(),
        b"res"
    );
}

#[test]
fn all_shells_and_extra_chunks_use_the_same_container_entry() {
    let data = version_fixture(4, &[0x22, 0], 0);
    for wrapped in [
        data.clone(),
        crate::mdf::tests::encode_fixture(&data),
        crate::mdf::tests::mzs_fixture(&data),
        crate::mdf::tests::psz_fixture(&data),
    ] {
        let bytes: Arc<[u8]> = wrapped.into();
        let file = PsbFile::open(Arc::new(bytes), ParseOptions::default()).unwrap();
        assert_eq!(file.entries().len(), 3);
        assert_eq!(
            file.open_entry(&file.entries()[0]).unwrap().as_ref(),
            b"res"
        );
        assert_eq!(
            file.open_entry(&file.entries()[1]).unwrap().as_ref(),
            b"extra"
        );
        assert_eq!(file.document.header.checksum_valid(), Some(true));
        let value = file
            .entry_metadata(&file.entries()[2])
            .unwrap()
            .unwrap()
            .downcast::<super::super::PsbValueFile>()
            .unwrap();
        assert_eq!(file.entries()[2].name, "root");
        assert_eq!(value.value(), Some(&file.document.root));
        assert_eq!(
            file.open_entry(&file.entries()[2]).unwrap().as_ref(),
            &[0x22, 0]
        );
        assert_eq!(
            file.document.root,
            PsbValue::Resource {
                index: 0,
                is_extra: true
            }
        );
    }
}
