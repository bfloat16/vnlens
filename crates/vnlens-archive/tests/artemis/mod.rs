#![allow(clippy::unwrap_used)]
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_io::{BinaryReader, BinaryWriter};

mod local;

// Builds the native serializer footer, including zero-field object maps.
pub(super) fn fixture(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut objects = Vec::new();
    let mut offsets = Vec::new();
    word(&mut index, records.len() as u32);
    for (name, data) in records {
        word(&mut index, name.len() as u32);
        index.extend_from_slice(name.as_bytes());
        objects.push(index.len() as u32);
        word(&mut index, 7);
        index.extend_from_slice(b"old.pfs");
        offsets.push(index.len());
        word(&mut index, 0);
        word(&mut index, data.len() as u32);
    }
    let footer = index.len() as u32;
    word(&mut index, objects.len() as u32 + 1);
    for offset in objects.into_iter().chain([0]) {
        word(&mut index, offset);
        word(&mut index, 0);
    }
    word(&mut index, footer);
    let mut offset = index.len() as u32 + 7;
    for ((_, data), field) in records.iter().zip(offsets) {
        BinaryWriter::u32_le(offset, &mut index[field..]);
        offset += data.len() as u32;
    }
    let key = vnlens_crypto::hash::sha1::Sha1::from(&index)
        .digest()
        .bytes();
    let mut bytes = b"pf8".to_vec();
    word(&mut bytes, index.len() as u32);
    bytes.extend(index);
    for (_, data) in records {
        let mut encoded = data.to_vec();
        xor::apply(&mut encoded, &key).unwrap();
        bytes.extend(encoded);
    }
    bytes
}
fn word(bytes: &mut Vec<u8>, value: u32) {
    let at = bytes.len();
    bytes.resize(at + 4, 0);
    BinaryWriter::u32_le(value, &mut bytes[at..]);
}

struct Counted {
    bytes: Arc<[u8]>,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for Counted {
    fn len(&self) -> u64 {
        self.bytes.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        self.reads.lock().unwrap().push((offset, size));
        self.bytes.read_at(offset, size)
    }
}

#[test]
fn mounted_index_is_lazy_and_entry_sources_seek_independently() -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let payload = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let bytes = fixture(&[
        ("dir\\日本?.ast", payload),
        ("broken.png", b"invalid image"),
    ]);
    let index_end = 7 + u64::from(BinaryReader::u32_le(&bytes[3..]));
    let counted = Arc::new(Counted {
        bytes: bytes.into(),
        reads: Mutex::new(Vec::new()),
    });
    let opened = vnlens_core::Catalog::load()
        .open_source(
            counted.clone(),
            "game.pfs",
            &vnlens_core::ArchiveRoute::new("pfs/artemis"),
        )?
        .ok_or(Error::InvalidFormat)?;
    let archive = opened.archive;
    assert_eq!(archive.entries().len(), 2);
    assert_eq!(archive.entries()[0].name, "dir\\日本?.ast");
    assert!(
        counted
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|(off, n)| off + *n as u64 <= index_end)
    );
    counted.reads.lock().unwrap().clear();
    let entry = &archive.entries()[0];
    let source = archive
        .open_entry_source(entry)?
        .ok_or(Error::InvalidFormat)?;
    assert!(counted.reads.lock().unwrap().is_empty());
    assert_eq!(&*source.read_at(19, 24)?, &payload[19..43]);
    assert_eq!(&*source.read_at(3, 8)?, &payload[3..11]);
    assert!(source.read_at(source.len(), 1).is_err());
    let cancel = Arc::new(AtomicBool::new(false));
    let mut a = source.clone().reader(cancel.clone())?;
    let mut b = source.clone().reader(cancel.clone())?;
    a.seek(SeekFrom::Start(21))?;
    let mut part = [0; 9];
    a.read_exact(&mut part)?;
    assert_eq!(&part, &payload[21..30]);
    b.read_exact(&mut part)?;
    assert_eq!(&part, &payload[..9]);
    assert_eq!(&*archive.open_entry(entry)?, payload);
    assert!(matches!(archive.open_entry_raw(entry)?, Cow::Borrowed(_)));
    assert_ne!(&*archive.open_entry_raw(entry)?, payload);
    assert!(
        counted
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|(off, n)| *off >= entry.offset && off + *n as u64 <= entry.offset + entry.size)
    );
    cancel.store(true, Ordering::Relaxed);
    assert!(a.read_exact(&mut part).is_err());
    Ok(())
}

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "vnlens-artemis-archive-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    Temp(path)
}

#[test]
fn companions_keep_per_file_keys_and_later_packages_override() -> Result<()> {
    let dir = temp();
    let base = dir.0.join("Game.pfs");
    let patch = dir.0.join("Game.pfs.002");
    fs::write(
        &base,
        fixture(&[
            ("same.ast", b"base"),
            ("only.ast", b"unique"),
            ("same.ast", b"ignored duplicate"),
        ]),
    )?;
    fs::write(
        dir.0.join("Game.pfs.000"),
        fixture(&[("same.ast", b"part 000")]),
    )?;
    fs::write(
        &patch,
        fixture(&[("same.ast", b"part 002"), ("new.ast", b"added")]),
    )?;
    let mut route = vnlens_core::ArchiveRoute::new("pfs/artemis");
    route.options.numbers.insert("artemis_companions", 1);
    for path in [&base, &patch] {
        let archive = vnlens_core::Catalog::load().open(path, &route)?.archive;
        assert_eq!(archive.entries().len(), 3);
        for (entry, expected) in
            archive
                .entries()
                .iter()
                .zip([&b"part 002"[..], &b"unique"[..], &b"added"[..]])
        {
            assert_eq!(&*archive.open_entry(entry)?, expected);
            assert_eq!(
                &*archive
                    .open_entry_source(entry)?
                    .ok_or(Error::InvalidFormat)?
                    .read_at(0, expected.len())?,
                expected
            );
        }
    }
    // An explicitly opened, independent nested package does not discover peers.
    let source: Arc<[u8]> = fs::read(&base)?.into();
    let archive = Pfs
        .open_source(Arc::new(source), "nested.pfs", &ArchiveOptions::default())?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(&*archive.open_entry(&archive.entries()[0])?, b"base");
    Ok(())
}
