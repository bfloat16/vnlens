#![allow(clippy::unwrap_used)]

use super::*;
use std::path::PathBuf;
fn fixture(version: u8, offset: Option<u32>) -> (Vec<u8>, usize) {
    let names = b"../good.c\0bad.bin\0";
    let start = if version == 1 { 16 } else { 20 };
    let width = if version == 1 { 136 } else { 12 };
    let payload = start + 2 * width + if version == 1 { 0 } else { names.len() };
    let mut data = vec![0; payload];
    data[..8].copy_from_slice(if version == 1 {
        b"ESC-ARC1"
    } else {
        b"ESC-ARC2"
    });
    let mut cipher = IndexCipher::new(0);
    BinaryWriter::u32_le(cipher.decode_word(2), &mut data[12..]);
    if version == 2 {
        BinaryWriter::u32_le(cipher.decode_word(names.len() as u32), &mut data[16..]);
        data[start + 2 * width..].copy_from_slice(names);
    }
    for (i, name) in [b"../good.c".as_slice(), b"bad.bin"]
        .into_iter()
        .enumerate()
    {
        let at = start + i * width;
        let fields = if version == 1 {
            data[at..at + name.len()].copy_from_slice(name);
            at + 128
        } else {
            BinaryWriter::u32_le(if i == 0 { 0 } else { 10 }, &mut data[at..]);
            at + 4
        };
        BinaryWriter::u32_le(
            offset.unwrap_or(payload as u32 + if i == 0 { 0 } else { 3 }),
            &mut data[fields..],
        );
        BinaryWriter::u32_le(if i == 0 { 3 } else { 4 }, &mut data[fields + 4..]);
    }
    for word in data[start..start + 2 * width].as_chunks_mut::<4>().0 {
        BinaryWriter::u32_le(cipher.decode_word(BinaryReader::u32_le(word)), word);
    }
    data.extend_from_slice(b"ok!acp\0");
    (data, payload)
}
struct IndexOnly {
    bytes: Vec<u8>,
    end: usize,
}
impl ReadAt for IndexOnly {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        assert!(
            offset + size as u64 <= self.end as u64,
            "payload read while mounting"
        );
        Ok(Cow::Borrowed(
            &self.bytes[offset as usize..offset as usize + size],
        ))
    }
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn both_indexes_preserve_names_and_never_read_payloads() -> Result<()> {
    for version in [1, 2] {
        let (bytes, end) = fixture(version, None);
        let source = IndexOnly { bytes, end };
        let entries = read_index(&source)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "../good.c");
        assert_eq!(entries[1].name, "bad.bin");
        assert_eq!(entries[1].kind, ResourceKind::Unknown);
    }
    Ok(())
}
#[test]
fn entry_access_is_lazy_and_raw_bytes_remain_available() -> Result<()> {
    crate::init();
    let (bytes, _) = fixture(2, None);
    let root = std::env::temp_dir().join(format!(
        "vnlens-escude-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root)?;
    let dir = Temp(root);
    let path = dir.0.join("data.bin");
    std::fs::write(&path, bytes)?;
    let archive = vnlens_core::Catalog::load()
        .open(&path, &vnlens_core::ArchiveRoute::new("bin/escude"))?
        .archive;
    assert_eq!(archive.entries().len(), 2);
    assert!(matches!(
        archive.open_entry(&archive.entries()[0])?,
        Cow::Borrowed(b"ok!")
    ));
    assert!(archive.open_entry(&archive.entries()[1]).is_err());
    assert_eq!(
        archive.open_entry_raw(&archive.entries()[1])?.as_ref(),
        b"acp\0"
    );
    let companion = dir.0.join("host.bin");
    std::fs::write(&companion, b"broken, unrequested source archive")?;
    let mut route = vnlens_core::ArchiveRoute::new("bin/escude");
    route
        .options
        .paths
        .insert("escude_source", companion.clone());
    let archive = vnlens_core::Catalog::load().open(&path, &route)?.archive;
    assert_eq!(archive.entries().len(), 2);
    assert_eq!(archive.open_entry(&archive.entries()[0])?.as_ref(), b"ok!");
    assert!(archive.read_companion("../good.c").is_err());
    std::fs::write(&companion, fixture(2, None).0)?;
    assert_eq!(archive.read_companion("../good.c")?, Some(b"ok!".to_vec()));
    assert!(archive.read_companion("missing.inc")?.is_none());
    assert!(archive.read_companion("bad.bin").is_err());
    Ok(())
}
#[test]
fn truncated_index_bad_names_and_out_of_file_ranges_are_rejected() {
    for version in [1, 2] {
        let (bytes, end) = fixture(version, None);
        for cut in 0..end {
            assert!(read_index(&&bytes[..cut]).is_err());
        }
        let (bytes, _) = fixture(version, Some(u32::MAX));
        assert!(read_index(&bytes.as_slice()).is_err());
    }
    let (mut bytes, end) = fixture(2, None);
    bytes[end - 1] = b'x';
    assert!(read_index(&bytes.as_slice()).is_err());
    bytes[..8].copy_from_slice(b"ESC-ARC9");
    assert!(matches!(
        read_index(&bytes.as_slice()),
        Err(Error::InvalidFormat)
    ));
}
