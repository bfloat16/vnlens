//! ESC-ARC1/2 indexes (GARbro Escude.IndexReader; native OpenFastFile 0x441900).
//! LE u32 seed/count, then v1 encrypted 0x88-byte records or v2 encrypted
//! 12-byte records and a plain CP932 name pool. Counts and records consume a
//! continuous XOR stream. ACP payloads are inspected only on entry access.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_crypto::{cipher::escude::IndexCipher, compress::acp};
use nvlens_io::{ArcView, BinaryReader, BinaryWriter, ReadAt};
use std::{borrow::Cow, cell::RefCell, path::PathBuf, sync::Arc};

const SIGNATURES: &[u32] = &[0x2d43_5345];
#[derive(Debug, Default)]
struct Bin;
impl Format for Bin {
    fn tag(&self) -> &'static str {
        "bin/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bin"]
    }
    fn description(&self) -> &'static str {
        "Escu:de ESC-ARC resources"
    }
}
impl ArchiveFormat for Bin {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let entries = read_index(view.as_ref())?;
        Ok(Box::new(Package {
            view: view.clone(),
            entries,
            companion: options
                .paths
                .get("escude_source")
                .filter(|path| path.as_path() != view.path())
                .cloned(),
            companion_archive: RefCell::new(None),
        }))
    }
}
fn read_index(view: &dyn ReadAt) -> Result<Vec<Entry>> {
    let header_bytes = view.read_at(0, 16)?;
    let mut header = BinaryReader::new(&header_bytes);
    let signature = header.read_bytes(8)?;
    let version = match signature {
        b"ESC-ARC1" => 1,
        b"ESC-ARC2" => 2,
        _ => return Err(Error::InvalidFormat),
    };
    let mut cipher = IndexCipher::new(header.read_u32_le()?);
    let count = u64::from(cipher.decode_word(header.read_u32_le()?));
    let (start, record_size, names_size) = if version == 1 {
        (16, 136, 0)
    } else {
        (
            20,
            12,
            u64::from(cipher.decode_word(BinaryReader::u32_le(&view.read_at(16, 4)?))),
        )
    };
    let index_size = count * record_size;
    let mut index = view
        .read_at(
            start,
            usize::try_from(index_size)
                .map_err(|_| bad(start, "ESC-ARC index exceeds address space"))?,
        )?
        .into_owned();
    let names = view.read_at(
        start + index_size,
        usize::try_from(names_size)
            .map_err(|_| bad(start, "ESC-ARC names exceed address space"))?,
    )?;
    for word in index.as_chunks_mut::<4>().0 {
        BinaryWriter::u32_le(cipher.decode_word(BinaryReader::u32_le(word)), word);
    }
    let mut r = BinaryReader::new(&index);
    let mut entries = Vec::new();
    for _ in 0..count {
        let name_bytes = if version == 1 {
            let field = r.read_bytes(128)?;
            field.split(|&b| b == 0).next().unwrap_or_default()
        } else {
            let offset = r.read_u32_le()? as usize;
            let mut text = BinaryReader::new_at(&names, offset)?;
            while text.read_u8()? != 0 {}
            &names[offset..text.position() - 1]
        };
        let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(name_bytes);
        if errors {
            return Err(bad(
                start + r.position() as u64,
                "Invalid ESC-ARC CP932 name",
            ));
        }
        let name = name.into_owned();
        let extension = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let kind = match extension.as_str() {
            "bin" | "001" | "c" | "h" | "inc" | "lsf" | "mot" | "sfx" => ResourceKind::Script,
            _ => ResourceKind::guess_from_name(&name),
        };
        let entry = Entry {
            kind,
            name,
            offset: u64::from(r.read_u32_le()?),
            size: u64::from(r.read_u32_le()?),
            packed: None,
        };
        if !entry.check_placement(view.len()) {
            return Err(bad(entry.offset, "ESC-ARC entry exceeds file"));
        }
        entries.push(entry);
    }
    Ok(entries)
}
nvlens_core::register_archive!(Bin);

struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    companion: Option<PathBuf>,
    companion_archive: RefCell<Option<Box<dyn Archive>>>,
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = self.view.slice(entry.offset, entry.size)?;
        if bytes.starts_with(b"acp\0") {
            let decoded = acp::unpack(bytes).map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidInput {
                    bad(entry.offset, &error.to_string())
                } else {
                    error.into()
                }
            })?;
            Ok(Cow::Owned(decoded))
        } else {
            Ok(Cow::Borrowed(bytes))
        }
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn read_companion(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(path) = &self.companion else {
            return Ok(None);
        };
        let mut cached = self.companion_archive.borrow_mut();
        if cached.is_none() {
            let view = match ArcView::open(path) {
                Ok(view) => Arc::new(view),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            *cached = Some(Bin.open(&view, &ArchiveOptions::default())?);
        }
        let Some(archive) = cached.as_ref() else {
            return Ok(None);
        };
        archive
            .entries()
            .iter()
            .find(|entry| entry.name.replace('\\', "/").eq_ignore_ascii_case(name))
            .map(|entry| archive.open_entry(entry).map(Cow::into_owned))
            .transpose()
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
            assert_eq!(entries[1].kind, ResourceKind::Script);
        }
        Ok(())
    }
    #[test]
    fn entry_access_is_lazy_and_raw_bytes_remain_available() -> Result<()> {
        crate::init();
        let (bytes, _) = fixture(2, None);
        let root = std::env::temp_dir().join(format!(
            "nvlens-escude-{}-{}",
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
        let archive = nvlens_core::Catalog::load()
            .open(&path, &nvlens_core::ArchiveRoute::new("bin/escude"))?
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
        let mut route = nvlens_core::ArchiveRoute::new("bin/escude");
        route
            .options
            .paths
            .insert("escude_source", companion.clone());
        let archive = nvlens_core::Catalog::load().open(&path, &route)?.archive;
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
}
